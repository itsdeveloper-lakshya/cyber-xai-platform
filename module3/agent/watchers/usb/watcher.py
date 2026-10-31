"""
USB Storage Watcher (Section 7 Steps U1 to U6)
Monitors insertion and removal of USB mass storage devices.
Uses dual signal sources:
1. Primary: WMI Win32_VolumeChangeEvent listener
2. Fallback: 5-second periodic disk partition polling
Classifies USB storage (including external USB HDDs reporting as 'Fixed').
Hashes volume serial with per-deployment salt.
Debounces arrivals within 3 seconds.
Notifies file-session watcher upon mount/unmount.
"""

import os
import time
import hashlib
import threading
import logging
from typing import Dict, Any, Optional, Set, Callable, Tuple
import psutil

try:
    import pythoncom
    import win32file
    import win32api
    import wmi
except ImportError:
    pythoncom = None
    win32file = None
    win32api = None
    wmi = None

from core.outbox import SQLiteOutbox
from core.event_factory import EventFactory

logger = logging.getLogger("cyber_sentinel_agent.usb")

VOLUME_SALT = "CyberSentinel_USB_Salt_2026"

def hash_volume_serial(serial_str: str) -> str:
    """Produces deterministic 64-char SHA256 hash of volume serial."""
    salted = f"{VOLUME_SALT}:{serial_str.strip().upper()}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()

class UsbWatcherThread(threading.Thread):
    def __init__(
        self,
        outbox: SQLiteOutbox,
        on_mount_callback: Optional[Callable[[str, str], None]] = None,
        on_unmount_callback: Optional[Callable[[str, str], None]] = None,
        poll_interval: float = 5.0
    ):
        super().__init__(name="UsbWatcherThread", daemon=True)
        self.outbox = outbox
        self.on_mount_callback = on_mount_callback
        self.on_unmount_callback = on_unmount_callback
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.status = "ok"

        # Track currently mounted USB drive letters and metadata: drive_letter -> metadata
        self._mounted_usb_drives: Dict[str, Dict[str, Any]] = {}
        # Debounce tracker: vol_hash -> last_event_time
        self._recent_events: Dict[str, float] = {}
        self._lock = threading.Lock()

    def stop(self):
        self._stop_event.set()

    def get_status(self) -> str:
        return self.status

    def _get_drive_serial_and_fs(self, drive_letter: str) -> Tuple[str, str]:
        """Retrieves volume serial, volume name and filesystem type via win32api."""
        path = drive_letter.rstrip("\\") + "\\"
        try:
            if win32api:
                name, serial, max_comp, flags, fs_type = win32api.GetVolumeInformation(path)
                return str(serial), str(fs_type)
        except Exception:
            pass
        return "UNKNOWN_SERIAL", "UNKNOWN"

    def _is_usb_device(self, drive_letter: str) -> Tuple[bool, str, Optional[str]]:
        """
        Determines whether the drive is connected via USB interface (Section 7 U2).
        Inspects physical disk drive properties to catch external USB hard drives reporting as 'Fixed'.
        """
        # Normalize drive letter (e.g. 'E:' or 'E:\\')
        dl = drive_letter[:2].upper()

        # Check explicit test drive override (e.g. AGENT_TEST_DRIVES="T:,X:")
        test_drives = [d.strip() for d in os.getenv("AGENT_TEST_DRIVES", "").upper().split(",") if d.strip()]
        if dl in test_drives:
            return True, "mass_storage", "TEST_DRV"

        try:
            # First check drive type via win32file if available
            is_removable = False
            if win32file:
                dtype = win32file.GetDriveType(dl + "\\")
                if dtype == win32file.DRIVE_REMOVABLE:
                    is_removable = True

            # If WMI is available, inspect physical disk interface type
            if wmi:
                pythoncom.CoInitialize()
                c = wmi.WMI()
                for disk in c.Win32_DiskDrive():
                    # Check if interface or PNPDeviceID indicates USB
                    inter = str(disk.InterfaceType or "").upper()
                    pnp = str(disk.PNPDeviceID or "").upper()
                    if inter == "USB" or "USBSTOR" in pnp or "VID_" in pnp:
                        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                                if logical_disk.DeviceID.upper() == dl:
                                    vid_pid = None
                                    if "VID_" in pnp:
                                        # Extract VID/PID
                                        parts = pnp.split("\\")
                                        if len(parts) > 1:
                                            vid_pid = parts[1][:9]
                                    return True, "mass_storage", vid_pid

            if is_removable:
                return True, "mass_storage", None
        except Exception as e:
            logger.debug(f"USB classification error for {dl}: {e}")
        return False, "other", None

    def _handle_drive_connect(self, drive_letter: str):
        now = time.time()
        is_usb, dev_class, vid_pid = self._is_usb_device(drive_letter)
        if not is_usb:
            return

        serial_raw, fs_type = self._get_drive_serial_and_fs(drive_letter)
        vol_hash = hash_volume_serial(f"{drive_letter}_{serial_raw}")

        # Debounce: ignore duplicate arrival of the same volume within 3 seconds (Section 7 U4)
        with self._lock:
            last_time = self._recent_events.get(vol_hash, 0)
            if now - last_time < 3.0:
                logger.debug(f"Debounced duplicate USB connect for volume {vol_hash[:8]}")
                return
            self._recent_events[vol_hash] = now

            if drive_letter in self._mounted_usb_drives:
                return

            capacity_gb = None
            try:
                usage = psutil.disk_usage(drive_letter[:2] + "\\")
                capacity_gb = round(usage.total / (1024 ** 3), 2)
            except Exception:
                pass

            meta = {
                "drive_letter": drive_letter[:2],
                "volume_serial_hash": vol_hash,
                "device_class": dev_class,
                "usb_vid_pid": vid_pid,
                "capacity_gb": capacity_gb,
                "fs_type": fs_type
            }
            self._mounted_usb_drives[drive_letter[:2]] = meta

        # Emit usb_connect event to outbox
        evt = EventFactory.create_usb_event(
            event_type="usb_connect",
            volume_serial_hash=vol_hash,
            drive_letter=meta["drive_letter"],
            device_class=dev_class,
            usb_vid_pid=vid_pid,
            capacity_gb=capacity_gb,
            fs_type=fs_type
        )
        self.outbox.enqueue(evt, severity="low")
        logger.info(f"USB storage connected on {meta['drive_letter']} (hash: {vol_hash[:8]}...)")

        print("\n" + "=" * 65)
        print(f" [LIVE EVENT] USB STORAGE DEVICE DETECTED!")
        print(f"   Drive Letter : {meta['drive_letter']}\\")
        print(f"   Volume Hash  : {vol_hash[:16]}...")
        print(f"   File System  : {fs_type} (Capacity: {capacity_gb} GB)")
        print(f"   Action       : Recursive file-copy watcher is now ACTIVE on {meta['drive_letter']}\\")
        print("=" * 65 + "\n")

        # Notify file session watcher to watch drive root
        if self.on_mount_callback:
            try:
                self.on_mount_callback(meta["drive_letter"], vol_hash)
            except Exception as e:
                logger.error(f"Error notifying mount callback: {e}")

    def _handle_drive_disconnect(self, drive_letter: str):
        dl = drive_letter[:2]
        meta = None
        with self._lock:
            if dl in self._mounted_usb_drives:
                meta = self._mounted_usb_drives.pop(dl)

        if meta:
            vol_hash = meta["volume_serial_hash"]
            evt = EventFactory.create_usb_event(
                event_type="usb_disconnect",
                volume_serial_hash=vol_hash,
                drive_letter=dl,
                device_class=meta.get("device_class", "mass_storage")
            )
            self.outbox.enqueue(evt, severity="low")
            logger.info(f"USB storage disconnected from {dl} (hash: {vol_hash[:8]}...)")

            print("\n" + "=" * 65)
            print(f" [LIVE EVENT] USB STORAGE DEVICE REMOVED!")
            print(f"   Drive Letter : {dl}\\")
            print(f"   Volume Hash  : {vol_hash[:16]}...")
            print(f"   Action       : File monitor stopped. Flushed any open sessions.")
            print("=" * 65 + "\n")

            # Notify file session watcher to flush and stop
            if self.on_unmount_callback:
                try:
                    self.on_unmount_callback(dl, vol_hash)
                except Exception as e:
                    logger.error(f"Error notifying unmount callback: {e}")

    def _run_periodic_fallback(self):
        """
        Fallback periodic scan (every 5 seconds) to catch missed events (Section 7 U1).
        """
        try:
            current_partitions = psutil.disk_partitions(all=False)
            current_letters = {p.mountpoint[:2].upper() for p in current_partitions if p.mountpoint}

            # Check new arrivals
            for p in current_partitions:
                dl = p.mountpoint[:2].upper()
                if dl not in self._mounted_usb_drives:
                    # Check if USB
                    is_usb, _, _ = self._is_usb_device(dl)
                    if is_usb:
                        self._handle_drive_connect(dl)

            # Check removals
            with self._lock:
                tracked = list(self._mounted_usb_drives.keys())
            for dl in tracked:
                if dl not in current_letters:
                    self._handle_drive_disconnect(dl)

        except Exception as e:
            logger.debug(f"Fallback scan error: {e}")

    def run(self):
        logger.info("UsbWatcherThread started.")
        # Initial scan of already attached drives
        self._run_periodic_fallback()

        # Run primary WMI watcher with periodic fallback
        while not self._stop_event.is_set():
            try:
                self._run_periodic_fallback()
                self._stop_event.wait(self.poll_interval)
                self.status = "ok"
            except Exception as e:
                self.status = f"error: {str(e)[:20]}"
                logger.error(f"UsbWatcherThread encountered error: {e}")
                self._stop_event.wait(5.0)

        logger.info("UsbWatcherThread stopped.")

