"""
Module 3 Windows Endpoint Agent Entry Point (Section 6 Steps G1 to G8)
Controls single-instance lock (named mutex), supervisor lifecycle, outbox sender,
heartbeat, and all 4 behavior watchers (USB, File Sessions, Clipboard, AI Apps).
"""

import os
import sys
import time
import signal
from datetime import datetime, timezone
from pathlib import Path
import threading
import logging

try:
    import win32event
    import win32api
    import winerror
except ImportError:
    win32event = None
    win32api = None
    winerror = None

# Ensure agent root is on python path
AGENT_ROOT = Path(__file__).resolve().parent
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from core.logging_config import setup_agent_logging
from core.config import AgentConfig
from core.outbox import SQLiteOutbox
from core.sender import EventSenderThread
from core.heartbeat import HeartbeatThread
from core.event_factory import EventFactory
from watchers.usb.watcher import UsbWatcherThread
from watchers.file_sessions.watcher import FileSessionWatcher
from watchers.clipboard.watcher import ClipboardWatcherThread
from watchers.apps.watcher import AiAppWatcherThread
from ui.tray import AgentTrayIcon

MUTEX_NAME = "Local\\CyberSentinelAgentLock"
RUNNING_MARKER_FILE = AGENT_ROOT / ".agent_running"

class AgentSupervisor:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.log_dir = base_dir / "logs"
        self.logger = setup_agent_logging(self.log_dir)

        self.mutex_handle = None
        self._shutdown_event = threading.Event()
        self.agent_started_at = datetime.now(timezone.utc)

        # Core components
        self.config = AgentConfig(self.base_dir)
        self.outbox = SQLiteOutbox(self.base_dir / "outbox.db")
        self.sender = EventSenderThread(self.outbox, self.config)

        # Watchers
        self.file_watcher = FileSessionWatcher(self.outbox, self.config)
        self.usb_watcher = UsbWatcherThread(
            self.outbox,
            on_mount_callback=self.file_watcher.start_watching_drive,
            on_unmount_callback=self.file_watcher.stop_watching_drive
        )
        self.clipboard_watcher = ClipboardWatcherThread(self.outbox, self.config)
        self.apps_watcher = AiAppWatcherThread(self.outbox, self.config)

        # Heartbeat
        self.heartbeat = HeartbeatThread(
            self.outbox,
            self.config,
            get_watcher_statuses=self.get_watcher_statuses,
            get_low_risk_clipboard_count=self.clipboard_watcher.get_and_reset_low_risk_count,
            agent_started_at=self.agent_started_at
        )

        self.tray = AgentTrayIcon(on_exit_callback=self.request_shutdown)

    def acquire_single_instance_lock(self) -> bool:
        """
        Takes a system-wide named mutex so two copies never run (Section 6 G1).
        Returns False if another instance is already running.
        """
        if not win32event:
            return True
        try:
            self.mutex_handle = win32event.CreateMutex(None, False, MUTEX_NAME)
            last_err = win32api.GetLastError()
            if last_err == winerror.ERROR_ALREADY_EXISTS:
                self.logger.warning("Another instance of Cyber Sentinel Agent is already running. Exiting.")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error acquiring mutex lock: {e}")
            return True

    def check_unclean_restart(self):
        """
        Step G8: If the previous run left a 'running' marker without a stop record,
        emit an agent_unclean_restart event.
        """
        if RUNNING_MARKER_FILE.exists():
            self.logger.warning("Detected previous unclean agent termination (kill or system crash).")
            evt = EventFactory.create_lifecycle_event(
                event_type="agent_unclean_restart",
                reason="Unclean shutdown detected from previous session"
            )
            self.outbox.enqueue(evt, severity="high")
        # Touch marker file
        RUNNING_MARKER_FILE.write_text(f"started_at={self.agent_started_at.isoformat()}\npid={os.getpid()}\n")

    def get_watcher_statuses(self) -> dict:
        return {
            "usb": self.usb_watcher.get_status(),
            "file": self.file_watcher.get_status(),
            "clipboard": self.clipboard_watcher.get_status(),
            "apps": self.apps_watcher.get_status()
        }

    def start(self, enable_tray: bool = False):
        if not self.acquire_single_instance_lock():
            sys.exit(0)

        self.logger.info("Starting Cyber Sentinel Endpoint Agent...")
        self.check_unclean_restart()

        # Initial device registration and server config sync
        self.config.register_device_if_needed()
        self.config.sync_server_config()

        # Start sender and heartbeat
        self.sender.start()
        self.heartbeat.start()

        # Start watchers
        self.usb_watcher.start()
        self.file_watcher.start()
        self.clipboard_watcher.start()
        self.apps_watcher.start()

        self.logger.info("All watchers running under supervision.")

        # Hook signals
        signal.signal(signal.SIGINT, lambda s, f: self.request_shutdown())
        signal.signal(signal.SIGTERM, lambda s, f: self.request_shutdown())

        if enable_tray:
            self.logger.info("Starting System Tray Icon (Cyber Sentinel)...")
            threading.Thread(target=self.tray.run, daemon=True).start()

    def supervisor_loop(self):
        """Monitors watcher thread health and restarts crashed watchers (Section 6 G6)."""
        while not self._shutdown_event.is_set():
            try:
                # Check USB watcher
                if not self.usb_watcher.is_alive() and not self._shutdown_event.is_set():
                    self.logger.warning("Supervisor: UsbWatcher thread died! Restarting...")
                    self.usb_watcher = UsbWatcherThread(
                        self.outbox,
                        on_mount_callback=self.file_watcher.start_watching_drive,
                        on_unmount_callback=self.file_watcher.stop_watching_drive
                    )
                    self.usb_watcher.start()

                # Check File watcher
                if not self.file_watcher.is_alive() and not self._shutdown_event.is_set():
                    self.logger.warning("Supervisor: FileSessionWatcher thread died! Restarting...")
                    self.file_watcher = FileSessionWatcher(self.outbox, self.config)
                    self.file_watcher.start()

                # Check Clipboard watcher
                if not self.clipboard_watcher.is_alive() and not self._shutdown_event.is_set():
                    self.logger.warning("Supervisor: ClipboardWatcher thread died! Restarting...")
                    self.clipboard_watcher = ClipboardWatcherThread(self.outbox, self.config)
                    self.clipboard_watcher.start()

                # Check Apps watcher
                if not self.apps_watcher.is_alive() and not self._shutdown_event.is_set():
                    self.logger.warning("Supervisor: AiAppWatcher thread died! Restarting...")
                    self.apps_watcher = AiAppWatcherThread(self.outbox, self.config)
                    self.apps_watcher.start()

                self._shutdown_event.wait(5.0)
            except Exception as e:
                self.logger.error(f"Supervisor loop error: {e}")
                self._shutdown_event.wait(5.0)

    def request_shutdown(self, reason: str = "user_requested"):
        """Graceful shutdown (Section 6 G8)."""
        if self._shutdown_event.is_set():
            return
        self.logger.info(f"Initiating graceful agent shutdown: reason='{reason}'...")
        self._shutdown_event.set()

        # Emit agent_stop lifecycle event
        evt = EventFactory.create_lifecycle_event(event_type="agent_stop", reason=reason)
        self.outbox.enqueue(evt, severity="medium")

        # Stop watchers
        self.usb_watcher.stop()
        self.file_watcher.stop()
        self.clipboard_watcher.stop()
        self.apps_watcher.stop()
        self.heartbeat.stop()
        self.tray.stop()

        # Allow sender a moment to flush pending events
        time.sleep(1.0)
        self.sender.stop()

        # Remove marker file indicating clean stop
        if RUNNING_MARKER_FILE.exists():
            try:
                RUNNING_MARKER_FILE.unlink()
            except Exception:
                pass

        # Release mutex
        if self.mutex_handle and win32api:
            try:
                win32api.CloseHandle(self.mutex_handle)
            except Exception:
                pass

        self.logger.info("Agent stopped cleanly.")

def main():
    enable_tray = os.environ.get("AGENT_ENABLE_TRAY", "1") == "1" and "--no-tray" not in sys.argv
    agent = AgentSupervisor(AGENT_ROOT)
    agent.start(enable_tray=enable_tray)
    try:
        agent.supervisor_loop()
    except KeyboardInterrupt:
        agent.request_shutdown("keyboard_interrupt")

if __name__ == "__main__":
    main()
