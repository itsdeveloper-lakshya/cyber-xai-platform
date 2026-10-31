"""
File-Copy Session Watcher (Section 8 Steps F1 to F6)
Groups bursts of file write events on removable drives into discrete copy sessions.
Features:
- Watchdog recursive filesystem observer on mounted USB drive letters.
- Session starts on first create/move event.
- Closes after 15 seconds of quiet (configurable).
- Session caps: 30 minutes or 100,000 files -> flush as partial and start new session.
- Handles in-progress copies by re-reading final file sizes upon session close.
- Aggregates file count, total bytes, max bytes, extension histogram, sensitive/archive counts.
- Strict data minimization: ZERO file names or paths stored anywhere (Test F-08 & X-01).
- Unplug mid-copy: flushes open session as is_partial=True immediately.
"""

import os
import time
from datetime import datetime, timezone
import threading
import logging
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Tuple
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent

from core.outbox import SQLiteOutbox
from core.event_factory import EventFactory
from core.config import AgentConfig

logger = logging.getLogger("cyber_sentinel_agent.file_sessions")

IGNORED_DIRECTORIES = {
    "$recycle.bin",
    "system volume information",
    ".trashes",
    ".spotlight-v100",
    ".fseventsd"
}

IGNORED_PREFIXES = ("~", ".~", "tmp_", ".tmp_")
IGNORED_SUFFIXES = (".tmp", ".crdownload", ".part", ".swp", ".bak~")

class DriveCopySession:
    """Manages an active copy session on a specific USB volume."""
    def __init__(self, drive_letter: str, volume_serial_hash: str, config: AgentConfig):
        self.drive_letter = drive_letter
        self.volume_serial_hash = volume_serial_hash
        self.config = config

        self.session_start = datetime.now(timezone.utc)
        self.last_activity_time = time.time()
        self.is_closed = False

        # Internal tracking set of paths during the session to read final sizes at close
        # Paths are NEVER written to events or logs!
        self._tracked_paths: Set[str] = set()
        self._lock = threading.Lock()

    def record_file_event(self, file_path: str):
        with self._lock:
            self._tracked_paths.add(file_path)
            self.last_activity_time = time.time()

    def check_should_close(self, quiet_threshold: float, max_duration_sec: float, max_files: int) -> Tuple[bool, bool]:
        with self._lock:
            now = time.time()
            elapsed_session = (datetime.now(timezone.utc) - self.session_start).total_seconds()
            quiet_seconds = now - self.last_activity_time
            file_count = len(self._tracked_paths)

            if quiet_seconds >= quiet_threshold:
                return True, False  # Close normally due to quiet
            if elapsed_session >= max_duration_sec or file_count >= max_files:
                return True, True   # Close due to capacity cap (is_partial = True)
            return False, False

    def finalize(self, is_partial: bool = False) -> Optional[Dict[str, Any]]:
        """
        Re-reads final file sizes, aggregates extension histogram, and builds event.
        Guarantees zero file names in returned dictionary.
        """
        with self._lock:
            if self.is_closed:
                return None
            self.is_closed = True
            session_end = datetime.now(timezone.utc)
            paths = list(self._tracked_paths)
            self._tracked_paths.clear()

        if not paths:
            return None

        cfg = self.config.active_config
        sensitive_exts = set(cfg.get("sensitive_extensions", []))
        archive_exts = set(cfg.get("archive_extensions", []))

        total_bytes = 0
        max_file_bytes = 0
        ext_histogram: Dict[str, int] = {}
        sensitive_ext_count = 0
        archive_count = 0
        valid_file_count = 0

        for p_str in paths:
            try:
                p = Path(p_str)
                # Re-read final size (Section 8 F3)
                if p.exists() and p.is_file():
                    sz = p.stat().st_size
                    total_bytes += sz
                    if sz > max_file_bytes:
                        max_file_bytes = sz
                else:
                    sz = 0
            except Exception:
                sz = 0

            # Extension categorization
            ext = os.path.splitext(p_str)[1].lower()
            if not ext:
                ext = "none"
            ext_histogram[ext] = ext_histogram.get(ext, 0) + 1
            valid_file_count += 1

            if ext in sensitive_exts:
                sensitive_ext_count += 1
            if ext in archive_exts:
                archive_count += 1

        duration_seconds = max(1, int((session_end - self.session_start).total_seconds()))

        # Determine severity for outbox priority
        severity = "low"
        if valid_file_count >= 200 or total_bytes >= 524288000:
            severity = "high"
        elif sensitive_ext_count >= 5 or archive_count >= 1:
            severity = "medium"

        event = EventFactory.create_file_session_event(
            session_start=self.session_start.isoformat(),
            session_end=session_end.isoformat(),
            volume_serial_hash=self.volume_serial_hash,
            file_count=valid_file_count,
            total_bytes=total_bytes,
            max_file_bytes=max_file_bytes,
            ext_histogram=ext_histogram,
            sensitive_ext_count=sensitive_ext_count,
            archive_count=archive_count,
            duration_seconds=duration_seconds,
            is_partial=is_partial
        )
        return {"event": event, "severity": severity}


class UsbDriveEventHandler(FileSystemEventHandler):
    """Watchdog event handler filtering noise and recording write events."""
    def __init__(self, session_manager: 'FileSessionWatcher'):
        super().__init__()
        self.session_manager = session_manager

    def _should_ignore(self, path_str: str) -> bool:
        low = path_str.lower()
        parts = [p.lower() for p in Path(path_str).parts]
        for ignored in IGNORED_DIRECTORIES:
            if ignored in parts:
                return True
        name = os.path.basename(path_str).lower()
        if any(name.startswith(pfx) for pfx in IGNORED_PREFIXES):
            return True
        if any(name.endswith(sfx) for sfx in IGNORED_SUFFIXES):
            return True
        return False

    def on_created(self, event):
        if not event.is_directory and not self._should_ignore(event.src_path):
            self.session_manager.record_activity(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and not self._should_ignore(event.src_path):
            self.session_manager.record_activity(event.src_path)

    def on_moved(self, event):
        if not event.is_directory and not self._should_ignore(event.dest_path):
            self.session_manager.record_activity(event.dest_path)


class FileSessionWatcher(threading.Thread):
    def __init__(self, outbox: SQLiteOutbox, config: AgentConfig):
        super().__init__(name="FileSessionWatcherThread", daemon=True)
        self.outbox = outbox
        self.config = config
        self._stop_event = threading.Event()
        self.status = "ok"

        # Drive letter -> Observer instance
        self._observers: Dict[str, Observer] = {}
        # Drive letter -> Active DriveCopySession
        self._active_sessions: Dict[str, DriveCopySession] = {}
        # Drive letter -> volume_serial_hash
        self._drive_vol_hashes: Dict[str, str] = {}
        self._lock = threading.Lock()

    def get_status(self) -> str:
        return self.status

    def start_watching_drive(self, drive_letter: str, volume_serial_hash: str):
        """Called by USB watcher upon volume arrival (Section 7 U5)."""
        dl = drive_letter[:2].upper()
        root_path = dl + "\\"
        if not os.path.exists(root_path):
            return

        with self._lock:
            if dl in self._observers:
                return

            try:
                observer = Observer()
                handler = UsbDriveEventHandler(self)
                observer.schedule(handler, path=root_path, recursive=True)
                observer.start()
                self._observers[dl] = observer
                self._drive_vol_hashes[dl] = volume_serial_hash
                logger.info(f"FileSessionWatcher: started monitoring drive root {dl}\\")
            except Exception as e:
                logger.error(f"Failed to start watchdog on {dl}: {e}")

    def stop_watching_drive(self, drive_letter: str, volume_serial_hash: str):
        """Called by USB watcher upon volume removal (Section 7 U5 & F-05)."""
        dl = drive_letter[:2].upper()
        with self._lock:
            observer = self._observers.pop(dl, None)
            self._drive_vol_hashes.pop(dl, None)
            session = self._active_sessions.pop(dl, None)

        if observer:
            try:
                observer.stop()
                observer.join(timeout=2.0)
            except Exception:
                pass

        # Unplug mid-copy: immediately flush open session as partial
        if session:
            logger.info(f"Drive {dl} unplugged mid-session: flushing partial copy session.")
            res = session.finalize(is_partial=True)
            if res:
                self.outbox.enqueue(res["event"], severity=res["severity"])

    def record_activity(self, file_path: str):
        dl = file_path[:2].upper()
        with self._lock:
            vol_hash = self._drive_vol_hashes.get(dl, "")
            if not vol_hash:
                return

            session = self._active_sessions.get(dl)
            if not session:
                session = DriveCopySession(dl, vol_hash, self.config)
                self._active_sessions[dl] = session
                logger.debug(f"FileSessionWatcher: opened new copy session on {dl}")
                print(f" [LIVE ACTIVITY] Opened active file-copy session on {dl}\\")

            session.record_file_event(file_path)

    def stop(self):
        self._stop_event.set()
        # Flush all active sessions
        with self._lock:
            tracked = list(self._active_sessions.keys())
        for dl in tracked:
            with self._lock:
                session = self._active_sessions.pop(dl, None)
            if session:
                res = session.finalize(is_partial=True)
                if res:
                    self.outbox.enqueue(res["event"], severity=res["severity"])

        # Stop observers
        with self._lock:
            observers = list(self._observers.values())
            self._observers.clear()
        for obs in observers:
            try:
                obs.stop()
                obs.join(timeout=1.0)
            except Exception:
                pass

    def run(self):
        logger.info("FileSessionWatcher thread started.")
        while not self._stop_event.is_set():
            try:
                cfg = self.config.active_config
                quiet_sec = cfg.get("session_quiet_seconds", 15)
                max_duration = cfg.get("session_max_duration_seconds", 1800)
                max_files = cfg.get("session_max_files", 100000)

                sessions_to_close = []
                with self._lock:
                    for dl, session in list(self._active_sessions.items()):
                        should_close, is_partial = session.check_should_close(quiet_sec, max_duration, max_files)
                        if should_close:
                            sessions_to_close.append((dl, session, is_partial))
                            del self._active_sessions[dl]

                for dl, session, is_partial in sessions_to_close:
                    res = session.finalize(is_partial=is_partial)
                    if res:
                        self.outbox.enqueue(res["event"], severity=res["severity"])
                        evt = res["event"]
                        logger.info(
                            f"Closed copy session on {dl}: {evt['file_count']} files, "
                            f"{evt['total_bytes']} bytes, duration={evt['duration_seconds']}s, "
                            f"partial={is_partial}"
                        )
                        print("\n" + "=" * 65)
                        print(f" [LIVE EVENT] USB FILE-COPY SESSION COMPLETED!")
                        print(f"   Drive Letter : {dl}\\")
                        print(f"   Files Copied : {evt['file_count']} files")
                        print(f"   Total Size   : {evt['total_bytes']:,} bytes ({evt['total_bytes']/(1024*1024):.2f} MB)")
                        print(f"   Extensions   : {evt['ext_histogram']}")
                        print(f"   Sensitive    : {evt['sensitive_ext_count']} sensitive files (.key, .sql, .xlsx, etc.)")
                        print(f"   Archives     : {evt['archive_count']} archive files (.zip, etc.)")
                        print(f"   Data Privacy : METADATA ONLY! Zero file names or file paths stored.")
                        print(f"   Delivery     : Queued in SQLite Outbox -> Forwarded to Backend Worker")
                        print("=" * 65 + "\n")

                self._stop_event.wait(1.0)
                self.status = "ok"
            except Exception as e:
                self.status = f"error: {str(e)[:20]}"
                logger.error(f"FileSessionWatcher error: {e}")
                self._stop_event.wait(2.0)

        logger.info("FileSessionWatcher thread stopped.")

