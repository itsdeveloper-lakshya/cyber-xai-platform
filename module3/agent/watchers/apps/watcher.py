"""
AI Desktop App & Focus Session Watcher (Section 10 Steps P1 to P3)
Monitors desktop AI application usage and tracks active window focus time.
Features:
- Polls running processes against configured AI apps every 5 seconds.
- Tracks continuous foreground focus time per application.
- Emits app_session events upon focus blur or application exit.
- Captures browser usage with AI keywords without storing window titles.
"""

import time
from datetime import datetime, timezone
import threading
import logging
from typing import Dict, Any, Optional
import psutil

try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None
    win32process = None

from core.outbox import SQLiteOutbox
from core.event_factory import EventFactory
from core.config import AgentConfig

logger = logging.getLogger("cyber_sentinel_agent.apps")

class AppFocusTracker:
    def __init__(self, app_label: str):
        self.app_label = app_label
        self.started_at = datetime.now(timezone.utc)
        self.focus_seconds = 0
        self.last_tick = time.time()

    def add_focus(self, seconds: float):
        self.focus_seconds += int(seconds)
        self.last_tick = time.time()


class AiAppWatcherThread(threading.Thread):
    def __init__(self, outbox: SQLiteOutbox, config: AgentConfig, poll_interval: float = 1.0):
        super().__init__(name="AiAppWatcherThread", daemon=True)
        self.outbox = outbox
        self.config = config
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.status = "ok"

        self._active_session: Optional[AppFocusTracker] = None
        self._lock = threading.Lock()

    def stop(self):
        self._stop_event.set()
        self._flush_active_session()

    def get_status(self) -> str:
        return self.status

    def _flush_active_session(self):
        with self._lock:
            session = self._active_session
            self._active_session = None

        if session and session.focus_seconds >= 2:
            ended_at = datetime.now(timezone.utc)
            evt = EventFactory.create_app_session_event(
                app_label=session.app_label,
                started_at=session.started_at.isoformat(),
                ended_at=ended_at.isoformat(),
                focus_seconds=session.focus_seconds
            )
            self.outbox.enqueue(evt, severity="low")
            logger.info(f"AI App focus session emitted: {session.app_label} ({session.focus_seconds}s)")

    def _check_foreground_app(self):
        if not win32gui or not win32process:
            return

        try:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                self._flush_active_session()
                return

            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name().lower()
            except Exception:
                proc_name = ""

            title = win32gui.GetWindowText(hwnd).lower()

            cfg = self.config.active_config
            ai_apps = {a.get("process_name", "").lower(): a.get("label", "") for a in cfg.get("ai_apps", [])}
            ai_keywords = cfg.get("ai_keywords", [])

            current_app_label = None
            if proc_name in ai_apps:
                current_app_label = ai_apps[proc_name]
            elif any(kw in title for kw in ai_keywords):
                for kw in ai_keywords:
                    if kw in title:
                        current_app_label = f"Web AI ({kw.capitalize()})"
                        break

            with self._lock:
                if current_app_label:
                    if self._active_session and self._active_session.app_label == current_app_label:
                        self._active_session.add_focus(self.poll_interval)
                    else:
                        # Switched apps, flush old
                        old_session = self._active_session
                        self._active_session = AppFocusTracker(current_app_label)
                        self._active_session.add_focus(self.poll_interval)
                        if old_session and old_session.focus_seconds >= 2:
                            ended_at = datetime.now(timezone.utc)
                            evt = EventFactory.create_app_session_event(
                                app_label=old_session.app_label,
                                started_at=old_session.started_at.isoformat(),
                                ended_at=ended_at.isoformat(),
                                focus_seconds=old_session.focus_seconds
                            )
                            self.outbox.enqueue(evt, severity="low")
                else:
                    # Focus lost from AI apps
                    if self._active_session:
                        old_session = self._active_session
                        self._active_session = None
                        if old_session.focus_seconds >= 2:
                            ended_at = datetime.now(timezone.utc)
                            evt = EventFactory.create_app_session_event(
                                app_label=old_session.app_label,
                                started_at=old_session.started_at.isoformat(),
                                ended_at=ended_at.isoformat(),
                                focus_seconds=old_session.focus_seconds
                            )
                            self.outbox.enqueue(evt, severity="low")

        except Exception as e:
            logger.debug(f"App focus check error: {e}")

    def run(self):
        logger.info("AiAppWatcherThread started.")
        while not self._stop_event.is_set():
            try:
                self._check_foreground_app()
                self.status = "ok"
                self._stop_event.wait(self.poll_interval)
            except Exception as e:
                self.status = f"error: {str(e)[:20]}"
                logger.error(f"AiAppWatcherThread error: {e}")
                self._stop_event.wait(2.0)

        logger.info("AiAppWatcherThread stopped.")
