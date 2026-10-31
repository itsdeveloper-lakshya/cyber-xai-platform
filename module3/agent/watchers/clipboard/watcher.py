"""
Clipboard Watcher (Section 9 Steps C1 to C7)
Monitors system clipboard changes cheaply using Win32 clipboard sequence numbers.
Features:
- Polls GetClipboardSequenceNumber() twice per second (500ms).
- Respects password manager exclusion formats (Clipboard Viewer Ignore, etc.) -> skips completely.
- Content identification: Text, File List (count only, zero names), Image, Other.
- Caps text analysis at 100 KB and runs local ScoringEngine.
- Context capture: detects foreground process name and AI window keyword match.
- Strict data minimization: NEVER stores raw clipboard text, file names, or window titles.
- Filtering: high/medium/AI events queued to outbox; low-risk events increment heartbeat counter.
- Pure observation: never blocks or clears user clipboard.
"""

import time
import threading
import logging
from typing import Dict, Any, Optional, Tuple, Set
import psutil

try:
    import win32clipboard
    import win32gui
    import win32process
    import pywintypes
except ImportError:
    win32clipboard = None
    win32gui = None
    win32process = None
    pywintypes = None

from core.outbox import SQLiteOutbox
from core.event_factory import EventFactory
from core.config import AgentConfig
from scoring.scorer import ScoringEngine

logger = logging.getLogger("cyber_sentinel_agent.clipboard")

# Password manager exclusion clipboard format names (Section 9 C2)
EXCLUSION_FORMAT_NAMES = {
    "clipboard viewer ignore",
    "excludeclipboardcontentfrommonitor",
    "canincludeinclipboardhistory",
    "canuploadtocloudclipboard",
    "1password",
    "bitwarden"
}

# Process classification keywords
BROWSER_PROCESSES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
IDE_PROCESSES = {"code.exe", "devenv.exe", "pycharm64.exe", "idea64.exe", "sublime_text.exe", "notepad++.exe"}

class ClipboardWatcherThread(threading.Thread):
    def __init__(self, outbox: SQLiteOutbox, config: AgentConfig, poll_interval: float = 0.5):
        super().__init__(name="ClipboardWatcherThread", daemon=True)
        self.outbox = outbox
        self.config = config
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.status = "ok"

        self.scoring_engine = ScoringEngine()
        self.last_seq_num = 0
        self.low_risk_count = 0
        self._lock = threading.Lock()

    def stop(self):
        self._stop_event.set()

    def get_status(self) -> str:
        return self.status

    def get_and_reset_low_risk_count(self) -> int:
        with self._lock:
            val = self.low_risk_count
            self.low_risk_count = 0
            return val

    def _get_registered_exclusion_formats(self) -> Set[int]:
        """Resolves Windows clipboard format IDs for known password manager ignore flags."""
        registered = set()
        if not win32clipboard:
            return registered
        for name in EXCLUSION_FORMAT_NAMES:
            try:
                fid = win32clipboard.RegisterClipboardFormat(name)
                if fid:
                    registered.add(fid)
            except Exception:
                pass
        return registered

    def _get_foreground_context(self) -> Tuple[str, str, bool, Optional[str]]:
        """
        Retrieves active foreground application process name and checks for AI keyword matches.
        NEVER stores or returns the actual window title.
        """
        proc_name = "unknown"
        app_class = "unknown"
        ai_matched_kw = None
        is_ai_context = False

        if not win32gui or not win32process:
            return proc_name, app_class, is_ai_context, ai_matched_kw

        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()
                except Exception:
                    proc_name = "unknown"

                title = win32gui.GetWindowText(hwnd).lower()

                cfg = self.config.active_config
                ai_apps = {a.get("process_name", "").lower(): a.get("label", "") for a in cfg.get("ai_apps", [])}
                ai_keywords = cfg.get("ai_keywords", [])

                # Process classification
                if proc_name in ai_apps:
                    app_class = "ai_desktop_app"
                    is_ai_context = True
                    ai_matched_kw = ai_apps[proc_name]
                elif proc_name in BROWSER_PROCESSES:
                    app_class = "browser"
                elif proc_name in OFFICE_PROCESSES:
                    app_class = "office"
                elif proc_name in IDE_PROCESSES:
                    app_class = "ide"
                else:
                    app_class = "other"

                # Check if window title contains AI keywords without storing title
                for kw in ai_keywords:
                    if kw.lower() in title:
                        is_ai_context = True
                        if not ai_matched_kw:
                            ai_matched_kw = kw
                        break
        except Exception as e:
            logger.debug(f"Foreground context check error: {e}")

        return proc_name, app_class, is_ai_context, ai_matched_kw

    def _process_clipboard_change(self):
        if not win32clipboard:
            return

        # Step C2: Check exclusion formats (password managers)
        exclusion_ids = self._get_registered_exclusion_formats()
        try:
            win32clipboard.OpenClipboard()
        except pywintypes.error:
            # Clipboard busy/locked by another app, wait for next tick
            return

        try:
            # Inspect available clipboard formats
            current_format = 0
            has_exclusion = False
            has_text = False
            has_files = False
            has_image = False

            while True:
                current_format = win32clipboard.EnumClipboardFormats(current_format)
                if current_format == 0:
                    break
                if current_format in exclusion_ids:
                    has_exclusion = True
                    break
                if current_format in (win32clipboard.CF_UNICODETEXT, win32clipboard.CF_TEXT):
                    has_text = True
                elif current_format == win32clipboard.CF_HDROP:
                    has_files = True
                elif current_format in (win32clipboard.CF_BITMAP, win32clipboard.CF_DIB, win32clipboard.CF_DIBV5):
                    has_image = True

            if has_exclusion:
                logger.debug("Clipboard content marked with password manager exclusion format, skipping.")
                return

            proc_name, app_class, is_ai_context, ai_keyword = self._get_foreground_context()

            # Step C3: Identify content kind and extract metadata
            if has_files:
                # File list: record ONLY file count, NEVER file names (Test C-04)
                file_count = 0
                try:
                    file_list = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                    file_count = len(file_list) if file_list else 0
                except Exception:
                    file_count = 1

                evt = EventFactory.create_clipboard_event(
                    content_kind="files",
                    file_count=file_count,
                    risk_tier="low" if not is_ai_context else "medium",
                    foreground_app=proc_name,
                    foreground_class=app_class,
                    ai_context=is_ai_context,
                    ai_keyword=ai_keyword
                )
                self.outbox.enqueue(evt, severity="low" if not is_ai_context else "medium")
                logger.info(f"Clipboard file copy: {file_count} files, ai_context={is_ai_context}")
                return

            if has_image:
                # Image: record kind only (Test C-05)
                evt = EventFactory.create_clipboard_event(
                    content_kind="image",
                    risk_tier="low" if not is_ai_context else "medium",
                    foreground_app=proc_name,
                    foreground_class=app_class,
                    ai_context=is_ai_context,
                    ai_keyword=ai_keyword
                )
                if is_ai_context:
                    self.outbox.enqueue(evt, severity="medium")
                else:
                    with self._lock:
                        self.low_risk_count += 1
                return

            if has_text:
                # Text: analyze locally (Section 9 C4)
                raw_text = ""
                try:
                    if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                        raw_text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                    elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                        raw_bytes = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                        raw_text = raw_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    pass

                if not raw_text:
                    return

                char_count = len(raw_text)
                line_count = len(raw_text.split("\n"))

                cfg = self.config.active_config
                max_bytes = cfg.get("clipboard_max_bytes", 102400)

                # Local classification
                score_res = self.scoring_engine.score_text(raw_text, max_bytes=max_bytes)

                risk_tier = score_res["risk_tier"]
                final_score = score_res["final_score"]

                # Step C6: Decide what to store
                # Medium and high events, and ANY event with ai_context=True, are stored individually
                if risk_tier in ("medium", "high") or is_ai_context:
                    evt = EventFactory.create_clipboard_event(
                        content_kind="text",
                        char_count=char_count,
                        line_count=line_count,
                        matched_categories=score_res["matched_categories"],
                        regex_score=score_res["regex_score"],
                        ml_score=score_res["ml_score"],
                        final_score=final_score,
                        risk_tier=risk_tier,
                        foreground_app=proc_name,
                        foreground_class=app_class,
                        ai_context=is_ai_context,
                        ai_keyword=ai_keyword
                    )
                    self.outbox.enqueue(evt, severity=risk_tier)
                    logger.info(
                        f"Clipboard sensitive event queued: tier={risk_tier}, score={final_score}, "
                        f"categories={score_res['matched_categories']}, ai_context={is_ai_context}"
                    )
                    print("\n" + "=" * 65)
                    print(f" [LIVE EVENT] SENSITIVE TEXT COPIED TO CLIPBOARD!")
                    print(f"   Risk Tier    : {risk_tier.upper()} (Score: {final_score})")
                    print(f"   Characters   : {char_count} chars, {line_count} lines")
                    print(f"   Categories   : {score_res['matched_categories']}")
                    print(f"   App in Focus : {proc_name} ({app_class})")
                    print(f"   AI Context   : {is_ai_context} ({ai_keyword or 'None'})")
                    print(f"   Data Privacy : ZERO text content stored! Only category metadata.")
                    print("=" * 65 + "\n")
                else:
                    # Low-risk copies only increment per-minute counter
                    with self._lock:
                        self.low_risk_count += 1

        finally:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass

    def run(self):
        logger.info("ClipboardWatcherThread started.")
        if win32clipboard:
            try:
                self.last_seq_num = win32clipboard.GetClipboardSequenceNumber()
            except Exception:
                self.last_seq_num = 0

        while not self._stop_event.is_set():
            try:
                if win32clipboard:
                    current_seq = win32clipboard.GetClipboardSequenceNumber()
                    if current_seq != self.last_seq_num:
                        self.last_seq_num = current_seq
                        self._process_clipboard_change()

                self.status = "ok"
                self._stop_event.wait(self.poll_interval)
            except Exception as e:
                self.status = f"error: {str(e)[:20]}"
                logger.error(f"ClipboardWatcherThread error: {e}")
                self._stop_event.wait(1.0)

        logger.info("ClipboardWatcherThread stopped.")

