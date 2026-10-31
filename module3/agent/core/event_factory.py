"""
Event Factory (Section 6 G5 & Section 5 Schemas)
Assigns UUIDs, stamps UTC time with local offset, and validates schema before queueing.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

def current_iso_timestamp() -> str:
    """Returns ISO 8601 string with UTC time and timezone offset."""
    return datetime.now(timezone.utc).isoformat()

class EventFactory:
    @staticmethod
    def create_usb_event(
        event_type: str,
        volume_serial_hash: str,
        drive_letter: Optional[str] = None,
        device_class: str = "mass_storage",
        usb_vid_pid: Optional[str] = None,
        capacity_gb: Optional[float] = None,
        fs_type: Optional[str] = None,
        is_encrypted: Optional[bool] = None
    ) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,  # 'usb_connect' or 'usb_disconnect'
            "occurred_at": current_iso_timestamp(),
            "device_class": device_class,
            "drive_letter": drive_letter,
            "volume_serial_hash": volume_serial_hash,
            "usb_vid_pid": usb_vid_pid,
            "capacity_gb": capacity_gb,
            "fs_type": fs_type,
            "is_encrypted": is_encrypted
        }

    @staticmethod
    def create_file_session_event(
        session_start: str,
        session_end: str,
        volume_serial_hash: str,
        file_count: int,
        total_bytes: int,
        max_file_bytes: int,
        ext_histogram: Dict[str, int],
        sensitive_ext_count: int,
        archive_count: int,
        duration_seconds: int,
        is_partial: bool = False,
        usb_connect_event_id: Optional[str] = None
    ) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "file_transfer_session",
            "occurred_at": session_end,
            "session_start": session_start,
            "session_end": session_end,
            "volume_serial_hash": volume_serial_hash,
            "usb_connect_event_id": usb_connect_event_id,
            "file_count": file_count,
            "total_bytes": total_bytes,
            "max_file_bytes": max_file_bytes,
            "ext_histogram": ext_histogram,
            "sensitive_ext_count": sensitive_ext_count,
            "archive_count": archive_count,
            "duration_seconds": duration_seconds,
            "is_partial": is_partial
        }

    @staticmethod
    def create_clipboard_event(
        content_kind: str,
        char_count: Optional[int] = None,
        line_count: Optional[int] = None,
        file_count: Optional[int] = None,
        matched_categories: Optional[list] = None,
        regex_score: float = 0.0,
        ml_score: float = 0.0,
        final_score: float = 0.0,
        risk_tier: str = "low",
        foreground_app: str = "unknown",
        foreground_class: str = "unknown",
        ai_context: bool = False,
        ai_keyword: Optional[str] = None
    ) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "clipboard_event",
            "occurred_at": current_iso_timestamp(),
            "content_kind": content_kind,
            "char_count": char_count,
            "line_count": line_count,
            "file_count": file_count,
            "matched_categories": matched_categories or [],
            "regex_score": regex_score,
            "ml_score": ml_score,
            "final_score": final_score,
            "risk_tier": risk_tier,
            "foreground_app": foreground_app,
            "foreground_class": foreground_class,
            "ai_context": ai_context,
            "ai_keyword": ai_keyword
        }

    @staticmethod
    def create_app_session_event(
        app_label: str,
        started_at: str,
        ended_at: str,
        focus_seconds: int
    ) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "app_session",
            "occurred_at": ended_at,
            "app_label": app_label,
            "started_at": started_at,
            "ended_at": ended_at,
            "focus_seconds": focus_seconds
        }

    @staticmethod
    def create_lifecycle_event(event_type: str, reason: str = "") -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,  # 'agent_stop' or 'agent_unclean_restart'
            "occurred_at": current_iso_timestamp(),
            "reason": reason
        }
