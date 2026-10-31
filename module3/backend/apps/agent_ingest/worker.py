"""
Module 3 Agent Redis Worker Consumer (Section 12 Step K3 & Section 13 Rules AG-01..AG-09)
Consumes from Redis Stream 'agent_events' using a consumer group.
Routes events by event_type:
- usb_connect / usb_disconnect -> agt_usb_event
- file_transfer_session -> agt_file_transfer_event
- clipboard_event -> agt_clipboard_event
- app_session -> agt_app_session
- agent_unclean_restart / agent_stop -> agt_health_alert
Evaluates server-side security rules AG-01 to AG-09 and writes to beh_rule_flag.
Issues XACK only after successful database commit.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta, time as dtime
from pathlib import Path
import redis

# Django setup
REPO_ROOT = Path(__file__).resolve()
while REPO_ROOT.parent != REPO_ROOT:
    if (REPO_ROOT / "module2" / "backend" / "manage.py").exists():
        break
    REPO_ROOT = REPO_ROOT.parent

BASE_DIR = REPO_ROOT / "module2" / "backend"
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / 'apps'))
sys.path.insert(0, str(REPO_ROOT / 'module3' / 'backend' / 'apps'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django
django.setup()

from django.db import transaction
from django.conf import settings
from agent_ingest.models import (
    AgtUsbEvent, AgtFileTransferEvent, AgtClipboardEvent, AgtAppSession, AgtDailyAgg, AgtHealthAlert
)
from behavior.models import BehRuleFlag
from devices.models import ExtDevice

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("agent_worker")

STREAM_NAME = "agent_events"
GROUP_NAME = "agent_consumers"
DEAD_LETTER_STREAM = "agent_events_dead_letter"
CONSUMER_NAME = f"agent_consumer_{os.getpid()}"

WORK_DAY_START = dtime(7, 0)
WORK_DAY_END = dtime(19, 0)

def is_after_hours_ts(dt: datetime) -> bool:
    """Uses shared after-hours window from Module 1 & 2 (07:00-19:00 Mon-Fri)"""
    if dt.weekday() >= 5:  # Weekend
        return True
    return dt.time() < WORK_DAY_START or dt.time() >= WORK_DAY_END

def process_agent_event(event: dict):
    event_type = event.get("event_type")
    user_id = event.get("user_id", "UNKNOWN")
    occurred_at_str = event.get("occurred_at")
    occurred_at = datetime.fromisoformat(occurred_at_str) if occurred_at_str else datetime.utcnow()
    after_hours = is_after_hours_ts(occurred_at)

    with transaction.atomic():
        # 1. Route USB events
        if event_type in ("usb_connect", "usb_disconnect"):
            vol_hash = event.get("volume_serial_hash")
            # Check is_first_seen_for_user (Section U6)
            is_first_seen = not AgtUsbEvent.objects.filter(user_id=user_id, volume_serial_hash=vol_hash).exists()

            AgtUsbEvent.objects.get_or_create(
                event_id=event["event_id"],
                defaults={
                    "user_id": user_id,
                    "occurred_at": occurred_at,
                    "event_type": "connect" if event_type == "usb_connect" else "disconnect",
                    "device_class": event.get("device_class", "mass_storage"),
                    "drive_letter": event.get("drive_letter"),
                    "volume_serial_hash": vol_hash,
                    "usb_vid_pid": event.get("usb_vid_pid"),
                    "capacity_gb": event.get("capacity_gb"),
                    "fs_type": event.get("fs_type"),
                    "is_encrypted": event.get("is_encrypted"),
                    "is_first_seen_for_user": is_first_seen,
                    "is_after_hours": after_hours
                }
            )

            # Rule AG-01: USB connect outside after-hours window (Low)
            if event_type == "usb_connect" and after_hours:
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=occurred_at.date(),
                    rule_id="AG-01",
                    severity="low",
                    source_module="agent",
                    mitre_technique="T1052.001",
                    reason_text=f"USB removable drive connected outside normal working hours at {occurred_at.strftime('%H:%M:%S')}."
                )

            # Rule AG-02: First-ever use of this USB device by this user (Low)
            if event_type == "usb_connect" and is_first_seen:
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=occurred_at.date(),
                    rule_id="AG-02",
                    severity="low",
                    source_module="agent",
                    mitre_technique="T1052.001",
                    reason_text=f"First-ever use of USB device (hash: {vol_hash[:12]}...) by employee {user_id}."
                )

        # 2. Route File Transfer Session events
        elif event_type == "file_transfer_session":
            s_start = datetime.fromisoformat(event["session_start"])
            s_end = datetime.fromisoformat(event["session_end"])
            file_count = event.get("file_count", 0)
            total_bytes = event.get("total_bytes", 0)
            sens_count = event.get("sensitive_ext_count", 0)
            arch_count = event.get("archive_count", 0)

            AgtFileTransferEvent.objects.get_or_create(
                event_id=event["event_id"],
                defaults={
                    "user_id": user_id,
                    "session_start": s_start,
                    "session_end": s_end,
                    "volume_serial_hash": event.get("volume_serial_hash", ""),
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                    "max_file_bytes": event.get("max_file_bytes", 0),
                    "ext_histogram": event.get("ext_histogram", {}),
                    "sensitive_ext_count": sens_count,
                    "archive_count": arch_count,
                    "duration_seconds": event.get("duration_seconds", 0),
                    "is_after_hours": after_hours,
                    "is_partial": event.get("is_partial", False)
                }
            )

            # Rule AG-03: Massive copy session (High)
            if file_count >= 200 or total_bytes >= 500_000_000:
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=s_start.date(),
                    rule_id="AG-03",
                    severity="high",
                    source_module="agent",
                    mitre_technique="T1052.001",
                    reason_text=f"Massive file transfer to USB: {file_count} files ({total_bytes/(1024*1024):.1f} MB) in single session."
                )

            # Rule AG-04: Sensitive-extension files threshold (Medium)
            if sens_count >= 5:
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=s_start.date(),
                    rule_id="AG-04",
                    severity="medium",
                    source_module="agent",
                    mitre_technique="T1052.001",
                    reason_text=f"Exfiltration risk: {sens_count} sensitive files (.pem, .key, .sql, .env, .xlsx) written to USB."
                )

            # Rule AG-05: Archive files created on drive (Medium)
            if arch_count >= 1:
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=s_start.date(),
                    rule_id="AG-05",
                    severity="medium",
                    source_module="agent",
                    mitre_technique="T1560",
                    reason_text="Archive file created or written directly to removable USB media."
                )

            # Rule AG-08: After-hours USB connect followed by large copy within 10 minutes (High)
            if after_hours and (file_count >= 50 or total_bytes >= 50_000_000):
                window_start = s_start - timedelta(minutes=10)
                recent_usb = AgtUsbEvent.objects.filter(
                    user_id=user_id,
                    event_type="connect",
                    is_after_hours=True,
                    occurred_at__gte=window_start,
                    occurred_at__lte=s_start
                ).exists()
                if recent_usb:
                    BehRuleFlag.objects.create(
                        user_id=user_id,
                        date=s_start.date(),
                        rule_id="AG-08",
                        severity="high",
                        source_module="agent",
                        mitre_technique="T1052.001",
                        reason_text=f"After-hours exfiltration sequence: USB drive connected outside work hours followed by copy of {file_count} files within 10 minutes."
                    )

        # 3. Route Clipboard events
        elif event_type == "clipboard_event":
            AgtClipboardEvent.objects.get_or_create(
                event_id=event["event_id"],
                defaults={
                    "user_id": user_id,
                    "occurred_at": occurred_at,
                    "content_kind": event.get("content_kind", "text"),
                    "char_count": event.get("char_count"),
                    "line_count": event.get("line_count"),
                    "file_count": event.get("file_count"),
                    "matched_categories": event.get("matched_categories", []),
                    "regex_score": event.get("regex_score", 0.0),
                    "ml_score": event.get("ml_score", 0.0),
                    "final_score": event.get("final_score", 0.0),
                    "risk_tier": event.get("risk_tier", "low"),
                    "foreground_app": event.get("foreground_app", "unknown"),
                    "foreground_class": event.get("foreground_class", "unknown"),
                    "ai_context": event.get("ai_context", False),
                    "ai_keyword": event.get("ai_keyword"),
                }
            )

            # Rule AG-06: High-tier clipboard copy while AI app is focused (High)
            if event.get("risk_tier") == "high" and event.get("ai_context"):
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=occurred_at.date(),
                    rule_id="AG-06",
                    severity="high",
                    source_module="agent",
                    mitre_technique="T1115",
                    reason_text=f"Sensitive secret copied to clipboard while desktop AI application ({event.get('foreground_app')}) was in focus."
                )

            # Rule AG-07: Three or more medium or high clipboard events within 10 minutes (Medium)
            if event.get("risk_tier") in ("medium", "high"):
                window_10m = occurred_at - timedelta(minutes=10)
                recent_copies_count = AgtClipboardEvent.objects.filter(
                    user_id=user_id,
                    risk_tier__in=["medium", "high"],
                    occurred_at__gte=window_10m,
                    occurred_at__lte=occurred_at
                ).count()
                if recent_copies_count >= 3:
                    BehRuleFlag.objects.create(
                        user_id=user_id,
                        date=occurred_at.date(),
                        rule_id="AG-07",
                        severity="medium",
                        source_module="agent",
                        mitre_technique="T1115",
                        reason_text=f"Rapid sensitive data harvesting: {recent_copies_count} medium/high clipboard copies within 10 minutes."
                    )

        # 4. Route AI Desktop App Sessions
        elif event_type == "app_session":
            s_start = datetime.fromisoformat(event["started_at"])
            s_end = datetime.fromisoformat(event["ended_at"])
            AgtAppSession.objects.get_or_create(
                event_id=event["event_id"],
                defaults={
                    "user_id": user_id,
                    "app_label": event.get("app_label", "unknown"),
                    "started_at": s_start,
                    "ended_at": s_end,
                    "focus_seconds": event.get("focus_seconds", 0)
                }
            )

        # 5. Route Lifecycle & Unclean Restarts
        elif event_type == "agent_unclean_restart":
            AgtHealthAlert.objects.create(
                user_id=user_id,
                alert_type="ungraceful_stop",
                severity="medium",
                started_at=occurred_at,
                details={"reason": event.get("reason", "Process killed or system crashed")}
            )

            # Rule AG-09: Heartbeat gap or unclean restart within 30 minutes after USB or high clipboard event (High)
            window_30m = occurred_at - timedelta(minutes=30)
            had_usb = AgtUsbEvent.objects.filter(user_id=user_id, occurred_at__gte=window_30m).exists()
            had_high_clip = AgtClipboardEvent.objects.filter(user_id=user_id, risk_tier="high", occurred_at__gte=window_30m).exists()
            if had_usb or had_high_clip:
                BehRuleFlag.objects.create(
                    user_id=user_id,
                    date=occurred_at.date(),
                    rule_id="AG-09",
                    severity="high",
                    source_module="agent",
                    mitre_technique="T1562.001",
                    reason_text="Defense evasion: agent killed or crashed within 30 minutes of suspicious USB activity or high-risk secret clipboard copy."
                )

def run_agent_worker():
    r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        r.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
    except redis.exceptions.ResponseError:
        pass

    logger.info(f"Agent worker listening on stream '{STREAM_NAME}'...")
    while True:
        try:
            messages = r.xreadgroup(GROUP_NAME, CONSUMER_NAME, {STREAM_NAME: ">"}, count=10, block=2000)
            if not messages:
                continue

            for stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        event_dict = json.loads(data.get("data", "{}"))
                        process_agent_event(event_dict)
                        r.xack(STREAM_NAME, GROUP_NAME, msg_id)
                    except Exception as err:
                        logger.error(f"Error in agent event {msg_id}: {err}")
                        r.xadd(DEAD_LETTER_STREAM, {"error": str(err), "data": data.get("data", "")})
                        r.xack(STREAM_NAME, GROUP_NAME, msg_id)
        except Exception as e:
            time.sleep(1)

if __name__ == "__main__":
    run_agent_worker()
