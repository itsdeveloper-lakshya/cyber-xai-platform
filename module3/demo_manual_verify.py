"""
Interactive Manual Verification Runner for Module 3 (Rules AG-01 to AG-10)
Allows testing each security rule on-demand and inspecting PostgreSQL outputs in real time.
"""

import os
import sys
import json
import uuid
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Setup Django environment
REPO_ROOT = Path(__file__).resolve()
while REPO_ROOT.parent != REPO_ROOT:
    if (REPO_ROOT / "module2" / "backend" / "manage.py").exists():
        break
    REPO_ROOT = REPO_ROOT.parent

BASE_DIR = REPO_ROOT / "module2" / "backend"
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
sys.path.insert(0, str(REPO_ROOT / "module3" / "backend" / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django
django.setup()

import redis
from django.conf import settings
from behavior.models import BehRuleFlag
from agent_ingest.models import AgtUsbEvent, AgtFileTransferEvent, AgtClipboardEvent, AgtHeartbeat
from devices.models import ExtDevice
from agent_ingest.health_monitor import check_devices_health

r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
STREAM_NAME = "agent_events"
TEST_USER = "EMP_VERIFY_DEMO"

def print_separator(title):
    print("\n" + "=" * 70)
    print(f" >>> {title}")
    print("=" * 70)

def publish_event(evt):
    try:
        r.xadd(STREAM_NAME, {"data": json.dumps(evt)})
    except Exception:
        pass
    # Directly process event so manual verification works with or without background worker
    from agent_ingest.worker import process_agent_event
    process_agent_event(evt)
    print(f" [->] Emitted and processed event: {evt['event_type']} (ID: {evt['event_id'][:8]}...)")
    time.sleep(0.1)

def show_recent_flags(rule_id):
    flags = BehRuleFlag.objects.filter(user_id=TEST_USER, rule_id=rule_id).order_by("-id")[:3]
    if flags.exists():
        for f in flags:
            print(f" [PASS] RULE TRIGGERED: [{f.rule_id}] Severity: {f.severity.upper()} | MITRE: {f.mitre_technique or 'N/A'}")
            print(f"        Reason: {f.reason_text}\n")
    else:
        print(f" [FAIL] No flags found for {rule_id}.\n")

# ==============================================================================
# RULE VERIFICATIONS
# ==============================================================================

def verify_ag01():
    print_separator("TESTING RULE AG-01: After-Hours USB Connect")
    print("Scenario: User plugs in a USB storage drive at 11:30 PM (after-hours: outside 07:00-19:00).")
    evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "usb_connect",
        "user_id": TEST_USER,
        "occurred_at": "2026-10-30T23:30:00Z",
        "volume_serial_hash": "VOL_HASH_AG01_DEMO",
        "drive_letter": "E:",
        "device_class": "mass_storage",
        "capacity_gb": 32.0,
        "fs_type": "NTFS"
    }
    publish_event(evt)
    show_recent_flags("AG-01")

def verify_ag02():
    print_separator("TESTING RULE AG-02: First-Ever Use of USB Device")
    new_vol = f"VOL_BRAND_NEW_{uuid.uuid4().hex[:8]}"
    print(f"Scenario: User connects a brand new, previously unseen USB drive (Hash: {new_vol[:12]}...).")
    evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "usb_connect",
        "user_id": TEST_USER,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "volume_serial_hash": new_vol,
        "drive_letter": "F:",
        "device_class": "mass_storage"
    }
    publish_event(evt)
    show_recent_flags("AG-02")

def verify_ag03():
    print_separator("TESTING RULE AG-03: Massive File Copy Session (>= 200 files or 500 MB)")
    print("Scenario: User writes 350 files (750 MB) to removable media in one session.")
    now = datetime.now(timezone.utc)
    evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "file_transfer_session",
        "user_id": TEST_USER,
        "session_start": (now - timedelta(minutes=10)).isoformat(),
        "session_end": now.isoformat(),
        "volume_serial_hash": "VOL_MASS_COPY",
        "file_count": 350,
        "total_bytes": 786432000,
        "max_file_bytes": 52428800,
        "ext_histogram": {".pdf": 150, ".docx": 100, ".xlsx": 100},
        "sensitive_ext_count": 0,
        "archive_count": 0,
        "duration_seconds": 600
    }
    publish_event(evt)
    show_recent_flags("AG-03")

def verify_ag04():
    print_separator("TESTING RULE AG-04: Exfiltration of Sensitive Extension Files (>= 5)")
    print("Scenario: User copies 8 sensitive files (.pem, .key, .sql, .env) to a flash drive.")
    now = datetime.now(timezone.utc)
    evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "file_transfer_session",
        "user_id": TEST_USER,
        "session_start": (now - timedelta(minutes=3)).isoformat(),
        "session_end": now.isoformat(),
        "volume_serial_hash": "VOL_SENSITIVE_FILES",
        "file_count": 12,
        "total_bytes": 1048576,
        "max_file_bytes": 204800,
        "ext_histogram": {".pem": 3, ".key": 2, ".env": 2, ".sql": 1, ".txt": 4},
        "sensitive_ext_count": 8,
        "archive_count": 0,
        "duration_seconds": 180
    }
    publish_event(evt)
    show_recent_flags("AG-04")

def verify_ag05():
    print_separator("TESTING RULE AG-05: Archive File Created On USB Drive")
    print("Scenario: User creates an archive (.zip / .tar.gz) directly on removable media.")
    now = datetime.now(timezone.utc)
    evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "file_transfer_session",
        "user_id": TEST_USER,
        "session_start": (now - timedelta(minutes=2)).isoformat(),
        "session_end": now.isoformat(),
        "volume_serial_hash": "VOL_ARCHIVE",
        "file_count": 2,
        "total_bytes": 52428800,
        "max_file_bytes": 50000000,
        "ext_histogram": {".zip": 1, ".txt": 1},
        "sensitive_ext_count": 0,
        "archive_count": 1,
        "duration_seconds": 120
    }
    publish_event(evt)
    show_recent_flags("AG-05")

def verify_ag06():
    print_separator("TESTING RULE AG-06: High-Risk Clipboard Copy with AI App Focused")
    print("Scenario: User copies a Cloud Access Key (AKIA...) while ChatGPT Desktop is in foreground.")
    evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "clipboard_event",
        "user_id": TEST_USER,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "content_kind": "text",
        "char_count": 64,
        "line_count": 1,
        "matched_categories": ["CloudAccessKey"],
        "regex_score": 1.0,
        "ml_score": 0.9999,
        "final_score": 1.0,
        "risk_tier": "high",
        "foreground_app": "chatgpt.exe",
        "foreground_class": "ai_desktop_app",
        "ai_context": True,
        "ai_keyword": "ChatGPT Desktop"
    }
    publish_event(evt)
    show_recent_flags("AG-06")

def verify_ag07():
    print_separator("TESTING RULE AG-07: Rapid Sensitive Data Harvesting (>= 3 in 10 mins)")
    print("Scenario: User copies 3 medium/high risk text chunks within a 5-minute span.")
    now = datetime.now(timezone.utc)
    for i in range(3):
        t = (now - timedelta(minutes=4 - i)).isoformat()
        evt = {
            "event_id": str(uuid.uuid4()),
            "event_type": "clipboard_event",
            "user_id": TEST_USER,
            "occurred_at": t,
            "content_kind": "text",
            "char_count": 150,
            "line_count": 5,
            "matched_categories": ["PAN" if i == 0 else "ConfidentialityMarker"],
            "regex_score": 0.7,
            "ml_score": 0.65,
            "final_score": 0.68,
            "risk_tier": "medium",
            "foreground_app": "chrome.exe",
            "foreground_class": "browser",
            "ai_context": False
        }
        publish_event(evt)
    show_recent_flags("AG-07")

def verify_ag08():
    print_separator("TESTING RULE AG-08: After-Hours USB Connect Followed by Large Copy (< 10 min)")
    print("Scenario: USB connected at 22:00, followed immediately at 22:04 by copying 75 files.")
    t_conn = "2026-10-30T22:00:00Z"
    t_copy = "2026-10-30T22:04:00Z"

    # Connect
    evt1 = {
        "event_id": str(uuid.uuid4()),
        "event_type": "usb_connect",
        "user_id": TEST_USER,
        "occurred_at": t_conn,
        "volume_serial_hash": "VOL_AG08_EXFIL"
    }
    publish_event(evt1)

    # Copy
    evt2 = {
        "event_id": str(uuid.uuid4()),
        "event_type": "file_transfer_session",
        "user_id": TEST_USER,
        "session_start": t_copy,
        "session_end": "2026-10-30T22:08:00Z",
        "volume_serial_hash": "VOL_AG08_EXFIL",
        "file_count": 75,
        "total_bytes": 60000000
    }
    publish_event(evt2)
    show_recent_flags("AG-08")

def verify_ag09():
    print_separator("TESTING RULE AG-09: Defense Evasion (Unclean Restart after USB / Secret)")
    print("Scenario: USB connected, followed 10 minutes later by an unclean agent termination / crash.")
    now = datetime.now(timezone.utc)
    t_usb = (now - timedelta(minutes=15)).isoformat()
    t_restart = now.isoformat()

    # USB
    evt1 = {
        "event_id": str(uuid.uuid4()),
        "event_type": "usb_connect",
        "user_id": TEST_USER,
        "occurred_at": t_usb,
        "volume_serial_hash": "VOL_AG09_CRASH"
    }
    publish_event(evt1)

    # Crash / Kill restart
    evt2 = {
        "event_id": str(uuid.uuid4()),
        "event_type": "agent_unclean_restart",
        "user_id": TEST_USER,
        "occurred_at": t_restart,
        "reason": "Process terminated abnormally without stop event"
    }
    publish_event(evt2)
    show_recent_flags("AG-09")

def verify_ag10():
    print_separator("TESTING RULE AG-10: Agent Silent for More Than 24 Hours (Coverage Lost)")
    print("Scenario: Endpoint device check-in is older than 24 hours.")
    dev, _ = ExtDevice.objects.get_or_create(
        user_id=TEST_USER,
        device_kind="agent",
        defaults={"token_hash": "hash_demo_ag10", "client_version": "1.0.0"}
    )
    past_time = datetime.now(timezone.utc) - timedelta(hours=26)
    hb = AgtHeartbeat.objects.create(
        device=dev,
        agent_started_at=past_time,
        client_version="1.0.0"
    )
    AgtHeartbeat.objects.filter(id=hb.id).update(received_at=past_time)
    print(" [i] Running server-side health monitor audit...")
    check_devices_health(now_dt=datetime.now(timezone.utc))
    show_recent_flags("AG-10")

def run_all():
    verify_ag01()
    verify_ag02()
    verify_ag03()
    verify_ag04()
    verify_ag05()
    verify_ag06()
    verify_ag07()
    verify_ag08()
    verify_ag09()
    verify_ag10()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        func_map = {
            "ag01": verify_ag01, "ag02": verify_ag02, "ag03": verify_ag03,
            "ag04": verify_ag04, "ag05": verify_ag05, "ag06": verify_ag06,
            "ag07": verify_ag07, "ag08": verify_ag08, "ag09": verify_ag09,
            "ag10": verify_ag10, "all": run_all
        }
        if arg in func_map:
            func_map[arg]()
        else:
            print(f"Unknown rule '{arg}'. Options: ag01..ag10, all")
    else:
        run_all()
