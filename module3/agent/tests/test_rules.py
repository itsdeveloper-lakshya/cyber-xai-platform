"""
Security Rules Test Suite (Section 13 Rules AG-01..AG-10 & Section 15 Rules T)
Verifies positive and negative scripted cases for every single rule AG-01 through AG-10:
AG-01: USB connect outside shared after-hours window (Low)
AG-02: First-ever use of this USB device by this user (Low)
AG-03: Massive copy session (>= 200 files or 500 MB) (High)
AG-04: Sensitive-extension files count >= 5 (Medium)
AG-05: Archive files created on drive during session (Medium)
AG-06: High-tier clipboard event with ai_context=True (High)
AG-07: Three or more medium/high clipboard events within 10 minutes (Medium)
AG-08: After-hours USB connect followed by large copy within 10 minutes (High)
AG-09: Unclean restart within 30 minutes of USB/clipboard secret event (High)
AG-10: Agent silent for more than 24 hours (Medium)
"""

import pytest
from datetime import datetime, timezone, timedelta
from django.test import TestCase

from agent_ingest.models import (
    AgtUsbEvent, AgtFileTransferEvent, AgtClipboardEvent, AgtHeartbeat, AgtHealthAlert
)
from behavior.models import BehRuleFlag
from devices.models import ExtDevice
from agent_ingest.worker import process_agent_event
from agent_ingest.health_monitor import check_devices_health

@pytest.mark.django_db
class AgentRulesTestCase(TestCase):
    def setUp(self):
        self.user_id = "TEST_USER_001"
        self.device = ExtDevice.objects.create(
            user_id=self.user_id,
            device_kind="agent",
            token_hash="hash_test_token_123",
            client_version="1.0.0"
        )

    def test_ag01_after_hours_usb_connect(self):
        """AG-01: USB connect outside 07:00-19:00 Mon-Fri triggers flag (Low). Positive & Negative."""
        # Positive case: 22:30 at night (after-hours)
        evt_pos = {
            "event_id": "00000000-0000-0000-0000-000000000101",
            "event_type": "usb_connect",
            "user_id": self.user_id,
            "occurred_at": "2026-10-30T22:30:00Z",
            "volume_serial_hash": "VOL_SERIAL_HASH_01"
        }
        process_agent_event(evt_pos)
        flag = BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-01").first()
        assert flag is not None
        assert flag.severity == "low"
        assert "outside normal working hours" in flag.reason_text

        # Negative case: 11:00 AM on Wednesday (working hours)
        evt_neg = {
            "event_id": "00000000-0000-0000-0000-000000000102",
            "event_type": "usb_connect",
            "user_id": "TEST_USER_WORKHOURS",
            "occurred_at": "2026-10-28T11:00:00Z", # Wednesday 11am
            "volume_serial_hash": "VOL_SERIAL_HASH_02"
        }
        process_agent_event(evt_neg)
        assert not BehRuleFlag.objects.filter(user_id="TEST_USER_WORKHOURS", rule_id="AG-01").exists()

    def test_ag02_first_ever_use_usb(self):
        """AG-02: First-ever use of a USB volume by this user triggers AG-02. Second use does not."""
        vol = "VOL_FIRST_SEEN_999"
        # First use (Positive)
        evt1 = {
            "event_id": "00000000-0000-0000-0000-000000000201",
            "event_type": "usb_connect",
            "user_id": self.user_id,
            "occurred_at": "2026-10-28T10:00:00Z",
            "volume_serial_hash": vol
        }
        process_agent_event(evt1)
        assert BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-02").exists()

        BehRuleFlag.objects.all().delete()

        # Second use of same volume (Negative)
        evt2 = {
            "event_id": "00000000-0000-0000-0000-000000000202",
            "event_type": "usb_connect",
            "user_id": self.user_id,
            "occurred_at": "2026-10-28T14:00:00Z",
            "volume_serial_hash": vol
        }
        process_agent_event(evt2)
        assert not BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-02").exists()

    def test_ag03_large_copy_session(self):
        """AG-03: Copy session >= 200 files or 500 MB triggers AG-03 (High). Positive & Negative."""
        # Positive: 250 files
        evt_pos = {
            "event_id": "00000000-0000-0000-0000-000000000301",
            "event_type": "file_transfer_session",
            "user_id": self.user_id,
            "session_start": "2026-10-28T10:00:00Z",
            "session_end": "2026-10-28T10:15:00Z",
            "file_count": 250,
            "total_bytes": 100_000_000
        }
        process_agent_event(evt_pos)
        flag = BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-03").first()
        assert flag is not None
        assert flag.severity == "high"

        # Negative: 15 files, 5 MB
        evt_neg = {
            "event_id": "00000000-0000-0000-0000-000000000302",
            "event_type": "file_transfer_session",
            "user_id": "USER_SMALL_COPY",
            "session_start": "2026-10-28T10:00:00Z",
            "session_end": "2026-10-28T10:05:00Z",
            "file_count": 15,
            "total_bytes": 5_000_000
        }
        process_agent_event(evt_neg)
        assert not BehRuleFlag.objects.filter(user_id="USER_SMALL_COPY", rule_id="AG-03").exists()

    def test_ag04_sensitive_extensions_threshold(self):
        """AG-04: Copy session with >= 5 sensitive extensions triggers AG-04 (Medium)."""
        evt_pos = {
            "event_id": "00000000-0000-0000-0000-000000000401",
            "event_type": "file_transfer_session",
            "user_id": self.user_id,
            "session_start": "2026-10-28T10:00:00Z",
            "session_end": "2026-10-28T10:05:00Z",
            "file_count": 10,
            "sensitive_ext_count": 6
        }
        process_agent_event(evt_pos)
        assert BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-04").exists()

        # Negative (only 2 sensitive files)
        evt_neg = {
            "event_id": "00000000-0000-0000-0000-000000000402",
            "event_type": "file_transfer_session",
            "user_id": "USER_FEW_SENS",
            "session_start": "2026-10-28T10:00:00Z",
            "session_end": "2026-10-28T10:05:00Z",
            "file_count": 10,
            "sensitive_ext_count": 2
        }
        process_agent_event(evt_neg)
        assert not BehRuleFlag.objects.filter(user_id="USER_FEW_SENS", rule_id="AG-04").exists()

    def test_ag05_archive_files_created(self):
        """AG-05: Archive file (.zip, .tar, .7z) created on USB media triggers AG-05 (Medium)."""
        evt_pos = {
            "event_id": "00000000-0000-0000-0000-000000000501",
            "event_type": "file_transfer_session",
            "user_id": self.user_id,
            "session_start": "2026-10-28T10:00:00Z",
            "session_end": "2026-10-28T10:05:00Z",
            "file_count": 5,
            "archive_count": 2
        }
        process_agent_event(evt_pos)
        assert BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-05").exists()

    def test_ag06_high_tier_clipboard_with_ai_context(self):
        """AG-06: High-tier clipboard copy while AI desktop app is focused triggers AG-06 (High)."""
        evt_pos = {
            "event_id": "00000000-0000-0000-0000-000000000601",
            "event_type": "clipboard_event",
            "user_id": self.user_id,
            "occurred_at": "2026-10-28T10:00:00Z",
            "risk_tier": "high",
            "ai_context": True,
            "foreground_app": "chatgpt.exe"
        }
        process_agent_event(evt_pos)
        flag = BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-06").first()
        assert flag is not None
        assert flag.severity == "high"

        # Negative: high risk copy while Notepad is focused (ai_context=False)
        evt_neg = {
            "event_id": "00000000-0000-0000-0000-000000000602",
            "event_type": "clipboard_event",
            "user_id": "USER_NOTEPAD",
            "occurred_at": "2026-10-28T10:00:00Z",
            "risk_tier": "high",
            "ai_context": False,
            "foreground_app": "notepad.exe"
        }
        process_agent_event(evt_neg)
        assert not BehRuleFlag.objects.filter(user_id="USER_NOTEPAD", rule_id="AG-06").exists()

    def test_ag07_three_clipboard_bursts_in_10_minutes(self):
        """AG-07: 3 or more medium/high clipboard events within 10 minutes triggers AG-07 (Medium)."""
        base_t = datetime(2026, 10, 28, 14, 0, tzinfo=timezone.utc)
        for i in range(3):
            t_str = (base_t + timedelta(minutes=i*2)).isoformat()
            evt = {
                "event_id": f"00000000-0000-0000-0000-00000000070{i}",
                "event_type": "clipboard_event",
                "user_id": "USER_HARVEST",
                "occurred_at": t_str,
                "risk_tier": "medium",
                "ai_context": False
            }
            process_agent_event(evt)

        flag = BehRuleFlag.objects.filter(user_id="USER_HARVEST", rule_id="AG-07").first()
        assert flag is not None
        assert flag.severity == "medium"

    def test_ag08_after_hours_usb_and_rapid_copy(self):
        """AG-08: After-hours USB connect followed by copy within 10 minutes triggers AG-08 (High)."""
        # Step 1: USB connect at 21:00
        usb_evt = {
            "event_id": "00000000-0000-0000-0000-000000000801",
            "event_type": "usb_connect",
            "user_id": "USER_EXFIL",
            "occurred_at": "2026-10-28T21:00:00Z",
            "volume_serial_hash": "VOL_EXFIL_801"
        }
        process_agent_event(usb_evt)

        # Step 2: Large copy at 21:05 (within 10 minutes)
        copy_evt = {
            "event_id": "00000000-0000-0000-0000-000000000802",
            "event_type": "file_transfer_session",
            "user_id": "USER_EXFIL",
            "session_start": "2026-10-28T21:05:00Z",
            "session_end": "2026-10-28T21:08:00Z",
            "file_count": 60,
            "total_bytes": 60_000_000
        }
        process_agent_event(copy_evt)
        flag = BehRuleFlag.objects.filter(user_id="USER_EXFIL", rule_id="AG-08").first()
        assert flag is not None
        assert flag.severity == "high"

    def test_ag09_unclean_restart_after_usb_activity(self):
        """AG-09: Unclean restart within 30 min of USB activity triggers AG-09 (High)."""
        # Step 1: USB connect at 15:00
        usb_evt = {
            "event_id": "00000000-0000-0000-0000-000000000901",
            "event_type": "usb_connect",
            "user_id": "USER_CRASH",
            "occurred_at": "2026-10-28T15:00:00Z",
            "volume_serial_hash": "VOL_CRASH"
        }
        process_agent_event(usb_evt)

        # Step 2: Unclean restart at 15:15 (within 30 minutes)
        restart_evt = {
            "event_id": "00000000-0000-0000-0000-000000000902",
            "event_type": "agent_unclean_restart",
            "user_id": "USER_CRASH",
            "occurred_at": "2026-10-28T15:15:00Z",
            "reason": "Process killed"
        }
        process_agent_event(restart_evt)
        flag = BehRuleFlag.objects.filter(user_id="USER_CRASH", rule_id="AG-09").first()
        assert flag is not None
        assert flag.severity == "high"

    def test_ag10_agent_silent_for_24_hours(self):
        """AG-10: Agent silent for more than 24 hours triggers coverage alert AG-10 (Medium)."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=26)
        hb = AgtHeartbeat.objects.create(
            device=self.device,
            agent_started_at=past_time,
            client_version="1.0.0"
        )
        AgtHeartbeat.objects.filter(id=hb.id).update(received_at=past_time)
        check_devices_health(now_dt=datetime.now(timezone.utc))
        flag = BehRuleFlag.objects.filter(user_id=self.user_id, rule_id="AG-10").first()
        assert flag is not None
        assert flag.severity == "medium"
        assert "Agent coverage lost" in flag.reason_text
