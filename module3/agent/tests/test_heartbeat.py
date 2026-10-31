"""
Agent Heartbeat Thread Test Suite (Module 3 Section 11 Step H1 & Section 5.2)
Verifies:
H-01: Heartbeat payload structure contains all required health metrics
H-02: Successful transmission (200 OK) records telemetry
H-03: Offline tolerance when server is unreachable without crashing the thread
H-04: Graceful shutdown via stop()
"""

import time
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import requests

from core.heartbeat import HeartbeatThread
from core.outbox import SQLiteOutbox
from core.config import AgentConfig

def test_heartbeat_payload_and_delivery(tmp_path):
    """H-01 & H-02: Verify telemetry payload fields and successful check-in."""
    outbox = SQLiteOutbox(tmp_path / "test_outbox.db")
    config = MagicMock(spec=AgentConfig)
    config.get_token.return_value = "test_agent_token_secret"
    config.client_version = "1.0.0"
    config.server_url = "http://127.0.0.1:8000"
    config.active_config = {"heartbeat_interval_sec": 60, "config_version": 1}

    watcher_statuses = lambda: {"usb": "ok", "files": "ok", "clipboard": "ok", "apps": "ok"}
    low_risk_count = lambda: 14
    started_at = datetime.now(timezone.utc)

    hb_thread = HeartbeatThread(
        outbox=outbox,
        config=config,
        get_watcher_statuses=watcher_statuses,
        get_low_risk_clipboard_count=low_risk_count,
        agent_started_at=started_at
    )

    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        hb_thread._send_heartbeat()

        assert mock_post.called
        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == "http://127.0.0.1:8000/api/v1/agent/heartbeat"

        payload = call_kwargs["json"]
        headers = call_kwargs["headers"]

        assert headers["Authorization"] == "Bearer test_agent_token_secret"
        assert payload["client_version"] == "1.0.0"
        assert payload["queue_depth"] == 0
        assert payload["dropped_events_total"] == 0
        assert payload["watcher_status"]["usb"] == "ok"
        assert payload["low_risk_clipboard_count"] == 14
        assert payload["config_version"] == 1
        assert "cpu_pct" in payload
        assert "mem_mb" in payload
        assert "clock_skew_seconds" in payload

def test_heartbeat_offline_handling(tmp_path):
    """H-03: Verify graceful offline buffering when server connection drops."""
    outbox = SQLiteOutbox(tmp_path / "test_outbox.db")
    config = MagicMock(spec=AgentConfig)
    config.get_token.return_value = "test_agent_token_secret"
    config.server_url = "http://127.0.0.1:8000"
    config.active_config = {"heartbeat_interval_sec": 60}

    hb_thread = HeartbeatThread(
        outbox=outbox,
        config=config,
        get_watcher_statuses=lambda: {"usb": "ok"},
        get_low_risk_clipboard_count=lambda: 0,
        agent_started_at=datetime.now(timezone.utc)
    )

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        # Should not raise exception or crash
        hb_thread._send_heartbeat()

def test_heartbeat_thread_start_and_stop(tmp_path):
    """H-04: Heartbeat thread starts and stops gracefully upon request."""
    outbox = SQLiteOutbox(tmp_path / "test_outbox.db")
    config = MagicMock(spec=AgentConfig)
    config.get_token.return_value = None  # Not registered yet
    config.active_config = {"heartbeat_interval_sec": 1}

    hb_thread = HeartbeatThread(
        outbox=outbox,
        config=config,
        get_watcher_statuses=lambda: {},
        get_low_risk_clipboard_count=lambda: 0,
        agent_started_at=datetime.now(timezone.utc)
    )

    hb_thread.start()
    assert hb_thread.is_alive()
    time.sleep(0.1)
    hb_thread.stop()
    hb_thread.join(timeout=2.0)
    assert not hb_thread.is_alive()
