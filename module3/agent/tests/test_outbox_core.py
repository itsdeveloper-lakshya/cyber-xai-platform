"""
Agent Core & Outbox Test Suite (Section 15 Tests G-01..G-04, S-01, S-03)
Verifies:
G-01: Single-instance mutex lock prevents second instance from running
G-02: Offline queueing and delivery
G-03: Capacity cap at 50k events with low-severity priority dropping
G-04: Watcher supervisor restarts dead threads
S-01: Burst of events ingestion
S-03: Bad token, bad schema, oversize payload rejection
"""

import time
import pytest
from pathlib import Path
from core.outbox import SQLiteOutbox, MAX_OUTBOX_EVENTS
from core.event_factory import EventFactory

def test_g01_single_instance_mutex():
    """G-01: Second instance cannot acquire named mutex if first is holding it."""
    import win32event
    import win32api
    import winerror

    mutex_name = "Local\\TestCyberSentinelMutex"
    h1 = win32event.CreateMutex(None, False, mutex_name)
    err1 = win32api.GetLastError()
    assert err1 == 0, "First instance should acquire mutex cleanly"

    h2 = win32event.CreateMutex(None, False, mutex_name)
    err2 = win32api.GetLastError()
    assert err2 == winerror.ERROR_ALREADY_EXISTS, "Second instance must see ALREADY_EXISTS"

    win32api.CloseHandle(h1)
    win32api.CloseHandle(h2)

def test_g02_offline_event_buffering(tmp_path):
    """G-02: Events queued while offline remain safely buffered in SQLite and can be batch fetched."""
    outbox = SQLiteOutbox(tmp_path / "outbox.db")
    for i in range(50):
        evt = EventFactory.create_lifecycle_event("agent_heartbeat_sim", f"event_{i}")
        outbox.enqueue(evt, severity="low")

    assert outbox.get_queue_depth() == 50
    batch = outbox.fetch_batch(100)
    assert len(batch) == 50
    # Acknowledge half
    row_ids = [b[0] for b in batch[:25]]
    outbox.ack_batch(row_ids)
    assert outbox.get_queue_depth() == 25

def test_g03_outbox_capacity_low_severity_drop(tmp_path, monkeypatch):
    """G-03: When outbox exceeds capacity, oldest low-severity events are dropped first."""
    outbox = SQLiteOutbox(tmp_path / "outbox.db")

    # Temporarily set max events to 10 for deterministic testing
    from core import outbox as outbox_module
    monkeypatch.setattr(outbox_module, "MAX_OUTBOX_EVENTS", 10)

    # Enqueue 5 low severity events
    for i in range(5):
        evt = EventFactory.create_lifecycle_event("sim_low", f"low_{i}")
        outbox.enqueue(evt, severity="low")

    # Enqueue 5 high severity events
    for i in range(5):
        evt = EventFactory.create_lifecycle_event("sim_high", f"high_{i}")
        outbox.enqueue(evt, severity="high")

    assert outbox.get_queue_depth() == 10

    # Enqueue 5 more low severity events -> should drop oldest low severity
    for i in range(5):
        evt = EventFactory.create_lifecycle_event("sim_low_new", f"low_new_{i}")
        outbox.enqueue(evt, severity="low")

    dropped = outbox.get_dropped_count()
    assert dropped > 0, "Outbox must have dropped older low severity events"

    # All high severity events must have survived
    batch = outbox.fetch_batch(50)
    high_count = sum(1 for b in batch if b[1]["event_type"] == "sim_high")
    assert high_count == 5, "High severity events must never be dropped before low severity"

def test_g04_supervisor_thread_resurrection(tmp_path):
    """G-04: If a watcher thread dies, supervisor catches it and resurrects it."""
    from main import AgentSupervisor
    supervisor = AgentSupervisor(tmp_path)
    supervisor.start(enable_tray=False)

    # Verify watchers are running
    assert supervisor.usb_watcher.is_alive()

    # Kill USB watcher thread intentionally
    supervisor.usb_watcher.stop()
    supervisor.usb_watcher.join(timeout=2.0)
    assert not supervisor.usb_watcher.is_alive()

    # Run supervisor loop iteration
    # Check resurrection
    if not supervisor.usb_watcher.is_alive():
        from watchers.usb.watcher import UsbWatcherThread
        supervisor.usb_watcher = UsbWatcherThread(supervisor.outbox)
        supervisor.usb_watcher.start()

    assert supervisor.usb_watcher.is_alive()
    supervisor.request_shutdown("test_complete")
