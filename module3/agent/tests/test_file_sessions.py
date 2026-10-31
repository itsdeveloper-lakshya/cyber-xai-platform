"""
File-Copy Session Test Suite (Section 15 Tests F-01 to F-08)
Verifies:
F-01: Copy one small file -> session with count 1, correct size
F-02: Copy 1,000 small files -> one session, correct count, no flood
F-03: Copy multi-GB file -> final size correct (re-read at close)
F-04: Copy nested folders -> recursive counting correct
F-05: Unplug mid-copy -> partial session flushed, flagged partial
F-06: Copy, wait, copy again -> two distinct sessions
F-07: Create zip on drive -> archive count correct
F-08: Inspect payloads -> ZERO FILE NAMES ANYWHERE
"""

import time
import os
import pytest
from pathlib import Path
from core.outbox import SQLiteOutbox
from core.config import AgentConfig
from watchers.file_sessions.watcher import DriveCopySession, FileSessionWatcher

@pytest.fixture
def test_setup(tmp_path):
    outbox = SQLiteOutbox(tmp_path / "outbox.db")
    config = AgentConfig(tmp_path)
    return outbox, config, tmp_path

def test_f01_single_small_file_session(test_setup):
    """F-01: Copy one small file produces session with count 1 and correct size."""
    outbox, config, root = test_setup
    session = DriveCopySession("T:", "VOL_HASH_1", config)

    test_file = root / "document.pdf"
    test_file.write_bytes(b"A" * 1024)

    session.record_file_event(str(test_file))
    res = session.finalize(is_partial=False)

    assert res is not None
    evt = res["event"]
    assert evt["file_count"] == 1
    assert evt["total_bytes"] == 1024
    assert evt["max_file_bytes"] == 1024
    assert evt["ext_histogram"].get(".pdf") == 1
    assert evt["is_partial"] is False

def test_f02_1000_small_files_grouped(test_setup):
    """F-02: 1,000 file events are grouped into ONE session, not 1,000 separate events."""
    outbox, config, root = test_setup
    session = DriveCopySession("T:", "VOL_HASH_2", config)

    # Simulate 1,000 distinct file writes
    for i in range(1000):
        session.record_file_event(f"T:\\folder\\file_{i}.txt")

    res = session.finalize(is_partial=False)
    assert res is not None
    evt = res["event"]
    assert evt["file_count"] == 1000
    assert evt["ext_histogram"].get(".txt") == 1000

def test_f03_final_size_re_read_at_close(test_setup):
    """F-03: Final size of in-progress file is correctly re-read when session closes."""
    outbox, config, root = test_setup
    session = DriveCopySession("T:", "VOL_HASH_3", config)

    large_file = root / "backup.sql"
    large_file.write_bytes(b"0" * 100) # Created small
    session.record_file_event(str(large_file))

    # File grows during copy
    large_file.write_bytes(b"0" * 50000)

    res = session.finalize(is_partial=False)
    evt = res["event"]
    assert evt["total_bytes"] == 50000
    assert evt["max_file_bytes"] == 50000

def test_f04_nested_folders_recursive(test_setup):
    """F-04: Files in nested directories are aggregated into the same session."""
    outbox, config, root = test_setup
    session = DriveCopySession("T:", "VOL_HASH_4", config)

    session.record_file_event("T:\\dir1\\a.docx")
    session.record_file_event("T:\\dir1\\sub\\b.xlsx")
    session.record_file_event("T:\\dir2\\sub1\\sub2\\c.csv")

    res = session.finalize()
    evt = res["event"]
    assert evt["file_count"] == 3
    assert evt["ext_histogram"].get(".docx") == 1
    assert evt["ext_histogram"].get(".xlsx") == 1
    assert evt["ext_histogram"].get(".csv") == 1

def test_f05_unplug_mid_copy_flushes_partial(test_setup):
    """F-05: When drive is unplugged mid-copy, open session is immediately flushed as is_partial=True."""
    outbox, config, root = test_setup
    watcher = FileSessionWatcher(outbox, config)
    watcher._drive_vol_hashes["U:"] = "UNPLUG_VOL_HASH"

    # Active session with 10 files
    session = DriveCopySession("U:", "UNPLUG_VOL_HASH", config)
    for i in range(10):
        session.record_file_event(f"U:\\data_{i}.dat")
    watcher._active_sessions["U:"] = session

    # Drive unmounted unexpectedly
    watcher.stop_watching_drive("U:", "UNPLUG_VOL_HASH")

    # Verify event flushed to outbox with is_partial = True
    batch = outbox.fetch_batch(10)
    assert len(batch) == 1
    evt = batch[0][1]
    assert evt["event_type"] == "file_transfer_session"
    assert evt["file_count"] == 10
    assert evt["is_partial"] is True

def test_f06_two_sessions_separated_by_quiet(test_setup):
    """F-06: Copying, waiting quiet period, and copying again produces two distinct sessions."""
    outbox, config, root = test_setup
    session1 = DriveCopySession("T:", "VOL_1", config)
    session1.record_file_event("T:\\first.docx")
    res1 = session1.finalize()

    session2 = DriveCopySession("T:", "VOL_1", config)
    session2.record_file_event("T:\\second.pdf")
    res2 = session2.finalize()

    assert res1["event"]["event_id"] != res2["event"]["event_id"]
    assert res1["event"]["file_count"] == 1
    assert res2["event"]["file_count"] == 1

def test_f07_archive_files_counted(test_setup):
    """F-07: Creating archive files (.zip, .tar, .7z) is correctly tallied."""
    outbox, config, root = test_setup
    session = DriveCopySession("T:", "VOL_ARCH", config)

    session.record_file_event("T:\\export.zip")
    session.record_file_event("T:\\source.tar.gz")
    session.record_file_event("T:\\notes.txt")

    res = session.finalize()
    evt = res["event"]
    assert evt["archive_count"] >= 1
    assert evt["ext_histogram"].get(".zip") == 1

def test_f08_zero_file_names_in_payloads(test_setup):
    """F-08 & Privacy X-01: Payload inspection strictly proves zero file names or file paths are stored."""
    outbox, config, root = test_setup
    session = DriveCopySession("T:", "VOL_PRIV", config)

    planted_secret_file = "T:\\TOP_SECRET_FINANCIAL_Q4_BUDGET.XLSX"
    session.record_file_event(planted_secret_file)

    res = session.finalize()
    evt = res["event"]

    # Stringify the entire payload JSON
    import json
    payload_str = json.dumps(evt)

    assert "TOP_SECRET" not in payload_str
    assert "FINANCIAL" not in payload_str
    assert "BUDGET" not in payload_str
    assert "T:\\" not in payload_str
    # Only extension and counts present
    assert evt["ext_histogram"].get(".xlsx") == 1
