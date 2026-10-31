# Module 3: Event Payload Contracts (Frozen Week 1)

This document formalizes the exact schema of every event emitted by the Windows Endpoint Agent to the ingestion endpoint (`POST /api/v1/agent/events`) and serialized to PostgreSQL.

---

## 1. `usb_connect` & `usb_disconnect`
Emitted upon USB mass storage insertion/removal.

```json
{
  "event_id": "UUIDv4",
  "event_type": "usb_connect",
  "occurred_at": "2026-10-31T01:00:00.000000+00:00",
  "device_class": "mass_storage",
  "drive_letter": "E:",
  "volume_serial_hash": "64-character SHA-256 hash of (salt + volume serial)",
  "usb_vid_pid": "0781:5583",
  "capacity_gb": 32.0,
  "fs_type": "NTFS",
  "is_encrypted": false
}
```

---

## 2. `file_transfer_session`
Emitted when a file copy session to a removable drive closes after a 15-second quiet period or capacity cap.
**Data Minimization: ZERO file names or source paths are ever collected or transmitted.**

```json
{
  "event_id": "UUIDv4",
  "event_type": "file_transfer_session",
  "occurred_at": "2026-10-31T01:15:00.000000+00:00",
  "session_start": "2026-10-31T01:00:00.000000+00:00",
  "session_end": "2026-10-31T01:15:00.000000+00:00",
  "volume_serial_hash": "64-character SHA-256 hash",
  "usb_connect_event_id": null,
  "file_count": 42,
  "total_bytes": 104857600,
  "max_file_bytes": 10485760,
  "ext_histogram": {
    ".docx": 10,
    ".pdf": 15,
    ".xlsx": 12,
    ".zip": 5
  },
  "sensitive_ext_count": 27,
  "archive_count": 5,
  "duration_seconds": 900,
  "is_partial": false
}
```

---

## 3. `clipboard_event`
Emitted for medium and high risk copies, or any copy occurring while a desktop AI application is focused.
**Data Minimization: ZERO raw clipboard text or window titles are stored. Only metadata and rule categories.**

```json
{
  "event_id": "UUIDv4",
  "event_type": "clipboard_event",
  "occurred_at": "2026-10-31T01:10:00.000000+00:00",
  "content_kind": "text",
  "char_count": 120,
  "line_count": 3,
  "file_count": null,
  "matched_categories": ["CloudAccessKey"],
  "regex_score": 1.0,
  "ml_score": 0.9998,
  "final_score": 1.0,
  "risk_tier": "high",
  "foreground_app": "chatgpt.exe",
  "foreground_class": "ai_desktop_app",
  "ai_context": true,
  "ai_keyword": "ChatGPT Desktop"
}
```

---

## 4. `app_session`
Emitted when a desktop AI app window loses focus or exits.

```json
{
  "event_id": "UUIDv4",
  "event_type": "app_session",
  "occurred_at": "2026-10-31T01:25:00.000000+00:00",
  "app_label": "Claude Desktop",
  "started_at": "2026-10-31T01:20:00.000000+00:00",
  "ended_at": "2026-10-31T01:25:00.000000+00:00",
  "focus_seconds": 300
}
```

---

## 5. `agt_heartbeat`
Emitted every 60 seconds to `POST /api/v1/agent/heartbeat`.

```json
{
  "agent_started_at": "2026-10-31T00:30:00.000000+00:00",
  "client_version": "1.0.0",
  "queue_depth": 0,
  "dropped_events_total": 0,
  "watcher_status": {
    "usb": "ok",
    "file": "ok",
    "clipboard": "ok",
    "apps": "ok"
  },
  "events_sent_since_last": 5,
  "low_risk_clipboard_count": 12,
  "cpu_pct": 0.4,
  "mem_mb": 42.5,
  "config_version": 1,
  "clock_skew_seconds": 0.0
}
```
