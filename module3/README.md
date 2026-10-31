# Module 3: OS-Level Endpoint Agent (Windows, Python Prototype)

## Overview
Module 3 is the Windows Endpoint Agent component of the Cyber Sentinel Insider Threat Detection platform. It monitors:
- **USB Events**: Removable mass storage attachments, removals, and volume identification.
- **File-Copy Sessions**: Groups file burst writes to removable media into discrete sessions with extension histograms, byte tallies, and sensitive/archive file counts (with ZERO file names collected).
- **Clipboard Sensitivity & AI Context**: Cheaply polls clipboard sequence numbers, applies local on-device ML/regex classification, and detects foreground AI desktop apps.
- **Health & Heartbeat**: Reports queue depth, CPU%, memory, watcher health, and raises alerts on heartbeat gaps, clock skew, and unclean process terminations.
- **Security Rule Engine**: Evaluates server-side rules **AG-01 through AG-10** and writes to `beh_rule_flag`.

---

## Quickstart & Verification

### 1. Prerequisites & Services
Ensure PostgreSQL 15 and Redis 7 are running:
```powershell
docker compose up -d
```

### 2. Apply Django Migrations
```powershell
cd module2\backend
..\..\venv\Scripts\python.exe manage.py migrate
cd ..\..
```

### 3. Run the Verification Test Suite
Execute the comprehensive 44-test verification matrix:
```powershell
.\venv\Scripts\python.exe -m pytest module3\agent\tests\ -v
```

### 4. Running the Agent Interactively
```powershell
.\venv\Scripts\python.exe module3\agent\main.py
```
To run the Redis stream consumer worker in a separate terminal:
```powershell
.\venv\Scripts\python.exe module3\backend\apps\agent_ingest\worker.py
```

---

## Test Matrix Summary
| Test Category | IDs | Coverage |
|---|---|---|
| **USB Watcher** | `U-01` to `U-08` | Connect/disconnect pairing, debounce, fixed drive detection, ignore mice/keyboards, fallback scan, asleep/wake handling, MTP limitation. |
| **File Sessions** | `F-01` to `F-08` | Single file, 1000 files grouped, final size re-read, nested folders, unplug mid-copy partial flush, wait-and-copy 2 sessions, zip archive count, inspect payloads for zero file names. |
| **Clipboard** | `C-01` to `C-10` | Low-tier ordinary text, fake secret high tier, AI app context, files count only, image kind only, password manager exclusion, 5MB text truncation, regex timeout test, rapid copies, **C-10 Scorer Parity with Node.js**. |
| **Core & Outbox** | `G-01` to `G-04` | Named mutex single instance lock, offline queue buffering, 50k capacity cap with priority dropping, supervisor thread resurrection. |
| **Privacy & Perf** | `X-01` to `X-04` | Zero content in payloads, metadata only in SQLite outbox, log file test string redaction, idle resource budget (< 2% CPU, < 100 MB RAM). |
| **Rules Engine** | `AG-01` to `AG-10` | Positive and negative scripted test cases for all 10 endpoint security rules. |
