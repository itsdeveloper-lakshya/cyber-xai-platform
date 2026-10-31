# Module 3: Threat Model of the Endpoint Agent

## 1. Overview
The Cyber Sentinel Windows Endpoint Agent is designed to detect insider exfiltration via USB mass storage and desktop AI tools while enforcing strict data minimization. This threat model analyzes malicious actions an employee could take to evade or disable the agent and documents the detection capabilities and limits of the prototype.

---

## 2. Adversarial Actions and Mitigations

| Threat / Evasion Action | Prototype Agent Detection & Handling | Production Hardening Path (Documented Limitation) |
|---|---|---|
| **Process Termination (`taskkill /f`)** | Next startup detects missing clean shutdown record and generates an `agent_unclean_restart` event. Server detects heartbeat gap (> 180s) and generates `heartbeat_gap` alert. If preceded by USB/secret copy, triggers **Rule AG-09** (Defense Evasion, T1562.001). | Run as a Windows Kernel / Minifilter Driver + SYSTEM protected process (PP / PPL) with code signing. |
| **System Clock Tampering** | Heartbeat compares device system time against server timestamp. Skew > 120s triggers `clock_skew` health alert. | Secure time synchronization using signed NTP / server-signed challenge responses. |
| **Network Disconnection / Flight Mode** | Offline SQLite queue buffers up to 50,000 events locally with ACID transactions. Server generates heartbeat gap alert after 3 missed intervals. Upon reconnection, all queued events are sent with exponential backoff and idempotency. | In a true exfiltration attempt, physical theft of unmanaged laptops requires BitLocker enforcement. |
| **Outbox DB Flooding / Tampering** | FIFO queue prioritizes high-severity events (secrets, massive copy sessions). Oldest low-severity events are dropped first when 50,000 event / 50MB cap is reached. `dropped_events_total` is reported in heartbeat. | Outbox SQLite database encrypted with DPAPI tied to machine credentials. |
| **Multiple Instances** | Single-instance named mutex (`Local\CyberSentinelAgentLock`) prevents concurrent instances from running. | Windows service single-instance enforcement. |
| **Password Manager Snooping** | Agent inspects clipboard formats for `"Clipboard Viewer Ignore"`, `"ExcludeClipboardContentFromMonitor"`, and password manager markers, skipping analysis completely. | Kernel-level isolation of password manager secure desktop. |

---

## 3. Clear Boundaries & Honest Claims
1. **Copying is not Pasting**: The agent detects sensitive text copied to the clipboard while a desktop AI application is focused. It does not monitor keystrokes or inject hooks into target processes.
2. **Destinations Only**: File system monitoring detects files written to removable drive roots. It cannot prove which source directory or network drive the files originated from.
3. **MTP Limitations**: Mobile phones connected via Media Transfer Protocol (MTP) do not expose standard Windows drive letters and are logged as MTP devices without deep file session tracking.
