# Module 3: Privacy & Data Minimization Architecture

## 1. Core Privacy Tenets

The Cyber Sentinel Endpoint Agent is designed strictly around the principle of **Data Minimization** as mandated by corporate compliance standards (GDPR Article 5(1)(c) and ISO 27701).

### What the Agent NEVER Collects:
1. **Zero File Names**: File copy sessions record extension histograms (e.g., `{"docx": 3, "xlsx": 5}`) and byte counts. File names, folder names, and directory paths are **never** stored or transmitted.
2. **Zero File Contents**: No file contents or documents are ever read, inspected, or transmitted.
3. **Zero Clipboard Text**: The agent performs **local on-device scoring** using regex rules and a tiny 18-feature logistic regression model. Only the resulting risk score, risk tier, and matched rule category IDs (e.g. `CloudAccessKey`) are sent to the server.
4. **Zero Window Titles**: Active foreground window titles are analyzed locally against a configured AI keyword list. If a match occurs, only the configured keyword name (e.g., `ChatGPT`) is recorded. The actual window title is discarded immediately.
5. **Zero Keystrokes or Screenshots**: Keystroke logging and screen capturing are strictly out of scope by design.

---

## 2. Password Manager Protection
Password managers (such as 1Password, Bitwarden, KeePass) set specialized Windows clipboard format markers when copying credentials:
- `Clipboard Viewer Ignore`
- `ExcludeClipboardContentFromMonitor`
- `CanIncludeInClipboardHistory`

The clipboard watcher queries clipboard formats before examining any payload. If any exclusion format is present, the clipboard update is skipped completely.

---

## 3. Transparency & Employee Notification
The agent provides visual indicators to the employee via a system tray icon. The employee can click "Privacy & Transparency Policy" at any time to verify exactly what metrics are monitored and what data is excluded.
