"""
Agent Configuration and Credential Management (Section 6 G2 & G3)
Manages server URL, enrollment token storage in Windows Credential Manager (via keyring),
and dynamic server config synchronization.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import requests

try:
    import keyring
except ImportError:
    keyring = None

logger = logging.getLogger("cyber_sentinel_agent.config")

KEYRING_SERVICE_NAME = "CyberSentinelEndpointAgent"
KEYRING_USERNAME = "DeviceAuthToken"

DEFAULT_LOCAL_CONFIG = {
    "config_version": 1,
    "heartbeat_interval_sec": 60,
    "clipboard_max_bytes": 102400,
    "session_quiet_seconds": 15,
    "session_max_duration_seconds": 1800,
    "session_max_files": 100000,
    "sensitive_extensions": [
        ".pem", ".key", ".cer", ".crt", ".pfx", ".p12", ".kdbx",
        ".sql", ".dump", ".db", ".sqlite", ".bak",
        ".env", ".conf", ".cfg", ".ini",
        ".xlsx", ".xls", ".csv", ".tsv",
        ".doc", ".docx", ".pdf",
        ".zip", ".tar", ".gz", ".7z", ".rar", ".tgz"
    ],
    "archive_extensions": [
        ".zip", ".tar", ".gz", ".7z", ".rar", ".tgz", ".bz2", ".xz"
    ],
    "ai_apps": [
        {"label": "ChatGPT Desktop", "process_name": "chatgpt.exe"},
        {"label": "Claude Desktop", "process_name": "claude.exe"},
        {"label": "Cursor IDE", "process_name": "cursor.exe"},
        {"label": "Ollama CLI", "process_name": "ollama.exe"},
        {"label": "LM Studio", "process_name": "lm studio.exe"},
        {"label": "Copilot", "process_name": "copilot.exe"}
    ],
    "ai_keywords": [
        "chatgpt", "claude", "cursor", "perplexity", "copilot", "gemini",
        "deepseek", "poe", "anthropic", "openai", "huggingface"
    ],
    "burst_thresholds": {
        "file_count_high": 200,
        "total_bytes_high": 524288000,
        "sensitive_count_medium": 5
    },
    "watched_folders": []
}

class AgentConfig:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.env_file = base_dir / "agent.env"
        self.cache_file = base_dir / "agent_config_cache.json"

        # Load environment variables / agent.env
        self._load_env_file()

        self.server_url = os.getenv("AGENT_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
        self.enrollment_code = os.getenv("AGENT_ENROLLMENT_CODE", "AGENT-DEMO-ENROLL-2026")
        self.user_id = os.getenv("AGENT_USER_ID", "CNA0101")
        self.client_version = "1.0.0"

        # Cached server config
        self.active_config: Dict[str, Any] = self._load_cached_config()

    def _load_env_file(self):
        if self.env_file.exists():
            with open(self.env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())

    def _load_cached_config(self) -> Dict[str, Any]:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read config cache, using defaults: {e}")
        return dict(DEFAULT_LOCAL_CONFIG)

    def save_cached_config(self, config_data: Dict[str, Any]):
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2)
            self.active_config = config_data
            logger.info(f"Updated local config cache to version {config_data.get('config_version', 1)}")
        except Exception as e:
            logger.error(f"Failed to write config cache: {e}")

    # Credential management via Windows Credential Manager (G2)
    def get_token(self) -> Optional[str]:
        # First check environment override
        env_token = os.getenv("AGENT_DEVICE_TOKEN")
        if env_token:
            return env_token
        # Query Windows Credential Manager
        if keyring:
            try:
                token = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)
                if token:
                    return token
            except Exception as e:
                logger.warning(f"Keyring read error: {e}")
        # Local fallback token file (for testing/unsupported environments)
        token_file = self.base_dir / ".token"
        if token_file.exists():
            return token_file.read_text(encoding="utf-8").strip()
        return None

    def store_token(self, token: str):
        if keyring:
            try:
                keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME, token)
                logger.info("Stored device token in Windows Credential Manager.")
                return
            except Exception as e:
                logger.warning(f"Keyring write error, falling back to local protected file: {e}")
        # Local fallback
        token_file = self.base_dir / ".token"
        token_file.write_text(token, encoding="utf-8")

    def register_device_if_needed(self) -> bool:
        """
        Performs Section 5.3 Step G2 device registration against POST /api/v1/devices/register.
        """
        token = self.get_token()
        if token:
            logger.info("Device is already registered with a valid token.")
            return True

        import socket
        import platform
        import hashlib

        hostname = socket.gethostname()
        hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()
        os_version = f"{platform.system()} {platform.release()}"

        reg_payload = {
            "device_id": None, # Server generates UUID
            "user_id": self.user_id,
            "enrollment_code": self.enrollment_code,
            "device_kind": "agent",
            "hostname_hash": hostname_hash,
            "os_version": os_version,
            "client_version": self.client_version
        }

        try:
            resp = requests.post(f"{self.server_url}/api/v1/devices/register", json=reg_payload, timeout=5)
            if resp.status_code == 201:
                data = resp.json()
                new_token = data.get("token")
                if new_token:
                    self.store_token(new_token)
                    logger.info("Successfully registered agent device with backend.")
                    print(" [AGENT] Successfully registered device with server (Token secured in Windows Credential Manager).")
                    return True
            logger.error(f"Device registration failed with status {resp.status_code}: {resp.text}")
            return False
        except Exception as e:
            logger.error(f"Registration network error: {e}")
            return False

    def sync_server_config(self):
        """
        Polls GET /api/v1/config/agent?current=N (Section 6 G3).
        Rejects malformed config and keeps previous active config on disk.
        """
        token = self.get_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        current_v = self.active_config.get("config_version", 1)

        try:
            resp = requests.get(
                f"{self.server_url}/api/v1/config/agent?current={current_v}",
                headers=headers,
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "not_modified":
                    logger.debug("Server configuration is not modified.")
                    return
                new_cfg = data.get("config")
                new_v = data.get("version", current_v)
                if isinstance(new_cfg, dict) and "sensitive_extensions" in new_cfg:
                    new_cfg["config_version"] = new_v
                    self.save_cached_config(new_cfg)
                else:
                    logger.warning("Received malformed config from server, keeping active config.")
        except Exception as e:
            logger.debug(f"Config sync skipped (offline or server unreachable): {e}")
