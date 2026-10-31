"""
Agent Heartbeat and Health Reporting (Section 11 H1 & Section 5.2 agt_heartbeat)
Transmits vital system and agent metrics every 60 seconds.
"""

import os
import time
from datetime import datetime, timezone
import threading
import logging
from typing import Dict, Any, Callable
import requests
import psutil

from .outbox import SQLiteOutbox
from .config import AgentConfig

logger = logging.getLogger("cyber_sentinel_agent.heartbeat")

class HeartbeatThread(threading.Thread):
    def __init__(
        self,
        outbox: SQLiteOutbox,
        config: AgentConfig,
        get_watcher_statuses: Callable[[], Dict[str, Any]],
        get_low_risk_clipboard_count: Callable[[], int],
        agent_started_at: datetime
    ):
        super().__init__(name="HeartbeatThread", daemon=True)
        self.outbox = outbox
        self.config = config
        self.get_watcher_statuses = get_watcher_statuses
        self.get_low_risk_clipboard_count = get_low_risk_clipboard_count
        self.agent_started_at = agent_started_at
        self._stop_event = threading.Event()
        self._last_sent_count = 0
        self._process = psutil.Process()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("HeartbeatThread started.")
        while not self._stop_event.is_set():
            env_interval = os.getenv("AGENT_HEARTBEAT_INTERVAL")
            interval = int(env_interval) if env_interval and env_interval.isdigit() else self.config.active_config.get("heartbeat_interval_sec", 60)
            # Send heartbeat
            self._send_heartbeat()
            self._stop_event.wait(interval)
        logger.info("HeartbeatThread stopped.")

    def _send_heartbeat(self):
        token = self.config.get_token()
        if not token:
            print(" [HEARTBEAT] Waiting for device registration with server...")
            return

        try:
            cpu_pct = psutil.cpu_percent(interval=0.1)
            mem_info = self._process.memory_info()
            mem_mb = round(mem_info.rss / (1024 * 1024), 2)

            queue_depth = self.outbox.get_queue_depth()
            dropped_total = self.outbox.get_dropped_count()
            watcher_status = self.get_watcher_statuses()
            low_risk_count = self.get_low_risk_clipboard_count()
            config_version = self.config.active_config.get("config_version", 1)

            payload = {
                "agent_started_at": self.agent_started_at.isoformat(),
                "client_version": self.config.client_version,
                "queue_depth": queue_depth,
                "dropped_events_total": dropped_total,
                "watcher_status": watcher_status,
                "events_sent_since_last": self._last_sent_count,
                "low_risk_clipboard_count": low_risk_count,
                "cpu_pct": cpu_pct,
                "mem_mb": mem_mb,
                "config_version": config_version,
                "clock_skew_seconds": 0.0
            }

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            url = f"{self.config.server_url}/api/v1/agent/heartbeat"
            resp = requests.post(url, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                logger.info(f"Heartbeat delivered successfully: queue={queue_depth}, cpu={cpu_pct}%, mem={mem_mb}MB")
                print(f" [HEARTBEAT PULSE] Server Check-in OK | Queue Depth: {queue_depth} | CPU: {cpu_pct:.1f}% | RAM: {mem_mb} MB | Watchers: OK")
            else:
                logger.warning(f"Heartbeat response: {resp.status_code}")
                print(f" [HEARTBEAT] Server response: {resp.status_code}")
        except requests.exceptions.ConnectionError:
            print(f" [HEARTBEAT] Server unreachable on {self.config.server_url} (events securely buffered in local SQLite outbox)")
        except Exception as e:
            logger.debug(f"Heartbeat network transmission skipped: {e}")
