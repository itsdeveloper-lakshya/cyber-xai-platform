"""
Background Event Sender (Section 6 G4 & Section 2 #12)
Batches up to 100 events, POSTs to /api/v1/agent/events, uses exponential backoff with jitter,
and deletes rows from SQLite outbox ONLY upon server 202 Accepted.
"""

import time
import random
import threading
import logging
from typing import Optional
import requests

from .outbox import SQLiteOutbox
from .config import AgentConfig

logger = logging.getLogger("cyber_sentinel_agent.sender")

class EventSenderThread(threading.Thread):
    def __init__(self, outbox: SQLiteOutbox, config: AgentConfig, batch_size: int = 100):
        super().__init__(name="EventSenderThread", daemon=True)
        self.outbox = outbox
        self.config = config
        self.batch_size = batch_size
        self._stop_event = threading.Event()
        self._backoff = 1.0
        self.events_sent_total = 0

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("EventSenderThread started.")
        while not self._stop_event.is_set():
            try:
                batch = self.outbox.fetch_batch(self.batch_size)
                if not batch:
                    # Nothing to send, sleep briefly
                    self._stop_event.wait(1.0)
                    continue

                row_ids = [item[0] for item in batch]
                events = [item[1] for item in batch]

                token = self.config.get_token()
                if not token:
                    # Try to register device first
                    if not self.config.register_device_if_needed():
                        self._stop_event.wait(5.0)
                        continue
                    token = self.config.get_token()

                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                payload = {"events": events}

                url = f"{self.config.server_url}/api/v1/agent/events"
                resp = requests.post(url, json=payload, headers=headers, timeout=10)

                if resp.status_code == 202:
                    # Successfully accepted by backend
                    self.outbox.ack_batch(row_ids)
                    self.events_sent_total += len(events)
                    self._backoff = 1.0
                    logger.debug(f"Successfully transmitted and ACKed batch of {len(events)} events.")
                elif resp.status_code == 401:
                    logger.warning("Token unauthorized, re-registering device...")
                    self.config.register_device_if_needed()
                    self._backoff_sleep()
                else:
                    logger.warning(f"Server rejected batch with status {resp.status_code}: {resp.text}")
                    self._backoff_sleep()

            except requests.exceptions.RequestException as e:
                logger.debug(f"Network error transmitting events: {e}")
                self._backoff_sleep()
            except Exception as e:
                logger.error(f"Unexpected sender error: {e}")
                self._backoff_sleep()

        logger.info("EventSenderThread stopped.")

    def _backoff_sleep(self):
        jitter = random.uniform(0.5, 1.5)
        sleep_time = min(60.0, self._backoff * jitter)
        self._backoff = min(60.0, self._backoff * 2.0)
        self._stop_event.wait(sleep_time)
