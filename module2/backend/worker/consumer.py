"""
Redis Stream Consumer Worker (Section 6.9 Step B4)
Reads events from Redis stream 'paste_events' using a consumer group.
Persists events into PostgreSQL and issues XACK only after commit.
Includes dead-letter stream handling for poison messages.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
import redis

# Setup Django standalone environment
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / 'apps'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django
django.setup()

from django.db import transaction
from django.conf import settings
from events.models import ExtPasteEvent, ExtDailyPasteAgg
from devices.models import ExtDevice

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("worker")

STREAM_NAME = "paste_events"
GROUP_NAME = "paste_consumers"
DEAD_LETTER_STREAM = "paste_events_dead_letter"
CONSUMER_NAME = f"consumer_{os.getpid()}"

def init_stream(r):
    try:
        r.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
        logger.info(f"Consumer group '{GROUP_NAME}' created on stream '{STREAM_NAME}'.")
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" in str(e):
            pass # Group already exists
        else:
            raise

def process_event(event_dict):
    device_id = event_dict.get("device_id")
    device = None
    if device_id:
        device = ExtDevice.objects.filter(device_id=device_id).first()

    with transaction.atomic():
        # Idempotent insert
        event, created = ExtPasteEvent.objects.get_or_create(
            event_id=event_dict["event_id"],
            defaults={
                "device": device,
                "user_id": event_dict.get("user_id", "UNKNOWN"),
                "occurred_at": event_dict.get("occurred_at"),
                "site_domain": event_dict.get("site_domain", "unknown"),
                "event_type": event_dict.get("event_type", "paste"),
                "content_length": event_dict.get("content_length", 0),
                "line_count": event_dict.get("line_count", 0),
                "file_extension": event_dict.get("file_extension"),
                "matched_categories": event_dict.get("matched_categories", []),
                "regex_score": event_dict.get("regex_score", 0.0),
                "ml_score": event_dict.get("ml_score", 0.0),
                "final_score": event_dict.get("final_score", 0.0),
                "risk_tier": event_dict.get("risk_tier", "low"),
                "action": event_dict.get("action", "logged"),
                "override_used": event_dict.get("override_used", False),
                "override_reason": event_dict.get("override_reason"),
            }
        )

        # Update daily aggregate
        if created and event.occurred_at:
            event_date = event.occurred_at.date()
            agg, _ = ExtDailyPasteAgg.objects.get_or_create(
                user_id=event.user_id,
                date=event_date
            )
            if event.event_type == "paste":
                agg.paste_count += 1
            else:
                agg.upload_count += 1

            if event.risk_tier == "medium":
                agg.medium_count += 1
            elif event.risk_tier == "high":
                agg.high_count += 1

            if event.action == "blocked":
                agg.blocked_count += 1
            if event.override_used:
                agg.override_count += 1
            agg.save()

    return created

def run_worker():
    r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    logger.info(f"Connecting to Redis at {settings.REDIS_URL}...")
    init_stream(r)

    logger.info(f"Worker '{CONSUMER_NAME}' listening for stream messages...")
    while True:
        try:
            # Read new messages from group
            messages = r.xreadgroup(GROUP_NAME, CONSUMER_NAME, {STREAM_NAME: ">"}, count=10, block=2000)
            if not messages:
                continue

            for stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        raw_payload = data.get("data")
                        event_dict = json.loads(raw_payload)
                        created = process_event(event_dict)
                        # Acknowledge message only AFTER successful DB commit
                        r.xack(STREAM_NAME, GROUP_NAME, msg_id)
                        logger.info(f"Processed event {event_dict.get('event_id')} (Created: {created}) - ACK {msg_id}")
                    except Exception as err:
                        logger.error(f"Error processing message {msg_id}: {err}. Moving to dead-letter stream.")
                        r.xadd(DEAD_LETTER_STREAM, {"error": str(err), "data": data.get("data", "")})
                        r.xack(STREAM_NAME, GROUP_NAME, msg_id)

            # Periodically trim stream length to prevent memory leaks (Section B4)
            r.xtrim(STREAM_NAME, maxlen=100000, approximate=True)

        except redis.exceptions.ConnectionError:
            logger.warning("Redis connection lost. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected worker error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    run_worker()
