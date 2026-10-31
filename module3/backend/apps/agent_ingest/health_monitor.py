"""
Agent Server-Side Health Monitor (Section 11 Step H2 & Rule AG-10)
Periodically checks registered devices for:
1. Heartbeat gaps (> 3 heartbeat intervals without check-in)
2. Watcher failures (reported error status)
3. Clock skew (> 120s divergence)
4. Queue backlog (> 1000 events)
5. Rule AG-10: Agent silent for more than one working day (> 24 hours)
"""

from datetime import datetime, timedelta, timezone
import logging
from django.db import transaction
from devices.models import ExtDevice
from behavior.models import BehRuleFlag
from .models import AgtHeartbeat, AgtHealthAlert

logger = logging.getLogger("agent_health_monitor")

HEARTBEAT_GAP_THRESHOLD_SECONDS = 180  # 3 intervals of 60s
LONG_SILENT_THRESHOLD_HOURS = 24       # 1 working day

def check_devices_health(now_dt: datetime = None):
    if not now_dt:
        now_dt = datetime.now(timezone.utc)

    # Active agent devices
    devices = ExtDevice.objects.filter(device_kind="agent", is_active=True)

    for dev in devices:
        last_hb = AgtHeartbeat.objects.filter(device=dev).order_by("-received_at").first()

        if not last_hb:
            continue

        time_since_hb = (now_dt - last_hb.received_at).total_seconds()

        # 1. Heartbeat gap check
        if time_since_hb > HEARTBEAT_GAP_THRESHOLD_SECONDS:
            # Check if there is already an unresolved gap alert
            existing_gap = AgtHealthAlert.objects.filter(
                device=dev,
                alert_type="heartbeat_gap",
                resolved_at__isnull=True
            ).first()

            if not existing_gap:
                AgtHealthAlert.objects.create(
                    device=dev,
                    user_id=dev.user_id,
                    alert_type="heartbeat_gap",
                    severity="medium",
                    started_at=last_hb.received_at + timedelta(seconds=HEARTBEAT_GAP_THRESHOLD_SECONDS),
                    details={"seconds_silent": int(time_since_hb)}
                )
                logger.warning(f"Heartbeat gap alert opened for device {dev.device_id} ({dev.user_id})")

        # 2. Rule AG-10: Silent for > 1 working day (24 hours)
        if time_since_hb > (LONG_SILENT_THRESHOLD_HOURS * 3600):
            flag_exists = BehRuleFlag.objects.filter(
                user_id=dev.user_id,
                date=now_dt.date(),
                rule_id="AG-10"
            ).exists()

            if not flag_exists:
                BehRuleFlag.objects.create(
                    user_id=dev.user_id,
                    date=now_dt.date(),
                    rule_id="AG-10",
                    severity="medium",
                    source_module="agent",
                    mitre_technique="",
                    reason_text=f"Agent coverage lost: endpoint agent on {dev.device_id} silent for more than 24 hours ({int(time_since_hb / 3600)}h)."
                )
                logger.warning(f"Rule AG-10 triggered: device {dev.device_id} silent for >24h.")

        # 3. Watcher failure check
        watcher_statuses = last_hb.watcher_status or {}
        for watcher_name, status_str in watcher_statuses.items():
            if status_str != "ok":
                AgtHealthAlert.objects.get_or_create(
                    device=dev,
                    alert_type="watcher_failure",
                    resolved_at__isnull=True,
                    defaults={
                        "user_id": dev.user_id,
                        "severity": "high",
                        "started_at": last_hb.received_at,
                        "details": {"watcher": watcher_name, "status": status_str}
                    }
                )

        # 4. Clock skew check
        if abs(last_hb.clock_skew_seconds) > 120.0:
            AgtHealthAlert.objects.get_or_create(
                device=dev,
                alert_type="clock_skew",
                resolved_at__isnull=True,
                defaults={
                    "user_id": dev.user_id,
                    "severity": "medium",
                    "started_at": last_hb.received_at,
                    "details": {"skew_seconds": last_hb.clock_skew_seconds}
                }
            )

        # 5. Queue backlog check
        if last_hb.queue_depth > 1000:
            AgtHealthAlert.objects.get_or_create(
                device=dev,
                alert_type="queue_backlog",
                resolved_at__isnull=True,
                defaults={
                    "user_id": dev.user_id,
                    "severity": "low",
                    "started_at": last_hb.received_at,
                    "details": {"queue_depth": last_hb.queue_depth}
                }
            )
