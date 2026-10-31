"""
Agent Daily Aggregation (Section 12 Step K4 & Section 5.2 agt_daily_agg)
Rolls up per-user daily agent activity features for Module 7 unified scoring.
"""

from datetime import date, datetime, time, timezone
import logging
from django.db.models import Sum, Count
from .models import (
    AgtUsbEvent, AgtFileTransferEvent, AgtClipboardEvent,
    AgtAppSession, AgtHeartbeat, AgtHealthAlert, AgtDailyAgg
)

logger = logging.getLogger("agent_daily_agg")

def aggregate_user_daily_activity(target_date: date):
    """
    Computes and upserts daily summary rows in agt_daily_agg for all users active on target_date.
    """
    start_dt = datetime.combine(target_date, time.min, tzinfo=timezone.utc)
    end_dt = datetime.combine(target_date, time.max, tzinfo=timezone.utc)

    # Find all distinct users active in any event table on target_date
    users = set()
    users.update(AgtUsbEvent.objects.filter(occurred_at__date=target_date).values_list("user_id", flat=True))
    users.update(AgtFileTransferEvent.objects.filter(session_start__date=target_date).values_list("user_id", flat=True))
    users.update(AgtClipboardEvent.objects.filter(occurred_at__date=target_date).values_list("user_id", flat=True))
    users.update(AgtAppSession.objects.filter(started_at__date=target_date).values_list("user_id", flat=True))
    users.update(AgtHeartbeat.objects.filter(received_at__date=target_date).values_list("device__user_id", flat=True))

    for user_id in users:
        if not user_id:
            continue

        # USB connects
        usb_qs = AgtUsbEvent.objects.filter(user_id=user_id, occurred_at__date=target_date, event_type="connect")
        usb_connects = usb_qs.count()
        after_hours_usb = usb_qs.filter(is_after_hours=True).count()
        distinct_usb = usb_qs.values("volume_serial_hash").distinct().count()

        # File transfers
        ft_qs = AgtFileTransferEvent.objects.filter(user_id=user_id, session_start__date=target_date)
        ft_agg = ft_qs.aggregate(
            files=Sum("file_count"),
            bytes=Sum("total_bytes"),
            sens=Sum("sensitive_ext_count")
        )
        files_copied = ft_agg["files"] or 0
        bytes_copied = ft_agg["bytes"] or 0
        sens_files = ft_agg["sens"] or 0

        # Clipboard
        cb_qs = AgtClipboardEvent.objects.filter(user_id=user_id, occurred_at__date=target_date)
        cb_medium = cb_qs.filter(risk_tier="medium").count()
        cb_high = cb_qs.filter(risk_tier="high").count()
        cb_ai = cb_qs.filter(ai_context=True).count()

        # AI App Focus
        app_qs = AgtAppSession.objects.filter(user_id=user_id, started_at__date=target_date)
        total_focus_sec = app_qs.aggregate(sec=Sum("focus_seconds"))["sec"] or 0
        ai_focus_minutes = int(total_focus_sec / 60)

        # Heartbeats & online minutes
        hb_count = AgtHeartbeat.objects.filter(device__user_id=user_id, received_at__date=target_date).count()
        online_minutes = hb_count  # 1 heartbeat per minute approximately

        # Gaps
        gap_count = AgtHealthAlert.objects.filter(
            user_id=user_id,
            alert_type="heartbeat_gap",
            started_at__date=target_date
        ).count()

        AgtDailyAgg.objects.update_or_create(
            user_id=user_id,
            date=target_date,
            defaults={
                "usb_connects": usb_connects,
                "after_hours_usb_connects": after_hours_usb,
                "distinct_usb_devices": distinct_usb,
                "files_copied_to_usb": files_copied,
                "bytes_copied_to_usb": bytes_copied,
                "sensitive_ext_files_to_usb": sens_files,
                "clipboard_medium_count": cb_medium,
                "clipboard_high_count": cb_high,
                "ai_context_clipboard_count": cb_ai,
                "ai_app_focus_minutes": ai_focus_minutes,
                "agent_online_minutes": online_minutes,
                "agent_gap_count": gap_count
            }
        )
        logger.info(f"Aggregated daily stats for user {user_id} on {target_date}: {files_copied} files, {bytes_copied} bytes.")
