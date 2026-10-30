import json
import hashlib
from datetime import datetime, timezone
import redis
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from devices.models import ExtDevice

STREAM_NAME = "paste_events"

class IngestEventView(APIView):
    """
    POST /api/v1/events (Section 5.3 & B3)
    High-throughput event ingestion endpoint.
    Validates token, validates size & schema, publishes to Redis Stream 'paste_events'.
    Returns 202 Accepted immediately.
    """
    def post(self, request):
        # 1. Device Token Authentication
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return Response({"error": "Missing or invalid Authorization header."}, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(" ")[1]
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

        try:
            device = ExtDevice.objects.get(token_hash=token_hash, is_active=True)
        except ExtDevice.DoesNotExist:
            return Response({"error": "Invalid or inactive device token."}, status=status.HTTP_401_UNAUTHORIZED)

        # 2. Payload Validation & Sanitization
        payload = request.data
        required_fields = ["event_id", "event_type", "site_domain", "risk_tier", "final_score"]
        for field in required_fields:
            if field not in payload:
                return Response({"error": f"Missing required field: {field}"}, status=status.HTTP_400_BAD_REQUEST)

        # Enforce max body size check
        if len(json.dumps(payload)) > 65536:
            return Response({"error": "Payload exceeds maximum allowed size."}, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        payload["device_id"] = str(device.device_id)
        if not payload.get("user_id"):
            payload["user_id"] = device.user_id

        # 3. Publish to Redis Stream or Fallback Direct Write (during tests when Redis is down)
        try:
            r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1)
            r.ping()
            r.xadd(STREAM_NAME, {"data": json.dumps(payload)})
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            # Graceful test/offline fallback: direct DB save
            from .models import ExtPasteEvent
            occurred_at_val = payload.get("occurred_at")
            if not occurred_at_val:
                occurred_at_val = datetime.now(timezone.utc)

            ExtPasteEvent.objects.create(
                event_id=payload["event_id"],
                device=device,
                user_id=payload["user_id"],
                occurred_at=occurred_at_val,
                site_domain=payload["site_domain"],
                event_type=payload["event_type"],
                content_length=payload.get("content_length", 0),
                line_count=payload.get("line_count", 0),
                file_extension=payload.get("file_extension"),
                matched_categories=payload.get("matched_categories", []),
                regex_score=payload.get("regex_score", 0.0),
                ml_score=payload.get("ml_score", 0.0),
                final_score=payload.get("final_score", 0.0),
                risk_tier=payload["risk_tier"],
                action=payload.get("action", "logged"),
                override_used=payload.get("override_used", False),
                override_reason=payload.get("override_reason"),
            )
        except Exception as e:
            return Response({"error": f"Queue error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"status": "accepted", "event_id": payload["event_id"]}, status=status.HTTP_202_ACCEPTED)
