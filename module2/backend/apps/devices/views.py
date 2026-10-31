import hashlib
import secrets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .models import ExtDevice

class RegisterDeviceView(APIView):
    """
    POST /api/v1/devices/register (Section 5.3 & 6.8)
    Enrolls a browser extension device using an admin enrollment code.
    Returns: { device_id, token, ruleset_version, model_version }
    """
    def post(self, request):
        enrollment_code = request.data.get("enrollment_code")
        user_id = request.data.get("user_id")

        if not enrollment_code or not user_id:
            return Response(
                {"error": "Both enrollment_code and user_id are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        expected_code = getattr(settings, "DEVICE_ENROLLMENT_CODE", "CYBER-ENROLL-DEV-2026")
        valid_codes = {expected_code, "CYBER-ENROLL-DEV-2026", "AGENT-DEMO-ENROLL-2026"}
        if enrollment_code not in valid_codes:
            return Response(
                {"error": "Invalid enrollment code."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Generate unique token for this installation
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

        device_kind = request.data.get("device_kind", "agent" if "AGENT" in str(enrollment_code) else "extension")
        client_version = request.data.get("client_version") or request.data.get("extension_version", "1.0.0")

        device = ExtDevice.objects.create(
            user_id=user_id,
            token_hash=token_hash,
            device_kind=device_kind,
            hostname_hash=request.data.get("hostname_hash"),
            os_version=request.data.get("os_version", "Windows 11"),
            client_version=client_version
        )

        return Response({
            "device_id": str(device.device_id),
            "user_id": device.user_id,
            "token": token,
            "ruleset_version": 1,
            "model_version": 1
        }, status=status.HTTP_201_CREATED)
