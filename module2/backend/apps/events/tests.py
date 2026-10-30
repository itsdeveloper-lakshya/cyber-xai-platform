import uuid
import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from devices.models import ExtDevice

@pytest.mark.django_db
class TestModule2PartA:
    def setup_method(self):
        self.client = APIClient()

    def test_device_registration_and_auth(self):
        """Tests POST /api/v1/devices/register (Section 5.3)"""
        url = reverse("device-register")
        resp = self.client.post(url, {
            "enrollment_code": "CYBER-ENROLL-DEV-2026",
            "user_id": "AAM0658",
            "extension_version": "1.0.0"
        }, format="json")

        assert resp.status_code == 201
        data = resp.json()
        assert "token" in data
        assert "device_id" in data
        assert data["user_id"] == "AAM0658"

        # Verify device in DB
        device = ExtDevice.objects.get(device_id=data["device_id"])
        assert device.is_active is True
        assert device.user_id == "AAM0658"

    def test_ingestion_api_validation(self):
        """Tests POST /api/v1/events with token auth and validation (Section B3 & B-04)"""
        # 1. Register device
        reg_resp = self.client.post(reverse("device-register"), {
            "enrollment_code": "CYBER-ENROLL-DEV-2026",
            "user_id": "AAM0658"
        }, format="json")
        token = reg_resp.json()["token"]

        # 2. Ingest valid high-risk event
        event_id = str(uuid.uuid4())
        event_payload = {
            "event_id": event_id,
            "site_domain": "chatgpt.com",
            "event_type": "paste",
            "content_length": 150,
            "line_count": 5,
            "matched_categories": ["PrivateKey"],
            "regex_score": 1.0,
            "ml_score": 0.95,
            "final_score": 0.98,
            "risk_tier": "high",
            "action": "blocked",
            "override_used": True,
            "override_reason": "Testing sanitization"
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        ingest_resp = self.client.post(reverse("event-ingest"), event_payload, format="json")
        assert ingest_resp.status_code == 202
        assert ingest_resp.json()["status"] == "accepted"

        # 3. Test unauthorized request
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalid-token-xyz")
        unauth_resp = self.client.post(reverse("event-ingest"), event_payload, format="json")
        assert unauth_resp.status_code == 401

        # 4. Test missing required fields
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        bad_resp = self.client.post(reverse("event-ingest"), {"bad_field": 123}, format="json")
        assert bad_resp.status_code == 400
