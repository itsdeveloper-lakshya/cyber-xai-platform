import uuid
from django.db import models

class ExtDevice(models.Model):
    """
    ext_device (Module 2 Section 5.1 & Module 3 Section 5.1 Amendment)
    Stores registered devices (both Browser Extensions and Windows Endpoint Agents).
    """
    device_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=32, db_index=True, help_text="CERT-style employee ID")
    token_hash = models.CharField(max_length=64, help_text="SHA-256 hash of device token")
    registered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    device_kind = models.CharField(max_length=12, default="extension", choices=[
        ("extension", "Browser Extension"),
        ("agent", "Windows Endpoint Agent")
    ])
    hostname_hash = models.CharField(max_length=64, null=True, blank=True)
    os_version = models.CharField(max_length=40, default="Windows 11")
    client_version = models.CharField(max_length=20, default="1.0.0")
    is_active = models.BooleanField(default=True, help_text="Allows revoking a compromised device")

    class Meta:
        db_table = "ext_device"

    def __str__(self):
        return f"{self.device_kind.title()} {self.device_id} ({self.user_id})"
