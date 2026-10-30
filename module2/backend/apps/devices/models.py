import uuid
from django.db import models

class ExtDevice(models.Model):
    """
    ext_device (Section 5.1)
    Stores registered browser extension devices.
    """
    device_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=32, db_index=True, help_text="CERT-style employee ID")
    token_hash = models.CharField(max_length=64, help_text="SHA-256 hash of device token")
    registered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    extension_version = models.CharField(max_length=20, default="1.0.0")
    is_active = models.BooleanField(default=True, help_text="Allows revoking a compromised device")

    class Meta:
        db_table = "ext_device"

    def __str__(self):
        return f"Device {self.device_id} ({self.user_id})"
