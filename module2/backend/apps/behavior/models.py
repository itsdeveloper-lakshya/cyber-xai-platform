from django.db import models

class UserDailyActivity(models.Model):
    """
    Unmanaged Django model mapping Module 1's user_daily_activity table (Section 5.2).
    Django will NEVER alter, create, or drop this table.
    """
    row_id = models.BigIntegerField(primary_key=True)
    user_id = models.CharField(max_length=32)
    date = models.DateField()
    department = models.CharField(max_length=100)
    logon_count = models.IntegerField()
    after_hours_logons = models.IntegerField()
    distinct_pcs = models.IntegerField()
    usb_connects = models.IntegerField()
    after_hours_usb_connects = models.IntegerField()
    files_copied = models.IntegerField()
    emails_sent = models.IntegerField()
    external_emails = models.IntegerField()
    emails_with_attachments = models.IntegerField()
    websites_visited = models.IntegerField()
    is_malicious = models.SmallIntegerField()

    class Meta:
        managed = False
        db_table = "user_daily_activity"

    def __str__(self):
        return f"{self.user_id} on {self.date}"

class BehModelRegistry(models.Model):
    """
    beh_model_registry (Section 5.1 & 7.9)
    Registry of trained behavior XGBoost and baseline models.
    """
    model_version = models.IntegerField(primary_key=True)
    trained_at = models.DateTimeField(auto_now_add=True)
    algorithm = models.CharField(max_length=64, default="XGBoost")
    feature_list = models.JSONField(help_text="Ordered list of feature column names")
    train_date_range = models.JSONField(default=dict)
    metrics = models.JSONField(default=dict)
    file_reference = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "beh_model_registry"

class BehDailyScore(models.Model):
    """
    beh_daily_score (Section 5.1 & 7.9)
    Per-user, per-day anomaly probability from XGBoost.
    """
    user_id = models.CharField(max_length=32)
    date = models.DateField()
    model_version = models.IntegerField()
    probability = models.FloatField()
    rank_in_day = models.IntegerField()

    class Meta:
        db_table = "beh_daily_score"
        unique_together = ("user_id", "date", "model_version")
        indexes = [
            models.Index(fields=["date", "-probability"]),
            models.Index(fields=["user_id", "date"]),
        ]

class BehRuleFlag(models.Model):
    """
    beh_rule_flag (Section 5.1 & 7.7)
    Hard flags with plain-language reasons produced by the rule engine.
    """
    id = models.BigAutoField(primary_key=True)
    user_id = models.CharField(max_length=32)
    date = models.DateField()
    rule_id = models.CharField(max_length=32)
    severity = models.CharField(max_length=16, choices=[
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical")
    ])
    reason_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "beh_rule_flag"
        indexes = [
            models.Index(fields=["user_id", "date"]),
            models.Index(fields=["date"]),
        ]
