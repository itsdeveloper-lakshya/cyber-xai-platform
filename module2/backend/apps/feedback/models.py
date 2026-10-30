from django.db import models
from events.models import ExtPasteEvent

class ExtAnalystFeedback(models.Model):
    """
    ext_analyst_feedback (Section 5.1 & B7)
    Analyst feedback on flagged events (true_positive / false_positive)
    Used by the server-side retraining loop.
    """
    event = models.ForeignKey(ExtPasteEvent, on_delete=models.CASCADE, db_column="event_id")
    analyst_id = models.CharField(max_length=64)
    verdict = models.CharField(max_length=16, choices=[
        ("true_positive", "True Positive"),
        ("false_positive", "False Positive")
    ])
    comment = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ext_analyst_feedback"
        unique_together = ("event", "analyst_id")

    def __str__(self):
        return f"Feedback on {self.event_id} by {self.analyst_id}: {self.verdict}"
