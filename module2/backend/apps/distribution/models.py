from django.db import models

class ExtRulesetVersion(models.Model):
    """
    ext_ruleset_version (Section 5.1 & B6)
    Versioned regex rule sets for dynamic distribution.
    """
    version = models.IntegerField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=64, default="admin")
    content = models.JSONField(help_text="Full ruleset JSON definition")
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True, default="")

    class Meta:
        db_table = "ext_ruleset_version"

    def __str__(self):
        return f"Ruleset v{self.version} (Active: {self.is_active})"

class ExtModelVersion(models.Model):
    """
    ext_model_version (Section 5.1 & B7)
    Versioned logistic regression weights and thresholds.
    """
    version = models.IntegerField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    parent_version = models.IntegerField(null=True, blank=True)
    weights_json = models.JSONField(help_text="Weights, bias, means, stds")
    feature_names = models.JSONField(help_text="Ordered list of feature names")
    training_set_size = models.IntegerField(default=0)
    golden_set_metrics = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True, default="")

    class Meta:
        db_table = "ext_model_version"

    def __str__(self):
        return f"Model v{self.version} (Active: {self.is_active})"
