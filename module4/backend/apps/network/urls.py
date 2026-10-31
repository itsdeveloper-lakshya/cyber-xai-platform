"""
Module 4 Network Forecasting URL Routes (Section 5.2)
"""

from django.urls import path
from .views import (
    NetworkForecastView,
    NetworkAlertsView,
    NetworkModelView,
    NetworkReplayView
)

urlpatterns = [
    path("forecast", NetworkForecastView.as_view(), name="network-forecast"),
    path("alerts", NetworkAlertsView.as_view(), name="network-alerts"),
    path("model", NetworkModelView.as_view(), name="network-model"),
    path("replay", NetworkReplayView.as_view(), name="network-replay"),
]
