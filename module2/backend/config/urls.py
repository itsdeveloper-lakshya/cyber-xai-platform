from django.contrib import admin
from django.urls import path, include
from devices.views import RegisterDeviceView
from events.views import IngestEventView
from distribution.views import ConfigRulesView, ConfigModelView
from agent_ingest.views import (
    AgentEventsIngestView, AgentHeartbeatView, AgentConfigView,
    AgentUsbListView, AgentTransfersListView, AgentClipboardListView, AgentHealthListView
)

urlpatterns = [
    path('admin/', admin.site.urls),

    # Module 2 API Endpoints
    path('api/v1/devices/register', RegisterDeviceView.as_view(), name='device-register'),
    path('api/v1/events', IngestEventView.as_view(), name='event-ingest'),
    path('api/v1/config/rules', ConfigRulesView.as_view(), name='config-rules'),
    path('api/v1/config/model', ConfigModelView.as_view(), name='config-model'),

    # Module 3 Agent Endpoints (Section 5.3)
    path('api/v1/agent/events', AgentEventsIngestView.as_view(), name='agent-events-ingest'),
    path('api/v1/agent/heartbeat', AgentHeartbeatView.as_view(), name='agent-heartbeat'),
    path('api/v1/config/agent', AgentConfigView.as_view(), name='agent-config'),
    path('api/v1/agent/usb', AgentUsbListView.as_view(), name='agent-usb-list'),
    path('api/v1/agent/transfers', AgentTransfersListView.as_view(), name='agent-transfers-list'),
    path('api/v1/agent/clipboard', AgentClipboardListView.as_view(), name='agent-clipboard-list'),
    path('api/v1/agent/health', AgentHealthListView.as_view(), name='agent-health-list'),

    # Module 4 Network Forecasting Endpoints (Section 5.2)
    path('api/v1/network/', include('network.urls')),
]
