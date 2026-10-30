from django.contrib import admin
from django.urls import path
from devices.views import RegisterDeviceView
from events.views import IngestEventView
from distribution.views import ConfigRulesView, ConfigModelView

urlpatterns = [
    path('admin/', admin.site.urls),

    # Module 2 API Endpoints (Section 5.3)
    path('api/v1/devices/register', RegisterDeviceView.as_view(), name='device-register'),
    path('api/v1/events', IngestEventView.as_view(), name='event-ingest'),
    path('api/v1/config/rules', ConfigRulesView.as_view(), name='config-rules'),
    path('api/v1/config/model', ConfigModelView.as_view(), name='config-model'),
]
