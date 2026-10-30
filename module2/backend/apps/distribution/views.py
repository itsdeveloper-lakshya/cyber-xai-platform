from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ExtRulesetVersion, ExtModelVersion

class ConfigRulesView(APIView):
    """
    GET /api/v1/config/rules?current=N (Section 5.3 & B6)
    Returns new rules JSON or 'not modified'.
    """
    def get(self, request):
        current_version = request.query_params.get("current")
        try:
            current_v = int(current_version) if current_version is not None else 0
        except ValueError:
            current_v = 0

        latest = ExtRulesetVersion.objects.filter(is_active=True).order_by("-version").first()
        if not latest or latest.version <= current_v:
            return Response({"status": "not_modified", "version": current_v}, status=status.HTTP_200_OK)

        return Response({
            "version": latest.version,
            "rules": latest.content,
            "created_at": latest.created_at
        }, status=status.HTTP_200_OK)

class ConfigModelView(APIView):
    """
    GET /api/v1/config/model?current=N (Section 5.3 & B6)
    Returns updated logistic regression weights JSON or 'not modified'.
    """
    def get(self, request):
        current_version = request.query_params.get("current")
        try:
            current_v = int(current_version) if current_version is not None else 0
        except ValueError:
            current_v = 0

        latest = ExtModelVersion.objects.filter(is_active=True).order_by("-version").first()
        if not latest or latest.version <= current_v:
            return Response({"status": "not_modified", "version": current_v}, status=status.HTTP_200_OK)

        return Response({
            "version": latest.version,
            "weights_json": latest.weights_json,
            "feature_names": latest.feature_names
        }, status=status.HTTP_200_OK)
