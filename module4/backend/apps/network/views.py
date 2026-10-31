"""
Module 4 Network Forecasting REST APIs (Section 5.2 Frozen API Contract)
Endpoints:
1. GET  /api/v1/network/forecast?replay_run_id=...&from=...&to=...
2. GET  /api/v1/network/alerts?replay_run_id=...&min_level=...
3. GET  /api/v1/network/model
4. POST /api/v1/network/replay
"""

import json
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import connection

class NetworkForecastView(APIView):
    """
    GET /api/v1/network/forecast?replay_run_id=X&from=Y&to=Z
    Returns forecast series with 4-level alerts for the analyst dashboard.
    """
    def get(self, request):
        replay_run_id = request.query_params.get("replay_run_id")
        from_ts = request.query_params.get("from")
        to_ts = request.query_params.get("to")
        limit = min(int(request.query_params.get("limit", 100)), 500)

        query = """
        SELECT replay_run_id, model_version, window_end, raw_score, calibrated_prob,
               level, level_reason, horizon_k, actual_surge_in_horizon
        FROM net_forecast
        WHERE 1=1
        """
        params = []
        if replay_run_id:
            query += " AND replay_run_id = %s"
            params.append(replay_run_id)
        if from_ts:
            query += " AND window_end >= %s"
            params.append(from_ts)
        if to_ts:
            query += " AND window_end <= %s"
            params.append(to_ts)

        query += " ORDER BY window_end ASC LIMIT %s;"
        params.append(limit)

        with connection.cursor() as cur:
            cur.execute(query, params)
            cols = [col[0] for col in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]

        return Response({
            "count": len(rows),
            "results": rows
        }, status=status.HTTP_200_OK)

class NetworkAlertsView(APIView):
    """
    GET /api/v1/network/alerts?replay_run_id=X&min_level=2
    Returns alert episodes aggregated during the replay.
    """
    def get(self, request):
        replay_run_id = request.query_params.get("replay_run_id")
        min_level = int(request.query_params.get("min_level", 1))

        query = """
        SELECT episode_id, replay_run_id, model_version, max_level,
               start_window, end_window, peak_prob, status, matched_surge_episode_id
        FROM net_alert_episode
        WHERE max_level >= %s
        """
        params = [min_level]
        if replay_run_id:
            query += " AND replay_run_id = %s"
            params.append(replay_run_id)

        query += " ORDER BY start_window ASC;"

        with connection.cursor() as cur:
            cur.execute(query, params)
            cols = [col[0] for col in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]

        return Response({
            "count": len(rows),
            "episodes": rows
        }, status=status.HTTP_200_OK)

class NetworkModelView(APIView):
    """
    GET /api/v1/network/model
    Returns active model version, calibration coefficients, and alert thresholds.
    """
    def get(self, request):
        query = """
        SELECT model_version, run_id, model_type, file_ref,
               window_size_sec, horizon_k, calibrator, thresholds, hysteresis, created_at
        FROM net_model_registry
        WHERE is_active = TRUE
        ORDER BY created_at DESC LIMIT 1;
        """
        with connection.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
            if not row:
                return Response({"error": "No active network forecasting model found."}, status=status.HTTP_404_NOT_FOUND)
            cols = [col[0] for col in cur.description]
            data = dict(zip(cols, row))

        return Response(data, status=status.HTTP_200_OK)

class NetworkReplayView(APIView):
    """
    POST /api/v1/network/replay
    Triggers or controls a simulated replay run.
    Payload: { replay_run_id, speed_multiplier }
    """
    def post(self, request):
        replay_run_id = request.data.get("replay_run_id", f"REP_API_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        speed_multiplier = float(request.data.get("speed_multiplier", 1.0))

        # Check if forecasts already exist for this run ID
        with connection.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM net_forecast WHERE replay_run_id = %s;", [replay_run_id])
            existing = cur.fetchone()[0]

        return Response({
            "status": "initiated" if existing == 0 else "already_running",
            "replay_run_id": replay_run_id,
            "speed_multiplier": speed_multiplier,
            "existing_windows": existing
        }, status=status.HTTP_202_ACCEPTED)
