"""
API Route Handlers
==================
Defines the FastAPI APIRouter with all REST endpoints for the
IoT Security Platform. These routes are included in the main
FastAPI application and provide endpoints for agent registration,
scan data submission, statistics, reporting, and device queries.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

router = APIRouter()


def get_routes(
    model,
    get_conn,
    get_stats_fn,
    get_latest_scans_per_device_fn,
    get_recent_scans_fn,
    get_device_latest_fn,
    get_scan_count_fn,
    format_time_label_fn,
    ensure_scan_schema_fn,
    create_csv_report_fn,
    create_json_report_fn,
    create_pdf_report_fn,
    utc_now_fn,
):
    """
    Factory function that creates and returns an APIRouter configured
    with all the platform's REST endpoints.

    This pattern allows routes to reference shared dependencies
    (model, DB, helpers) without circular imports.
    """

    from contextlib import closing
    from datetime import UTC, datetime
    import json
    from ..main import AgentRegister, ScanResult, combine_assessment

    api = APIRouter()

    @api.post("/agent/register")
    def register_agent(agent: AgentRegister) -> dict[str, str]:
        with closing(get_conn()) as conn:
            conn.execute(
                "INSERT INTO agents(name, ip, created_at) VALUES (?, ?, ?)",
                (agent.name, agent.ip, utc_now_fn()),
            )
            conn.commit()
        return {"message": "Agent registered successfully"}

    @api.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "model_metrics": model.metrics,
        }

    @api.get("/api/stats")
    def stats() -> dict[str, Any]:
        return get_stats_fn()

    @api.get("/api/recent-scans")
    def recent_scans() -> list[dict[str, Any]]:
        return get_recent_scans_fn(limit=12)

    @api.get("/api/device/{ip}")
    def get_device(ip: str) -> dict[str, Any]:
        scan = get_device_latest_fn(ip)
        if not scan:
            raise HTTPException(status_code=404, detail="Device not found")
        return scan

    @api.get("/api/report.csv")
    def report_csv() -> Response:
        scans = get_latest_scans_per_device_fn()
        content = create_csv_report_fn(scans)
        headers = {"Content-Disposition": 'attachment; filename="iot-security-report.csv"'}
        return Response(content=content, media_type="text/csv", headers=headers)

    @api.get("/api/report.json")
    def report_json() -> Response:
        scans = get_latest_scans_per_device_fn()
        content = create_json_report_fn(scans, get_stats_fn())
        headers = {"Content-Disposition": 'attachment; filename="iot-security-report.json"'}
        return Response(content=content, media_type="application/json", headers=headers)

    @api.get("/api/report.pdf")
    def report_pdf() -> StreamingResponse:
        scans = get_latest_scans_per_device_fn()
        pdf_bytes = create_pdf_report_fn(scans, get_stats_fn())
        headers = {"Content-Disposition": 'attachment; filename="iot-security-report.pdf"'}
        return StreamingResponse(iter([pdf_bytes]), media_type="application/pdf", headers=headers)

    @api.get("/api/model-info")
    def model_info() -> dict[str, Any]:
        return model.metrics

    return api
