"""
Services Module
===============
Contains the business logic / service layer for the IoT Security
Platform. This layer sits between the API routes and the data
access layer, implementing scan processing, risk aggregation,
and device management logic.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional


class ScanService:
    """
    Service class encapsulating all scan-related business logic:
    - Processing incoming scan data
    - Combining ML predictions with rule-based assessments
    - Querying and aggregating scan results
    """

    def __init__(self, get_conn_fn, model, ensure_schema_fn):
        self._get_conn = get_conn_fn
        self._model = model
        self._ensure_schema = ensure_schema_fn

    def process_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single scan report: run ML prediction, combine
        with rule-based assessment, store in database, and return
        the full assessment result.
        """
        from ..ml_engine import combine_assessment

        ml_output = self._model.predict(scan_data)
        assessment = combine_assessment(scan_data, ml_output)

        with closing(self._get_conn()) as conn:
            self._ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO scans(
                    agent_name, device_ip, hostname, vendor, os_guess,
                    open_ports, services, raw_nmap_xml, risk, risk_score,
                    ml_label, ml_confidence, anomaly_score, issues,
                    weak_credentials, config_issues, threat_indicators,
                    traffic_profile, label_probabilities, features, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_data.get("agent_name", ""),
                    scan_data.get("device_ip", ""),
                    scan_data.get("hostname"),
                    scan_data.get("vendor"),
                    scan_data.get("os_guess"),
                    json.dumps(sorted(set(scan_data.get("open_ports", [])))),
                    json.dumps(scan_data.get("services", [])),
                    scan_data.get("raw_nmap_xml"),
                    assessment["risk"],
                    assessment["risk_score"],
                    assessment["ml_label"],
                    assessment["ml_confidence"],
                    assessment["anomaly_score"],
                    json.dumps(assessment["issues"]),
                    json.dumps(assessment["weak_credentials"]),
                    json.dumps(assessment["config_issues"]),
                    json.dumps(assessment["threat_indicators"]),
                    json.dumps(assessment["traffic_profile"]) if assessment["traffic_profile"] else None,
                    json.dumps(assessment["label_probabilities"]),
                    json.dumps(assessment["features"]),
                    scan_data.get("timestamp", datetime.now(UTC).isoformat()),
                ),
            )
            conn.commit()

        return assessment

    def get_risk_summary(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute aggregate risk metrics across a set of scans.
        """
        if not scans:
            return {
                "total_devices": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "avg_risk_score": 0.0,
                "weak_credential_devices": 0,
                "config_issue_devices": 0,
                "threat_indicator_devices": 0,
            }

        return {
            "total_devices": len(scans),
            "critical": sum(1 for s in scans if s["risk"] == "CRITICAL"),
            "high": sum(1 for s in scans if s["risk"] == "HIGH"),
            "medium": sum(1 for s in scans if s["risk"] == "MEDIUM"),
            "low": sum(1 for s in scans if s["risk"] == "LOW"),
            "avg_risk_score": round(sum(s["risk_score"] for s in scans) / len(scans), 2),
            "weak_credential_devices": sum(1 for s in scans if s.get("weak_credentials")),
            "config_issue_devices": sum(1 for s in scans if s.get("config_issues")),
            "threat_indicator_devices": sum(1 for s in scans if s.get("threat_indicators")),
        }

    def get_device_history(self, device_ip: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieve scan history for a specific device.
        """
        with closing(self._get_conn()) as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE device_ip = ? ORDER BY datetime(timestamp) DESC LIMIT ?",
                (device_ip, limit),
            ).fetchall()
        return [self._decode_scan(row) for row in rows]

    @staticmethod
    def _decode_scan(row: sqlite3.Row) -> Dict[str, Any]:
        """Decode a database row into a scan dictionary."""

        def _json_load(value, default):
            if value in (None, ""):
                return default
            try:
                return json.loads(value)
            except Exception:
                return default

        return {
            "id": row["id"],
            "agent_name": row["agent_name"],
            "device_ip": row["device_ip"],
            "hostname": row["hostname"] or "",
            "vendor": row["vendor"] or "",
            "os_guess": row["os_guess"] or "",
            "open_ports": _json_load(row["open_ports"], []),
            "services": _json_load(row["services"], []),
            "risk": row["risk"],
            "risk_score": row["risk_score"],
            "ml_label": row["ml_label"],
            "ml_confidence": row["ml_confidence"],
            "anomaly_score": row["anomaly_score"],
            "issues": _json_load(row["issues"], []),
            "weak_credentials": _json_load(row["weak_credentials"], []),
            "config_issues": _json_load(row["config_issues"], []),
            "threat_indicators": _json_load(row["threat_indicators"], []),
            "traffic_profile": _json_load(row["traffic_profile"], None),
            "label_probabilities": _json_load(row["label_probabilities"], {}),
            "features": _json_load(row["features"], {}),
            "timestamp": row["timestamp"],
        }
