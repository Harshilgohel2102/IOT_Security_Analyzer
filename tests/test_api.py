import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


def build_client():
    db_file = Path(tempfile.gettempdir()) / "iot_security_test.db"
    if db_file.exists():
        db_file.unlink()
    os.environ["IOT_DB_PATH"] = str(db_file)
    from server.app.main import app, init_db
    init_db()
    return TestClient(app)


def test_scan_pipeline_and_reports():
    client = build_client()
    payload = {
        "agent_name": "tester",
        "device_ip": "192.168.1.10",
        "open_ports": [23, 80, 445],
        "services": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "product": "BusyBox", "version": "1.0"},
            {"port": 80, "protocol": "tcp", "service": "http", "product": "Embedded Web", "version": "1.0"},
        ],
        "weak_credentials": ["Default admin password still suspected on exposed telnet console"],
        "config_issues": ["HTTP management exposed without HTTPS"],
        "threat_indicators": ["Legacy remote administration stack is externally reachable"],
        "traffic_profile": {
            "connections_per_minute": 260,
            "unique_remote_ips": 18,
            "failed_connections": 27,
            "dns_requests_per_minute": 95,
            "outbound_ratio": 0.92,
            "beaconing_score": 0.88,
            "unusual_ports_contacted": 6,
            "notes": "Synthetic high-risk telemetry for regression testing",
        },
    }
    response = client.post("/scan/report", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk"] in {"HIGH", "CRITICAL"}
    assert data["weak_credentials"]
    assert data["config_issues"]
    assert data["threat_indicators"]

    stats = client.get("/api/stats")
    assert stats.status_code == 200
    assert stats.json()["total_devices"] == 1
    assert stats.json()["weak_credential_devices"] == 1

    recent = client.get("/api/recent-scans")
    assert recent.status_code == 200
    recent_payload = recent.json()[0]
    assert recent_payload["traffic_profile"]["beaconing_score"] == 0.88

    pdf = client.get("/api/report.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")

    csv_report = client.get("/api/report.csv")
    assert csv_report.status_code == 200
    assert "text/csv" in csv_report.headers["content-type"]

    json_report = client.get("/api/report.json")
    assert json_report.status_code == 200
    report_body = json_report.json()
    assert report_body["scans"][0]["weak_credentials"]
