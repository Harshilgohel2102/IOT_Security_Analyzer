from pathlib import Path

from server.app.ml_engine import RiskModel, combine_assessment


def test_risk_model_detects_critical_pattern(tmp_path: Path):
    model = RiskModel(tmp_path)
    scan = {
        "open_ports": [23, 2323, 7547],
        "services": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "product": "BusyBox", "version": "1.0"},
            {"port": 7547, "protocol": "tcp", "service": "cwmp", "product": "Router Mgmt", "version": "1.0"},
        ],
    }
    prediction = model.predict(scan)
    assessment = combine_assessment(scan, prediction)
    assert assessment["risk"] == "CRITICAL"
    assert assessment["risk_score"] >= 80
