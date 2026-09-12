from __future__ import annotations

import json
import os
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field

from .ml_engine import RiskModel, combine_assessment
from .reporting import create_csv_report, create_json_report, create_pdf_report


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
        return response


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("IOT_DB_PATH", str(DATA_DIR / "iot_security.db")))


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="IoT Security Analyzer Server", lifespan=lifespan)

# Security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],  # In production, specify allowed hosts
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
model = RiskModel(MODEL_DIR)


class AgentRegister(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    ip: str = Field(..., min_length=7, max_length=45)  # IPv4 or IPv6


class ServiceInfo(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")
    service: str = Field(default="", max_length=50)
    product: str = Field(default="", max_length=100)
    version: str = Field(default="", max_length=50)


class TrafficProfile(BaseModel):
    connections_per_minute: int = Field(default=0, ge=0, le=10000)
    unique_remote_ips: int = Field(default=0, ge=0, le=1000)
    failed_connections: int = Field(default=0, ge=0, le=10000)
    dns_requests_per_minute: int = Field(default=0, ge=0, le=1000)
    outbound_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    beaconing_score: float = Field(default=0.0, ge=0.0, le=1.0)
    unusual_ports_contacted: int = Field(default=0, ge=0, le=1000)
    notes: str = Field(default="", max_length=500)


class ScanResult(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=100)
    device_ip: str = Field(..., min_length=7, max_length=45)
    open_ports: List[int] = Field(default_factory=list, max_length=100)
    services: List[ServiceInfo] = Field(default_factory=list, max_length=50)
    hostname: Optional[str] = Field(None, max_length=253)
    vendor: Optional[str] = Field(None, max_length=100)
    os_guess: Optional[str] = Field(None, max_length=200)
    raw_nmap_xml: Optional[str] = Field(None, max_length=10000)
    weak_credentials: List[str] = Field(default_factory=list, max_length=20)
    config_issues: List[str] = Field(default_factory=list, max_length=20)
    threat_indicators: List[str] = Field(default_factory=list, max_length=20)
    traffic_profile: Optional[TrafficProfile] = None
    timestamp: Optional[datetime] = None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/network", response_class=HTMLResponse)
def network_page(request: Request):
    return templates.TemplateResponse("network.html", {"request": request})


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "db_path": str(DB_PATH),
        "model_metrics": model.metrics,
    }


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                os_guess TEXT,
                open_ports TEXT NOT NULL,
                services TEXT NOT NULL,
                raw_nmap_xml TEXT,
                risk TEXT NOT NULL,
                risk_score REAL NOT NULL,
                ml_label TEXT NOT NULL,
                ml_confidence REAL NOT NULL,
                anomaly_score REAL NOT NULL,
                issues TEXT NOT NULL,
                weak_credentials TEXT NOT NULL DEFAULT '[]',
                config_issues TEXT NOT NULL DEFAULT '[]',
                threat_indicators TEXT NOT NULL DEFAULT '[]',
                traffic_profile TEXT,
                label_probabilities TEXT NOT NULL,
                features TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        ensure_scan_schema(conn)
        conn.commit()


def ensure_scan_schema(conn: sqlite3.Connection) -> None:
    rows = conn.execute("PRAGMA table_info(scans)").fetchall()
    existing = {row["name"] for row in rows}
    required_columns = {
        "weak_credentials": "TEXT NOT NULL DEFAULT '[]'",
        "config_issues": "TEXT NOT NULL DEFAULT '[]'",
        "threat_indicators": "TEXT NOT NULL DEFAULT '[]'",
        "traffic_profile": "TEXT",
    }
    for column, ddl in required_columns.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {ddl}")


@app.post("/agent/register")
def register_agent(agent: AgentRegister) -> dict[str, str]:
    with closing(get_conn()) as conn:
        conn.execute(
            "INSERT INTO agents(name, ip, created_at) VALUES (?, ?, ?)",
            (agent.name, agent.ip, utc_now()),
        )
        conn.commit()
    return {"message": "Agent registered successfully"}


@app.post("/scan/report")
def receive_scan(scan: ScanResult) -> dict[str, Any]:
    payload = scan.model_dump()
    payload["services"] = [svc.model_dump() if hasattr(svc, "model_dump") else dict(svc) for svc in scan.services]
    payload["traffic_profile"] = scan.traffic_profile.model_dump() if scan.traffic_profile else None
    payload["timestamp"] = (scan.timestamp or datetime.now(UTC)).isoformat()

    ml_output = model.predict(payload)
    assessment = combine_assessment(payload, ml_output)

    with closing(get_conn()) as conn:
        ensure_scan_schema(conn)
        conn.execute(
            """
            INSERT INTO scans(
                agent_name, device_ip, hostname, vendor, os_guess, open_ports, services,
                raw_nmap_xml, risk, risk_score, ml_label, ml_confidence, anomaly_score,
                issues, weak_credentials, config_issues, threat_indicators, traffic_profile,
                label_probabilities, features, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.agent_name,
                scan.device_ip,
                scan.hostname,
                scan.vendor,
                scan.os_guess,
                json.dumps(sorted(set(scan.open_ports))),
                json.dumps(payload["services"]),
                scan.raw_nmap_xml,
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
                payload["timestamp"],
            ),
        )
        conn.commit()

    return {
        "message": "Scan analyzed and stored",
        **assessment,
    }


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    scans = get_latest_scans_per_device()
    recent = get_recent_scans(limit=200)
    risk_pressure = 0
    if scans:
        risk_pressure = round(sum(scan["risk_score"] for scan in scans) / len(scans), 2)

    return {
        "total_scans": get_scan_count(),
        "total_devices": len(scans),
        "critical_risk": sum(1 for scan in scans if scan["risk"] == "CRITICAL"),
        "high_risk": sum(1 for scan in scans if scan["risk"] == "HIGH"),
        "medium_risk": sum(1 for scan in scans if scan["risk"] == "MEDIUM"),
        "low_risk": sum(1 for scan in scans if scan["risk"] == "LOW"),
        "weak_credential_devices": sum(1 for scan in scans if scan["weak_credentials"]),
        "config_issue_devices": sum(1 for scan in scans if scan["config_issues"]),
        "threat_indicator_devices": sum(1 for scan in scans if scan["threat_indicators"]),
        "risk_pressure": risk_pressure,
        "critical_alarm": any(scan["risk"] == "CRITICAL" for scan in scans),
        "latest_scan_time": recent[0]["timestamp"] if recent else None,
        "model_accuracy": model.metrics.get("accuracy"),
        "model_weighted_f1": model.metrics.get("weighted_f1"),
    }


@app.get("/api/recent-scans")
def recent_scans() -> list[dict[str, Any]]:
    return get_recent_scans(limit=12)


@app.get("/api/network-data")
def network_data() -> dict[str, Any]:
    latest = get_latest_scans_per_device()
    nodes = [
        {
            "id": "gateway",
            "label": "Your PC / Gateway",
            "color": "#00ffff",
            "size": 35,
            "risk": "INFO",
            "risk_score": 0,
            "open_ports": [],
            "issues": [],
            "weak_credentials": [],
            "config_issues": [],
            "threat_indicators": [],
            "traffic_profile": None,
            "hostname": "Local Controller",
            "vendor": "Local Host",
            "services": [],
            "ml_label": "LOW",
            "ml_confidence": 1.0,
            "anomaly_score": 0.0,
        }
    ]
    edges = []
    for device in latest:
        risk = device["risk"]
        color = {
            "CRITICAL": "#ff0033",
            "HIGH": "#ff6b00",
            "MEDIUM": "#ffaa00",
            "LOW": "#00ff99",
        }.get(risk, "#00ff99")
        # Create device dict without the database id field to avoid overwriting node id
        device_data = {k: v for k, v in device.items() if k != "id"}
        nodes.append(
            {
                "id": device["device_ip"],
                "label": device["device_ip"],
                "color": color,
                "size": 32 if risk == "CRITICAL" else 28 if risk == "HIGH" else 24,
                **device_data,
            }
        )
        edges.append({"from": "gateway", "to": device["device_ip"]})
    return {"nodes": nodes, "edges": edges}


@app.get("/api/device/{ip}")
def get_device(ip: str) -> dict[str, Any]:
    scan = get_device_latest(ip)
    if not scan:
        raise HTTPException(status_code=404, detail="Device not found")
    return scan


@app.get("/api/trends")
def trends() -> dict[str, Any]:
    scans = list(reversed(get_recent_scans(limit=30)))
    return {
        "labels": [format_time_label(scan["timestamp"]) for scan in scans],
        "risk_scores": [scan["risk_score"] for scan in scans],
        "critical_counts": [1 if scan["risk"] == "CRITICAL" else 0 for scan in scans],
        "high_counts": [1 if scan["risk"] == "HIGH" else 0 for scan in scans],
        "medium_counts": [1 if scan["risk"] == "MEDIUM" else 0 for scan in scans],
        "low_counts": [1 if scan["risk"] == "LOW" else 0 for scan in scans],
    }


@app.get("/api/top-ports")
def top_ports() -> dict[str, Any]:
    counts: dict[int, int] = {}
    for scan in get_latest_scans_per_device():
        for port in scan["open_ports"]:
            counts[port] = counts.get(port, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:8]
    return {
        "labels": [str(port) for port, _ in ranked],
        "counts": [count for _, count in ranked],
    }


@app.get("/api/alerts")
def alerts() -> list[dict[str, Any]]:
    return [
        {
            "device_ip": scan["device_ip"],
            "risk": scan["risk"],
            "risk_score": scan["risk_score"],
            "headline": (scan["issues"][0] if scan["issues"] else "No issue summary available"),
        }
        for scan in get_latest_scans_per_device()
        if scan["risk"] in {"CRITICAL", "HIGH"}
    ][:6]


@app.get("/api/report.csv")
def report_csv() -> Response:
    scans = get_latest_scans_per_device()
    content = create_csv_report(scans)
    headers = {"Content-Disposition": 'attachment; filename="iot-security-report.csv"'}
    return Response(content=content, media_type="text/csv", headers=headers)


@app.get("/api/report.json")
def report_json() -> Response:
    scans = get_latest_scans_per_device()
    content = create_json_report(scans, get_stats())
    headers = {"Content-Disposition": 'attachment; filename="iot-security-report.json"'}
    return Response(content=content, media_type="application/json", headers=headers)


@app.get("/api/report.pdf")
def report_pdf() -> StreamingResponse:
    scans = get_latest_scans_per_device()
    pdf_bytes = create_pdf_report(scans, get_stats())
    headers = {"Content-Disposition": 'attachment; filename="iot-security-report.pdf"'}
    return StreamingResponse(iter([pdf_bytes]), media_type="application/pdf", headers=headers)


@app.get("/api/model-info")
def model_info() -> dict[str, Any]:
    return model.metrics


@app.post("/api/clear-scans")
def clear_scans() -> dict[str, str]:
    """Clear all scan results from the database."""
    try:
        with closing(get_conn()) as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()
        return {"message": "All scan results cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear scans: {str(e)}")


@app.post("/api/start-scan")
def start_scan() -> dict[str, str]:
    """Trigger a new scan by calling the agent scanner."""
    try:
        import subprocess
        import sys
        import os

        agent_dir = Path(__file__).parent.parent.parent / "agent"
        scanner_script = agent_dir / "scanner.py"

        if not scanner_script.exists():
            scanner_script = agent_dir / "windows_scanner.py"
            if not scanner_script.exists():
                raise HTTPException(status_code=500, detail="Scanner script not found")

        if os.name == 'nt':
            subprocess.Popen([sys.executable, str(scanner_script)],
                           cwd=str(agent_dir),
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            subprocess.Popen([sys.executable, str(scanner_script)],
                           cwd=str(agent_dir))

        return {"message": "Scan initiated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def format_time_label(timestamp: str) -> str:
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return timestamp


def get_scan_count() -> int:
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM scans").fetchone()
        return int(row["total"])


def _json_load_or_default(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _decode_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "agent_name": row["agent_name"],
        "device_ip": row["device_ip"],
        "hostname": row["hostname"] or "",
        "vendor": row["vendor"] or "",
        "os_guess": row["os_guess"] or "",
        "open_ports": _json_load_or_default(row["open_ports"], []),
        "services": _json_load_or_default(row["services"], []),
        "raw_nmap_xml": row["raw_nmap_xml"] or "",
        "risk": row["risk"],
        "risk_score": row["risk_score"],
        "ml_label": row["ml_label"],
        "ml_confidence": row["ml_confidence"],
        "anomaly_score": row["anomaly_score"],
        "issues": _json_load_or_default(row["issues"], []),
        "weak_credentials": _json_load_or_default(row["weak_credentials"], []),
        "config_issues": _json_load_or_default(row["config_issues"], []),
        "threat_indicators": _json_load_or_default(row["threat_indicators"], []),
        "traffic_profile": _json_load_or_default(row["traffic_profile"], None),
        "label_probabilities": _json_load_or_default(row["label_probabilities"], {}),
        "features": _json_load_or_default(row["features"], {}),
        "timestamp": row["timestamp"],
    }


def get_recent_scans(limit: int = 10) -> list[dict[str, Any]]:
    with closing(get_conn()) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY datetime(timestamp) DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_decode_scan(row) for row in rows]


def get_latest_scans_per_device() -> list[dict[str, Any]]:
    with closing(get_conn()) as conn:
        rows = conn.execute(
            """
            SELECT s.*
            FROM scans s
            INNER JOIN (
                SELECT device_ip, MAX(datetime(timestamp)) AS max_ts
                FROM scans
                GROUP BY device_ip
            ) latest
            ON s.device_ip = latest.device_ip AND datetime(s.timestamp) = latest.max_ts
            ORDER BY s.risk_score DESC, s.device_ip ASC
            """
        ).fetchall()
    seen: set[str] = set()
    result = []
    for row in rows:
        decoded = _decode_scan(row)
        if decoded["device_ip"] not in seen:
            result.append(decoded)
            seen.add(decoded["device_ip"])
    return result


def get_device_latest(ip: str) -> Optional[dict[str, Any]]:
    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE device_ip = ? ORDER BY datetime(timestamp) DESC LIMIT 1",
            (ip,),
        ).fetchone()
    return _decode_scan(row) if row else None
