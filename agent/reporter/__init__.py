"""
Reporter Module
===============
Handles agent-side reporting by sending scan results to the
IoT Security Platform server and logging scan summaries locally.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("iot-agent-reporter")


class AgentReporter:
    """
    Manages communication with the IoT Security Platform server.
    Handles agent registration, scan result submission, and local
    summary logging.
    """

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8000",
        timeout: int = 15,
        max_retries: int = 3,
        retry_delay: int = 5,
        log_dir: Optional[Path] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.log_dir = log_dir or Path(__file__).resolve().parent.parent / "output"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def register_agent(self, agent_name: Optional[str] = None, agent_ip: Optional[str] = None) -> Dict[str, Any]:
        """Register this scanning agent with the server."""
        payload = {
            "name": agent_name or socket.gethostname(),
            "ip": agent_ip or self._get_local_ip(),
        }
        response = requests.post(
            f"{self.server_url}/agent/register",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        logger.info("Agent registered: %s (%s)", payload["name"], payload["ip"])
        return response.json()

    def send_scan_result(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a single host scan result to the server for analysis."""
        import time

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    f"{self.server_url}/scan/report",
                    json=host_data,
                    timeout=self.timeout + 5,
                )
                response.raise_for_status()
                data = response.json()
                logger.info(
                    "[%s] %s -> %s (score: %s)",
                    attempt,
                    host_data.get("device_ip", "unknown"),
                    data.get("risk", "?"),
                    data.get("risk_score", "?"),
                )
                return data
            except Exception as exc:
                last_error = exc
                logger.warning("Attempt %d failed for %s: %s", attempt, host_data.get("device_ip"), exc)
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)

        raise RuntimeError(f"Failed to submit scan after {self.max_retries} attempts: {last_error}")

    def send_batch(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Submit multiple host results sequentially."""
        results = []
        for host in hosts:
            result = self.send_scan_result(host)
            results.append(result)
        return results

    def save_local_summary(self, hosts: List[Dict[str, Any]], results: List[Dict[str, Any]]) -> Path:
        """Save a local JSON summary of the scan session."""
        summary = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "agent_name": socket.gethostname(),
            "total_hosts": len(hosts),
            "results": [
                {
                    "device_ip": host.get("device_ip", ""),
                    "risk": result.get("risk", "UNKNOWN"),
                    "risk_score": result.get("risk_score", 0),
                    "ml_label": result.get("ml_label", ""),
                    "anomaly_score": result.get("anomaly_score", 0),
                    "open_ports": host.get("open_ports", []),
                }
                for host, result in zip(hosts, results)
            ],
        }
        summary_file = self.log_dir / "scan_summary.json"
        summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info("Local summary saved to %s", summary_file)
        return summary_file

    @staticmethod
    def _get_local_ip() -> str:
        """Detect local IP address."""
        import socket as _socket

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
