"""
Scanner Module
==============
Provides network scanning capabilities using Nmap.
This module abstracts Nmap interaction, XML parsing,
and security finding derivation for the IoT Security Platform agent.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class NmapScanner:
    """
    Network scanner that wraps Nmap CLI to discover hosts,
    open ports, services, and derive security findings.
    """

    # Default Nmap flags optimized for IoT scanning
    DEFAULT_FLAGS = ["-Pn", "-T4", "-F", "-sV", "--version-light"]

    def __init__(
        self,
        nmap_path: Optional[str] = None,
        output_dir: Optional[Path] = None,
        flags: Optional[List[str]] = None,
    ):
        self.nmap_path = nmap_path or self._locate_nmap()
        self.output_dir = output_dir or Path(__file__).resolve().parent.parent / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.flags = flags or self.DEFAULT_FLAGS

    @staticmethod
    def _locate_nmap() -> str:
        """Locate Nmap binary on the system."""
        candidates = [
            shutil.which("nmap"),
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return str(candidate)
        raise FileNotFoundError(
            "Nmap was not found. Please install Nmap from https://nmap.org/download.html "
            "and ensure nmap.exe (or nmap) is in your PATH."
        )

    @staticmethod
    def get_local_ip() -> str:
        """Detect the local machine's primary IP address."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()

    @staticmethod
    def get_subnet(mask: str = "/24") -> str:
        """Derive the local subnet in CIDR notation."""
        ip = NmapScanner.get_local_ip()
        network = ipaddress.ip_network(ip + mask, strict=False)
        return str(network)

    def run_scan(self, target: str) -> str:
        """Execute an Nmap scan and return raw XML output."""
        output_file = self.output_dir / "latest_scan.xml"
        command = [
            self.nmap_path,
            *self.flags,
            "-oX",
            str(output_file),
            target,
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip() or completed.stdout.strip() or "Nmap scan failed"
            )
        return output_file.read_text(encoding="utf-8", errors="ignore")

    def parse_hosts(self, xml_text: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output into structured host dictionaries."""
        root = ET.fromstring(xml_text)
        hosts: List[Dict[str, Any]] = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.attrib.get("state") != "up":
                continue

            address = host.find("address[@addrtype='ipv4']")
            if address is None:
                continue

            ipv4 = address.attrib.get("addr")
            hostname = ""
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                hn = hostnames_el.find("hostname")
                if hn is not None:
                    hostname = hn.attrib.get("name", "")

            vendor = address.attrib.get("vendor", "")
            os_guess = ""
            os_el = host.find("os")
            if os_el is not None:
                # Try to get the best OS match
                os_matches = os_el.findall("osmatch")
                if os_matches:
                    # Get the match with highest accuracy
                    best_match = max(os_matches, key=lambda m: float(m.attrib.get("accuracy", 0)))
                    os_guess = best_match.attrib.get("name", "")
                    # If accuracy is low, add uncertainty indicator
                    accuracy = float(best_match.attrib.get("accuracy", 0))
                    if accuracy < 90:
                        os_guess += f" ({accuracy:.0f}% confidence)"
                else:
                    # Fallback: try osclass information
                    os_class = os_el.find("osclass")
                    if os_class is not None:
                        vendor = os_class.attrib.get("vendor", "")
                        osfamily = os_class.attrib.get("osfamily", "")
                        if vendor and osfamily:
                            os_guess = f"{vendor} {osfamily}"
                        elif osfamily:
                            os_guess = osfamily

            open_ports: List[int] = []
            services: List[Dict[str, Any]] = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    state = port.find("state")
                    if state is None or state.attrib.get("state") != "open":
                        continue
                    port_id = int(port.attrib.get("portid", 0))
                    open_ports.append(port_id)
                    service = port.find("service")
                    services.append(
                        {
                            "port": port_id,
                            "protocol": port.attrib.get("protocol", "tcp"),
                            "service": service.attrib.get("name", "") if service is not None else "",
                            "product": service.attrib.get("product", "") if service is not None else "",
                            "version": service.attrib.get("version", "") if service is not None else "",
                        }
                    )

            hosts.append(
                {
                    "agent_name": socket.gethostname(),
                    "device_ip": ipv4,
                    "hostname": hostname,
                    "vendor": vendor,
                    "os_guess": os_guess,
                    "open_ports": sorted(set(open_ports)),
                    "services": services,
                    "raw_nmap_xml": ET.tostring(host, encoding="unicode"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

        return hosts
