from __future__ import annotations

import argparse
import ipaddress
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Configuration loader - reads config.yaml when available
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """Load configuration from config.yaml with sensible defaults."""
    config_path = SCRIPT_DIR / "config.yaml"
    defaults = {
        "server": {
            "url": "http://127.0.0.1:8000",
            "endpoints": {"register": "/agent/register", "scan_report": "/scan/report"},
            "timeout": 15,
        },
        "scan": {
            "scan_mode": "fast",
            "nmap_flags": "",
            "subnet_mask": "/24",
            "output_dir": "output",
            "scan_interval": 0,
        },
        "agent": {
            "name": "",
            "log_level": "INFO",
            "max_retries": 3,
            "retry_delay": 5,
        },
    }
    if not config_path.exists():
        return defaults
    try:
        import yaml  # type: ignore
        with open(config_path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        # Merge with defaults
        for section in defaults:
            if section in loaded and isinstance(loaded[section], dict):
                defaults[section].update(loaded[section])
        return defaults
    except ImportError:
        # PyYAML not installed - fall back to simple key extraction
        text = config_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("url:"):
                val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                if val:
                    defaults["server"]["url"] = val
        return defaults
    except Exception:
        return defaults


CONFIG = load_config()
SERVER = CONFIG["server"]["url"]


def get_default_scan_flags(mode: str) -> str:
    if mode == "full":
        return "-Pn -T4 -p- -sV --version-light -O"
    return "-Pn -T4 -F -sV --version-light -O"


def get_scan_mode(cli_mode: str | None = None) -> str:
    if cli_mode:
        return cli_mode.lower()
    return str(CONFIG["scan"].get("scan_mode", "fast")).lower()


def get_scan_flags(scan_mode: str) -> str:
    configured_flags = str(CONFIG["scan"].get("nmap_flags", "") or "").strip()
    if configured_flags:
        return configured_flags
    return get_default_scan_flags(scan_mode)


def locate_nmap() -> str:
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
        "Nmap was not found. Please install Nmap from https://nmap.org/download.html and ensure nmap.exe is in PATH."
    )


def get_local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()


def get_subnet() -> str:
    ip = get_local_ip()
    mask = CONFIG["scan"].get("subnet_mask", "/24")
    network = ipaddress.ip_network(ip + mask, strict=False)
    return str(network)


def register_agent(local_ip: str) -> None:
    agent_name = CONFIG["agent"].get("name") or socket.gethostname()
    payload = {"name": agent_name, "ip": local_ip}
    timeout = CONFIG["server"].get("timeout", 15)
    requests.post(f"{SERVER}/agent/register", json=payload, timeout=timeout)


def run_nmap(subnet: str, nmap_path: str, scan_mode: str | None = None) -> str:
    output_file = OUTPUT_DIR / "latest_scan.xml"
    mode = get_scan_mode(scan_mode)
    flags_str = get_scan_flags(mode)
    flags = flags_str.split()
    command = [nmap_path, *flags, "-oX", str(output_file), subnet]
    print(f"[*] Scan mode: {mode}")
    print("[*] Running:", " ".join(command))
    print("[*] This may take a few minutes...")
    try:
        # Add timeout of 180 seconds (3 minutes) for the scan
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out after 180 seconds. Using cached results if available.")
        if output_file.exists():
            return output_file.read_text(encoding="utf-8", errors="ignore")
        raise RuntimeError("Nmap scan timed out and no cached results available")
    
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "Nmap scan failed")
    print(completed.stdout)
    return output_file.read_text(encoding="utf-8", errors="ignore")


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def derive_weak_credential_findings(open_ports: list[int], services: list[dict], hostname: str, vendor: str) -> list[str]:
    ports = set(open_ports)
    service_names = {str(service.get("service", "")).lower() for service in services}
    findings: list[str] = []

    if 23 in ports or 2323 in ports or "telnet" in service_names:
        findings.append("Telnet management detected; verify no default or reused admin passwords remain enabled")
    if 21 in ports or "ftp" in service_names:
        findings.append("FTP service is exposed; confirm strong unique credentials and disable anonymous access")
    if 80 in ports or 81 in ports or 8080 in ports:
        findings.append("Web admin interface exposed over HTTP; review default web console credentials")
    if 7547 in ports:
        findings.append("CWMP/TR-069 remote management may expose ISP-default credentials on routers")
    if 554 in ports or "rtsp" in service_names:
        findings.append("RTSP camera stream exposed; check that vendor default camera credentials were changed")
    if 161 in ports or "snmp" in service_names:
        findings.append("SNMP exposure suggests community strings should be reviewed and rotated")
    if vendor and any(keyword in vendor.lower() for keyword in ["hikvision", "dahua", "tp-link", "tplink", "xiaomi"]):
        findings.append(f"Validate factory-default credentials are changed for vendor profile: {vendor}")
    if hostname and any(keyword in hostname.lower() for keyword in ["camera", "ipcam", "router", "dvr", "nvr"]):
        findings.append(f"Administrative credentials should be reviewed for device role inferred from hostname: {hostname}")

    return dedupe(findings)


def derive_config_issues(open_ports: list[int], services: list[dict]) -> list[str]:
    ports = set(open_ports)
    service_names = {str(service.get("service", "")).lower() for service in services}
    issues: list[str] = []

    if (80 in ports or 81 in ports or 8080 in ports) and 443 not in ports and 8443 not in ports:
        issues.append("HTTP management is available without an HTTPS alternative")
    if 1900 in ports or "upnp" in service_names or "ssdp" in service_names:
        issues.append("UPnP/SSDP discovery is exposed and may widen remote attack surface")
    if 161 in ports or "snmp" in service_names:
        issues.append("SNMP should be restricted to trusted management hosts only")
    if 445 in ports or 139 in ports or "microsoft-ds" in service_names:
        issues.append("SMB exposure should be segmented away from untrusted IoT network zones")
    if 502 in ports or "modbus" in service_names:
        issues.append("Industrial protocol exposure detected; apply network segmentation and ACLs")
    if 5555 in ports or "adb" in service_names:
        issues.append("Android Debug Bridge exposure detected; disable remote debugging")
    if len(ports) >= 6:
        issues.append("Device exposes a large number of ports and should be hardened")

    return dedupe(issues)


def derive_threat_indicators(open_ports: list[int], services: list[dict]) -> list[str]:
    ports = set(open_ports)
    service_names = {str(service.get("service", "")).lower() for service in services}
    indicators: list[str] = []

    if {23, 2323}.intersection(ports) and 7547 in ports:
        indicators.append("Router-style exposure pattern (Telnet + CWMP) resembles botnet-targeted device profiles")
    if {23, 2323}.intersection(ports) and 1900 in ports:
        indicators.append("Telnet with discovery services exposed can enable rapid device enumeration")
    if 5555 in ports and (80 in ports or 8080 in ports):
        indicators.append("ADB plus web management exposure increases risk of remote tampering")
    if 21 in ports and (23 in ports or 2323 in ports):
        indicators.append("Multiple legacy management services are simultaneously reachable")
    if "mqtt" in service_names and 1883 in ports and 8883 not in ports:
        indicators.append("Unencrypted MQTT detected; message interception or tampering risk is elevated")

    return dedupe(indicators)


def parse_hosts(xml_text: str) -> list[dict]:
    # Handle incomplete/broken XML by ensuring it's properly closed
    xml_text = xml_text.strip()
    if not xml_text.endswith("</nmaprun>"):
        xml_text += "</nmaprun>"
    
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        print(f"[!] Attempting to extract partial results...")
        # Try to extract what we can before the error
        try:
            # Find the last complete host element
            match_start = xml_text.rfind("<host ")
            if match_start == -1:
                return []
            match_end = xml_text.find("</host>", match_start)
            if match_end == -1:
                match_end = len(xml_text)
            partial_xml = xml_text[:match_end + 7] + "</nmaprun>"
            root = ET.fromstring(partial_xml)
        except:
            print("[!] Could not recover from XML parse error")
            return []
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue
        ipv4 = address.attrib.get("addr")
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
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
                print(f"[+] OS detected for {ipv4}: {os_guess} (accuracy: {accuracy}%)")
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
                    print(f"[+] OS class detected for {ipv4}: {os_guess}")
                else:
                    print(f"[!] No OS information found for {ipv4}")
        else:
            print(f"[!] No OS element in XML for {ipv4}")
        open_ports = []
        services = []
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
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

        weak_credentials = derive_weak_credential_findings(open_ports, services, hostname, vendor)
        config_issues = derive_config_issues(open_ports, services)
        threat_indicators = derive_threat_indicators(open_ports, services)

        agent_name = CONFIG["agent"].get("name") or socket.gethostname()
        hosts.append(
            {
                "agent_name": agent_name,
                "device_ip": ipv4,
                "hostname": hostname,
                "vendor": vendor,
                "os_guess": os_guess,
                "open_ports": sorted(set(open_ports)),
                "services": services,
                "weak_credentials": weak_credentials,
                "config_issues": config_issues,
                "threat_indicators": threat_indicators,
                "raw_nmap_xml": ET.tostring(host, encoding="unicode"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    return hosts


def send_host(host: dict) -> None:
    """Send scan result to server with retry logic."""
    timeout = CONFIG["server"].get("timeout", 15)
    max_retries = CONFIG["agent"].get("max_retries", 3)
    retry_delay = CONFIG["agent"].get("retry_delay", 5)
    
    for attempt in range(max_retries):
        try:
            response = requests.post(f"{SERVER}/scan/report", json=host, timeout=timeout + 5)
            response.raise_for_status()
            data = response.json()
            print(f"[+] {host['device_ip']} -> {data['risk']} ({data['risk_score']})")
            return
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                print(f"[!] Attempt {attempt + 1}/{max_retries} failed for {host['device_ip']}: {e}")
                print(f"[*] Retrying in {retry_delay} seconds...")
                import time
                time.sleep(retry_delay)
            else:
                print(f"[ERROR] Failed to send {host['device_ip']} after {max_retries} attempts: {e}")


def main(scan_mode: str | None = None) -> int:
    try:
        nmap_path = locate_nmap()
        local_ip = get_local_ip()
        subnet = get_subnet()
        print(f"[*] Server: {SERVER}")
        print("[*] Local IP:", local_ip)
        print("[*] Subnet:", subnet)
        
        try:
            register_agent(local_ip)
        except Exception as e:
            print(f"[!] Agent registration failed: {e}")
        
        xml_text = run_nmap(subnet, nmap_path, scan_mode)
        hosts = parse_hosts(xml_text)
        if not hosts:
            print("[!] No active hosts found in the subnet.")
            return 0
        
        successful = 0
        failed = 0
        for host in hosts:
            try:
                send_host(host)
                successful += 1
            except Exception as e:
                print(f"[ERROR] Failed to send host {host.get('device_ip', 'unknown')}: {e}")
                failed += 1
                continue
        
        print(f"[*] Completed. {successful} hosts reported, {failed} failed.")
        print(f"[*] XML saved to: {OUTPUT_DIR / 'latest_scan.xml'}")
        return 0 if successful > 0 else 1
    except Exception as exc:
        print(f"[ERROR] {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the agent scan using fast or full port detection.")
    parser.add_argument("--mode", choices=["fast", "full"], default=None, help="Scan mode to use")
    args = parser.parse_args()
    raise SystemExit(main(scan_mode=args.mode))
