from __future__ import annotations

import json
import math
import random
from pathlib import Path
from typing import Any, Dict, Iterable, List

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

PORT_SERVICE_MAP = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    81: "http-alt",
    110: "pop3",
    123: "ntp",
    135: "rpc",
    137: "netbios",
    138: "netbios",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    502: "modbus",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    7547: "cwmp",
    8080: "http-proxy",
    8443: "https-alt",
    8883: "mqtts",
    9100: "jetdirect",
    1883: "mqtt",
    1900: "ssdp",
    2323: "telnet-alt",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp",
    5353: "mdns",
    5432: "postgresql",
    5555: "adb",
    5683: "coap",
    5900: "vnc",
    8081: "http-alt",
}

PORT_WEIGHTS = {
    21: 12,
    23: 30,
    69: 18,
    80: 6,
    81: 12,
    110: 6,
    135: 8,
    137: 7,
    138: 7,
    139: 14,
    161: 16,
    445: 22,
    502: 25,
    554: 9,
    7547: 24,
    8080: 7,
    9100: 12,
    1883: 11,
    1900: 13,
    2323: 28,
    3306: 12,
    3389: 18,
    5432: 11,
    5555: 18,
    5683: 12,
    5900: 16,
}

LOW_PROFILES = [
    [443],
    [22],
    [80, 443],
    [53, 67],
    [554],
    [443, 8883],
    [80, 443, 554],
    [631],
]

MEDIUM_PROFILES = [
    [80],
    [80, 8080],
    [1883],
    [161, 80],
    [8080, 8443],
    [53, 80, 443],
    [554, 80],
    [631, 9100],
]

HIGH_PROFILES = [
    [21, 80],
    [445, 139],
    [3389, 445],
    [161, 1900, 80],
    [21, 80, 8080],
    [5555, 80],
    [9100, 631, 80],
    [5683, 1883, 80],
]

CRITICAL_PROFILES = [
    [23, 2323],
    [23, 80, 81],
    [23, 21, 445],
    [23, 2323, 7547],
    [502, 23, 2323],
    [5900, 23, 2323],
    [7547, 23, 80, 8080],
    [23, 1883, 1900, 5555],
]

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _normalize_services(services: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    result = []
    for svc in services or []:
        result.append(
            {
                "port": int(svc.get("port", 0)),
                "protocol": str(svc.get("protocol", "tcp")),
                "service": str(svc.get("service", svc.get("name", ""))).lower(),
                "product": str(svc.get("product", "")),
                "version": str(svc.get("version", "")),
            }
        )
    return result


def build_feature_row(scan: Dict[str, Any]) -> Dict[str, float]:
    open_ports = sorted({int(p) for p in scan.get("open_ports", [])})
    services = _normalize_services(scan.get("services", []))
    service_names = [svc["service"] for svc in services if svc.get("service")]
    unique_service_names = sorted(set(service_names or [PORT_SERVICE_MAP.get(p, "unknown") for p in open_ports]))

    open_port_count = len(open_ports)
    risky_weight = sum(PORT_WEIGHTS.get(p, 0) for p in open_ports)
    risky_count = sum(1 for p in open_ports if p in PORT_WEIGHTS)
    high_port_count = sum(1 for p in open_ports if p >= 1024)
    low_port_count = sum(1 for p in open_ports if p < 1024)
    well_known_port_count = sum(1 for p in open_ports if 1 <= p <= 1023)
    registered_port_count = sum(1 for p in open_ports if 1024 <= p <= 49151)
    dynamic_port_count = sum(1 for p in open_ports if 49152 <= p <= 65535)
    unusual_port_count = sum(1 for p in open_ports if p > 49151)
    service_diversity = len(unique_service_names)
    dangerous_services = sum(
        1
        for svc in unique_service_names
        if any(keyword in svc for keyword in ["telnet", "ftp", "smb", "rdp", "vnc", "snmp", "modbus", "cwmp", "adb"])
    )

    def has_port(port: int) -> int:
        return int(port in open_ports)

    http_plain = int(80 in open_ports or 8080 in open_ports or 81 in open_ports)
    https_present = int(443 in open_ports or 8443 in open_ports)
    http_without_https = int(http_plain and not https_present)
    exposure_ratio = round(risky_count / open_port_count, 4) if open_port_count else 0.0
    weighted_pressure = round(risky_weight / max(open_port_count, 1), 4)

    # Additional features for better classification
    port_range = max(open_ports) - min(open_ports) if open_ports else 0
    port_density = round(open_port_count / max(port_range, 1), 4) if port_range else 0.0
    sequential_ports = sum(1 for i in range(len(open_ports)-1) if open_ports[i+1] - open_ports[i] == 1)

    bucket_counts = [
        sum(1 for p in open_ports if bucket_start <= p <= bucket_end)
        for bucket_start, bucket_end in [(1, 1023), (1024, 49151), (49152, 65535)]
    ]
    bucket_probs = [count / open_port_count for count in bucket_counts if count and open_port_count]
    port_entropy = round(-sum(p * math.log(p) for p in bucket_probs), 4) if bucket_probs else 0.0

    # Service-based features
    web_services = sum(1 for svc in unique_service_names if "http" in svc or "web" in svc)
    iot_services = sum(1 for svc in unique_service_names if any(s in svc for s in ["mqtt", "coap", "rtsp", "ssdp"]))
    industrial_services = sum(1 for svc in unique_service_names if any(s in svc for s in ["modbus", "dnp3", "iec", "opc"]))
    management_services = sum(1 for svc in unique_service_names if any(s in svc for s in ["snmp", "ssh", "telnet", "rdp"]))

    # Contextual features
    has_weak_creds = int(len(scan.get("weak_credentials", [])) > 0)
    has_config_issues = int(len(scan.get("config_issues", [])) > 0)
    has_threat_indicators = int(len(scan.get("threat_indicators", [])) > 0)

    return {
        "open_port_count": float(open_port_count),
        "risky_port_count": float(risky_count),
        "risky_weight": float(risky_weight),
        "high_port_count": float(high_port_count),
        "low_port_count": float(low_port_count),
        "well_known_port_count": float(well_known_port_count),
        "registered_port_count": float(registered_port_count),
        "dynamic_port_count": float(dynamic_port_count),
        "unusual_port_count": float(unusual_port_count),
        "service_diversity": float(service_diversity),
        "dangerous_services": float(dangerous_services),
        "exposure_ratio": float(exposure_ratio),
        "weighted_pressure": float(weighted_pressure),
        "port_range": float(port_range),
        "port_density": float(port_density),
        "sequential_ports": float(sequential_ports),
        "port_entropy": float(port_entropy),
        "web_services": float(web_services),
        "iot_services": float(iot_services),
        "industrial_services": float(industrial_services),
        "management_services": float(management_services),
        "has_weak_creds": float(has_weak_creds),
        "has_config_issues": float(has_config_issues),
        "has_threat_indicators": float(has_threat_indicators),
        "has_ftp": float(has_port(21)),
        "has_telnet": float(has_port(23) or has_port(2323)),
        "has_http": float(http_plain),
        "has_https": float(https_present),
        "http_without_https": float(http_without_https),
        "has_snmp": float(has_port(161)),
        "has_smb": float(has_port(445) or has_port(139)),
        "has_modbus": float(has_port(502)),
        "has_rtsp": float(has_port(554)),
        "has_mqtt": float(has_port(1883)),
        "has_mqtts": float(has_port(8883)),
        "has_ssdp": float(has_port(1900)),
        "has_rdp": float(has_port(3389)),
        "has_vnc": float(has_port(5900)),
        "has_printer": float(has_port(631) or has_port(9100)),
        "has_coap": float(has_port(5683)),
        "has_cwmp": float(has_port(7547)),
        "has_adb": float(has_port(5555)),
    }


FEATURE_COLUMNS = list(build_feature_row({"open_ports": [80, 443], "services": []}).keys())


def _dedupe_text(items: Iterable[Any] | None) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items or []:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def contextual_findings(scan: Dict[str, Any]) -> Dict[str, Any]:
    weak_credentials = _dedupe_text(scan.get("weak_credentials"))
    config_issues = _dedupe_text(scan.get("config_issues"))
    threat_indicators = _dedupe_text(scan.get("threat_indicators"))
    traffic_profile = scan.get("traffic_profile") or None
    issues: list[str] = []
    bonus = 0

    if weak_credentials:
        bonus += min(18, 6 * len(weak_credentials))
        issues.extend(f"Weak credential risk: {item}" for item in weak_credentials)

    if config_issues:
        bonus += min(18, 4 * len(config_issues))
        issues.extend(f"Configuration issue: {item}" for item in config_issues)

    if threat_indicators:
        bonus += min(16, 5 * len(threat_indicators))
        issues.extend(f"Threat indicator: {item}" for item in threat_indicators)

    if traffic_profile:
        connections_per_minute = int(traffic_profile.get("connections_per_minute") or 0)
        unique_remote_ips = int(traffic_profile.get("unique_remote_ips") or 0)
        failed_connections = int(traffic_profile.get("failed_connections") or 0)
        dns_requests_per_minute = int(traffic_profile.get("dns_requests_per_minute") or 0)
        unusual_ports_contacted = int(traffic_profile.get("unusual_ports_contacted") or 0)
        outbound_ratio = float(traffic_profile.get("outbound_ratio") or 0.0)
        beaconing_score = float(traffic_profile.get("beaconing_score") or 0.0)

        if connections_per_minute >= 240:
            bonus += 8
            issues.append("Traffic profile shows a very high connection rate")
        if unique_remote_ips >= 15:
            bonus += 5
            issues.append("Device communicates with an unusually large set of remote IPs")
        if failed_connections >= 20:
            bonus += 6
            issues.append("Many failed connections suggest scanning, beaconing, or service instability")
        if dns_requests_per_minute >= 90:
            bonus += 5
            issues.append("DNS request volume is elevated for a typical IoT endpoint")
        if unusual_ports_contacted >= 5:
            bonus += 5
            issues.append("Device is contacting multiple unusual destination ports")
        if outbound_ratio >= 0.85:
            bonus += 4
            issues.append("Outbound-heavy traffic profile may indicate command-and-control style behavior")
        if beaconing_score >= 0.7:
            bonus += 8
            indicator = "Traffic cadence appears beacon-like and should be investigated"
            threat_indicators = _dedupe_text([*threat_indicators, indicator])
            issues.append(f"Threat indicator: {indicator}")

    return {
        "bonus": bonus,
        "issues": _dedupe_text(issues),
        "weak_credentials": weak_credentials,
        "config_issues": config_issues,
        "threat_indicators": threat_indicators,
        "traffic_profile": traffic_profile,
    }


def rule_score(scan: Dict[str, Any]) -> tuple[int, list[str]]:
    ports = set(int(p) for p in scan.get("open_ports", []))
    score = 8 + min(len(ports) * 4, 24)
    issues: list[str] = []

    for port, weight in PORT_WEIGHTS.items():
        if port in ports:
            score += weight
            issues.append(f"Sensitive or frequently abused port {port} exposed")

    if (80 in ports or 8080 in ports or 81 in ports) and 443 not in ports and 8443 not in ports:
        score += 10
        issues.append("HTTP service detected without an HTTPS equivalent")

    if len(ports) >= 6:
        score += 12
        issues.append("Large attack surface due to many open ports")

    if 23 in ports or 2323 in ports:
        issues.append("Telnet is enabled and should be disabled or replaced")
    if 21 in ports:
        issues.append("FTP is enabled; prefer SFTP/FTPS")
    if 445 in ports or 139 in ports:
        issues.append("SMB exposure can increase lateral movement risk")
    if 161 in ports:
        issues.append("SNMP exposure may leak device information")
    if 1900 in ports:
        issues.append("UPnP/SSDP discovery exposure detected")
    if 7547 in ports:
        issues.append("CWMP/TR-069 port exposed; often abused on routers")
    if 502 in ports:
        issues.append("Industrial Modbus port detected; protect with segmentation")
    if not ports:
        issues.append("No open ports detected in latest scan")
        score = 5

    if score >= 85:
        issues.append("Risk score crossed the critical alarm threshold")

    unique_issues = []
    for issue in issues:
        if issue not in unique_issues:
            unique_issues.append(issue)
    return min(score, 100), unique_issues


def _services_for_ports(ports: list[int]) -> list[dict[str, Any]]:
    services = []
    for port in ports:
        name = PORT_SERVICE_MAP.get(port, "unknown")
        services.append(
            {
                "port": port,
                "protocol": "tcp",
                "service": name,
                "product": {
                    "http": "Embedded Web Server",
                    "https": "Secure Web Server",
                    "ssh": "OpenSSH",
                    "rtsp": "IP Camera Streaming",
                    "mqtt": "Mosquitto",
                    "mqtts": "Mosquitto TLS",
                    "cwmp": "Router Management",
                    "modbus": "Industrial PLC",
                    "rdp": "Windows Remote Desktop",
                    "microsoft-ds": "SMB",
                }.get(name, "Embedded Service"),
                "version": "1.0",
            }
        )
    return services


def _bootstrap_rows() -> pd.DataFrame:
    random.seed(42)
    rows: list[dict[str, Any]] = []
    profile_groups = {
        "LOW": LOW_PROFILES,
        "MEDIUM": MEDIUM_PROFILES,
        "HIGH": HIGH_PROFILES,
        "CRITICAL": CRITICAL_PROFILES,
    }

    optional_noise = [53, 67, 123, 554, 631, 8081, 8443, 993, 995, 1433, 1521, 3306, 5432, 4786, 5353, 10000, 20000]
    # Add more realistic IoT device profiles
    iot_profiles = {
        "LOW": [
            [80, 443],  # Basic web server
            [22],       # SSH only
            [53, 67],   # DNS/DHCP
            [443, 8883], # HTTPS + MQTT TLS
            [22, 80, 443],  # SSH + Web
            [53, 80, 443],  # DNS + Web
            [67, 68],   # DHCP only
            [443, 53],  # HTTPS + DNS
            [22, 443],  # SSH + HTTPS
            [80, 53],   # HTTP + DNS
        ],
        "MEDIUM": [
            [80, 443, 554],  # Web + RTSP
            [22, 80, 443],   # SSH + Web
            [1883, 8883],    # MQTT + MQTT TLS
            [80, 443, 631],  # Web + Printer
            [22, 80, 8080],  # SSH + HTTP variants
            [80, 443, 53],   # Web + DNS
            [1883, 80, 443], # MQTT + Web
            [554, 80, 443],  # RTSP + Web
            [631, 80, 443],  # Printer + Web
            [22, 1883, 8883], # SSH + MQTT
        ],
        "HIGH": [
            [21, 80, 443],   # FTP + Web
            [23, 80],        # Telnet + Web
            [445, 139, 80],  # SMB + Web
            [161, 80, 443],  # SNMP + Web
            [21, 22, 80],    # FTP + SSH + Web
            [23, 80, 443],   # Telnet + Web
            [445, 80, 443],  # SMB + Web
            [161, 22, 80],   # SNMP + SSH + Web
            [3389, 80, 443], # RDP + Web
            [5900, 80, 443], # VNC + Web
        ],
        "CRITICAL": [
            [23, 21, 80],    # Telnet + FTP + Web
            [23, 2323, 80, 443],  # Multiple telnet + Web
            [502, 23, 80],   # Modbus + Telnet + Web
            [5900, 23, 80],  # VNC + Telnet + Web
            [23, 21, 445, 80], # Telnet + FTP + SMB + Web
            [23, 2323, 21, 80], # Multiple telnet + FTP + Web
            [502, 23, 2323, 80], # Modbus + telnet variants + Web
            [5900, 23, 21, 80], # VNC + Telnet + FTP + Web
            [23, 1883, 1900, 5555], # Telnet + IoT services
            [7547, 23, 80, 8080], # CWMP + Telnet + Web
        ],
    }

    # Generate more diverse training data (target: 15,000-20,000 samples)
    for label, profiles in profile_groups.items():
        # Use both original and IoT-specific profiles
        all_profiles = profiles + iot_profiles.get(label, [])
        samples_per_profile = 350 if label in ["LOW", "MEDIUM"] else 400  # More samples for critical/high risk

        for profile in all_profiles:
            for _ in range(samples_per_profile):
                ports = list(profile)
                # Add noise more intelligently
                noise_count = random.randint(0, 3) if label == "LOW" else random.randint(1, 5)
                for _ in range(noise_count):
                    if random.random() < 0.4:
                        ports.append(random.choice(optional_noise))

                # Add some realistic service combinations
                if 80 in ports and random.random() < 0.5:
                    if random.random() < 0.7:
                        ports.append(443)  # HTTPS with HTTP
                    if random.random() < 0.3:
                        ports.append(8080)  # Alt HTTP
                if 1883 in ports and random.random() < 0.7:
                    ports.append(8883)  # MQTT with MQTT-TLS
                if 22 in ports and random.random() < 0.2:
                    ports.append(80)  # SSH often with web

                ports = sorted(set(ports))
                scan = {"open_ports": ports, "services": _services_for_ports(ports)}

                # Add contextual data for more realistic training
                if random.random() < 0.15:  # 15% chance of having contextual issues
                    if label in ["HIGH", "CRITICAL"]:
                        scan["weak_credentials"] = ["default", "admin/admin", "root/root"]
                    if label == "CRITICAL":
                        scan["threat_indicators"] = ["unusual_traffic", "suspicious_connections"]
                    if random.random() < 0.3:
                        scan["config_issues"] = ["default_config", "outdated_firmware"]

                row = build_feature_row(scan)
                row["label"] = label
                rows.append(row)

    # Add extensive edge cases and anomalies (increased from 200 to 1000)
    for _ in range(1000):
        # Generate more varied unusual port combinations
        base_ports = []
        unusual_count = random.randint(2, 8)
        for _ in range(unusual_count):
            base_ports.append(random.randint(1, 65535))

        # Mix with some known risky ports more frequently
        risky_additions = []
        if random.random() < 0.4:
            risky_additions.extend(random.sample([23, 21, 161, 502, 5900, 7547], random.randint(1, 3)))
        if random.random() < 0.3:
            risky_additions.extend(random.sample([445, 139, 3389, 5555], random.randint(1, 2)))

        ports = sorted(set(base_ports + risky_additions))
        scan = {"open_ports": ports, "services": _services_for_ports(ports)}

        # Add contextual issues to anomalies
        if random.random() < 0.4:
            scan["threat_indicators"] = ["anomalous_ports", "unusual_service_combination"]
        if random.random() < 0.3:
            scan["weak_credentials"] = ["weak_passwords"]

        row = build_feature_row(scan)
        # Label based on risk factors with more nuance
        risk_score = rule_score(scan)[0]
        if risk_score >= 85:
            row["label"] = "CRITICAL"
        elif risk_score >= 65:
            row["label"] = "HIGH"
        elif risk_score >= 40:
            row["label"] = "MEDIUM"
        else:
            row["label"] = random.choice(["LOW", "MEDIUM"])
        rows.append(row)

    # Add specific IoT device patterns
    iot_device_patterns = [
        # Smart home devices
        ([80, 443, 8883, 1900], "LOW"),  # Smart bulb/hub
        ([22, 80, 443, 1883, 8883], "LOW"),  # Smart thermostat
        ([80, 443, 554, 1900], "MEDIUM"),  # IP Camera
        ([22, 80, 443, 1883, 1900], "MEDIUM"),  # Smart lock
        # Industrial IoT
        ([502, 80, 443, 161], "HIGH"),  # PLC/Controller
        ([502, 22, 80, 443], "HIGH"),  # Industrial gateway
        ([1883, 8883, 502, 80], "HIGH"),  # IoT gateway
        # Critical infrastructure
        ([23, 21, 80, 502, 7547], "CRITICAL"),  # Vulnerable router
        ([23, 2323, 21, 445, 80], "CRITICAL"),  # Compromised server
        ([5900, 23, 21, 80, 443], "CRITICAL"),  # Exposed management
    ]

    for ports, label in iot_device_patterns:
        for _ in range(200):  # 200 samples per pattern
            varied_ports = ports.copy()
            # Add some variation
            if random.random() < 0.3:
                varied_ports.extend(random.sample(optional_noise, random.randint(1, 3)))
            if random.random() < 0.4 and 80 in varied_ports:
                varied_ports.append(8080)

            scan = {"open_ports": sorted(set(varied_ports)), "services": _services_for_ports(varied_ports)}

            # Add contextual issues based on device type
            if label in ["HIGH", "CRITICAL"]:
                if random.random() < 0.6:
                    scan["weak_credentials"] = ["default_admin", "factory_reset"]
                if random.random() < 0.4:
                    scan["config_issues"] = ["exposed_management", "default_settings"]

            row = build_feature_row(scan)
            row["label"] = label
            rows.append(row)

    return pd.DataFrame(rows)


class RiskModel:
    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.classifier_path = self.model_dir / "risk_classifier.joblib"
        self.anomaly_path = self.model_dir / "anomaly_detector.joblib"
        self.metrics_path = self.model_dir / "training_metrics.json"
        self.classifier: RandomForestClassifier | None = None
        self.anomaly_detector: IsolationForest | None = None
        self.metrics: dict[str, Any] = {}
        self.ensure_loaded()

    def ensure_loaded(self) -> None:
        if self.classifier_path.exists() and self.anomaly_path.exists():
            self.classifier = load(self.classifier_path)
            self.anomaly_detector = load(self.anomaly_path)
            if self.metrics_path.exists():
                self.metrics = json.loads(self.metrics_path.read_text())

            if hasattr(self.classifier, "n_features_in_") and self.classifier.n_features_in_ != len(FEATURE_COLUMNS):
                self.train_bootstrap_model()
                return
            return
        self.train_bootstrap_model()

    def train_bootstrap_model(self) -> None:
        df = _bootstrap_rows()
        X = df[FEATURE_COLUMNS]
        y = df["label"]
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Enhanced Random Forest with better parameters
        self.classifier = RandomForestClassifier(
            n_estimators=500,  # Increased from 250
            max_depth=15,      # Increased from 10
            min_samples_split=4,
            min_samples_leaf=2,  # Added for better generalization
            max_features='sqrt',  # Added for feature selection
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,  # Use all available cores
        )
        self.classifier.fit(X_train, y_train)
        preds = self.classifier.predict(X_test)

        # Enhanced anomaly detector
        benign_baseline = df[df["label"].isin(["LOW", "MEDIUM"])][FEATURE_COLUMNS]
        self.anomaly_detector = IsolationForest(
            n_estimators=300,  # Increased from 200
            contamination=0.10,  # Adjusted from 0.12
            max_features=0.8,    # Added
            random_state=42,
        )
        self.anomaly_detector.fit(benign_baseline)

        # Add cross-validation for better evaluation
        from sklearn.model_selection import cross_val_score
        cv_scores = cross_val_score(self.classifier, X_train, y_train, cv=5, scoring='f1_weighted')
        cv_mean = float(np.mean(cv_scores))
        cv_std = float(np.std(cv_scores))

        self.metrics = {
            "bootstrap_rows": int(len(df)),
            "accuracy": round(float(accuracy_score(y_test, preds)), 4),
            "weighted_f1": round(float(f1_score(y_test, preds, average="weighted")), 4),
            "cv_mean_f1": round(cv_mean, 4),
            "cv_std_f1": round(cv_std, 4),
            "feature_columns": FEATURE_COLUMNS,
            "training_note": "Enhanced bootstrap model with diverse IoT profiles, edge cases, and cross-validation. Includes contextual features and improved anomaly detection.",
            "reference_datasets": [
                "UNSW-NB15",
                "Bot-IoT",
                "IoT-23",
                "CICIoT2023",
                "IoT-Network-Intrusion-Dataset",
            ],
            "model_params": {
                "n_estimators": 500,
                "max_depth": 15,
                "contamination": 0.10,
            },
        }

        dump(self.classifier, self.classifier_path)
        dump(self.anomaly_detector, self.anomaly_path)
        self.metrics_path.write_text(json.dumps(self.metrics, indent=2))

    def predict(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        if not self.classifier or not self.anomaly_detector:
            self.ensure_loaded()

        row = build_feature_row(scan)
        X = pd.DataFrame([row], columns=FEATURE_COLUMNS)
        probabilities = self.classifier.predict_proba(X)[0]
        labels = list(self.classifier.classes_)
        label_scores = {label: float(prob) for label, prob in zip(labels, probabilities)}
        ml_label = labels[int(np.argmax(probabilities))]
        ml_confidence = round(float(np.max(probabilities)), 4)

        anomaly_raw = float(self.anomaly_detector.score_samples(X)[0])
        anomaly_scaled = round(max(0.0, min(1.0, (0.2 - anomaly_raw) / 0.4)), 4)
        return {
            "ml_label": ml_label,
            "ml_confidence": ml_confidence,
            "anomaly_score": anomaly_scaled,
            "label_probabilities": label_scores,
            "features": row,
        }


def combine_assessment(scan: Dict[str, Any], ml_output: Dict[str, Any]) -> Dict[str, Any]:
    score, issues = rule_score(scan)
    context = contextual_findings(scan)
    score = min(100, score + context["bonus"])
    issues = _dedupe_text([*issues, *context["issues"]])

    ml_order_score = {label: idx for idx, label in enumerate(RISK_ORDER, start=1)}
    ml_scaled = ml_order_score.get(ml_output["ml_label"], 1) * 22
    anomaly_bonus = ml_output["anomaly_score"] * 20
    if context["threat_indicators"]:
        anomaly_bonus = max(anomaly_bonus, min(22, 8 + len(context["threat_indicators"]) * 3))
    final_score = min(100, round(score * 0.6 + ml_scaled * 0.3 + anomaly_bonus, 2))

    if final_score >= 80 or (23 in set(scan.get("open_ports", [])) and len(scan.get("open_ports", [])) >= 3):
        severity = "CRITICAL"
    elif final_score >= 60:
        severity = "HIGH"
    elif final_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if severity == "CRITICAL":
        issues = _dedupe_text([*issues, "Immediate remediation recommended for this device"])
    elif severity == "HIGH":
        issues = _dedupe_text([*issues, "Prompt remediation recommended for this device"])

    return {
        "risk": severity,
        "risk_score": final_score,
        "issues": issues,
        "weak_credentials": context["weak_credentials"],
        "config_issues": context["config_issues"],
        "threat_indicators": context["threat_indicators"],
        "traffic_profile": context["traffic_profile"],
        "ml_label": ml_output["ml_label"],
        "ml_confidence": ml_output["ml_confidence"],
        "anomaly_score": ml_output["anomaly_score"],
        "label_probabilities": ml_output["label_probabilities"],
        "features": ml_output["features"],
    }
