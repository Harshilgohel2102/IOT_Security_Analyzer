from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app.ml_engine import FEATURE_COLUMNS, PORT_SERVICE_MAP, build_feature_row

LABEL_DISTRIBUTION = [
    ("LOW", 0.32),
    ("MEDIUM", 0.34),
    ("HIGH", 0.22),
    ("CRITICAL", 0.12),
]

COMMON_PATTERNS = {
    "LOW": [
        [80, 443],
        [22, 80, 443],
        [53, 80, 443],
        [80, 443, 8883],
        [53, 67],
    ],
    "MEDIUM": [
        [80, 8080],
        [1883, 80],
        [554, 80],
        [161, 80],
        [8080, 8443],
    ],
    "HIGH": [
        [445, 139],
        [3389, 445],
        [502, 80, 443],
        [1883, 8022],
        [5900, 80],
    ],
    "CRITICAL": [
        [23, 2323, 7547],
        [23, 21, 445, 80],
        [23, 2323, 5555],
        [23, 5900, 7547],
        [21, 23, 80, 8080],
    ],
}

NOISE_PORTS = list(range(1, 65536))


def _service_for_port(port: int) -> dict[str, Any]:
    service_name = PORT_SERVICE_MAP.get(port, "unknown")
    return {
        "port": port,
        "protocol": "tcp",
        "service": str(service_name).lower(),
        "product": "",
        "version": "",
    }


def _choose_label() -> str:
    value = random.random()
    cumulative = 0.0
    for label, weight in LABEL_DISTRIBUTION:
        cumulative += weight
        if value <= cumulative:
            return label
    return LABEL_DISTRIBUTION[-1][0]


def _sample_ports(base_ports: list[int], label: str) -> list[int]:
    ports = set(base_ports)
    noise_count = random.randint(1, 5)
    if random.random() < 0.75:
        available = [p for p in NOISE_PORTS if p not in ports]
        sampled = random.sample(available, noise_count)
        ports.update(sampled)

    if label == "CRITICAL" and random.random() < 0.35:
        ports.update(random.sample([23, 2323, 7547, 445, 21, 5900, 5555], 2))
    if label == "HIGH" and random.random() < 0.3:
        ports.update(random.sample([502, 3389, 445, 139, 5900, 5432], 2))

    # include at least one high-numbered port in many samples
    if random.random() < 0.4:
        ports.add(random.randint(1024, 65535))
    return sorted(ports)


def _generate_scan_row(label: str) -> dict[str, Any]:
    bases = COMMON_PATTERNS[label]
    base_ports = random.choice(bases)
    open_ports = _sample_ports(base_ports, label)
    scan = {
        "open_ports": open_ports,
        "services": [_service_for_port(p) for p in open_ports],
    }
    if label in {"HIGH", "CRITICAL"} and random.random() < 0.5:
        scan["weak_credentials"] = ["default_password", "admin:admin"]
    if label in {"HIGH", "CRITICAL"} and random.random() < 0.35:
        scan["config_issues"] = ["exposed_management", "outdated_firmware"]
    if label == "CRITICAL" and random.random() < 0.4:
        scan["threat_indicators"] = ["command_and_control", "suspicious_payload"]

    row = build_feature_row(scan)
    row["label"] = label
    return row


def generate_dataset(output_path: Path, rows: int = 200_000) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    header = FEATURE_COLUMNS + ["label"]
    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)
        for _ in range(rows):
            label = _choose_label()
            row = _generate_scan_row(label)
            writer.writerow([row[col] for col in header])
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic training dataset for IoT security risk assessment.")
    parser.add_argument("--rows", type=int, default=200_000, help="Number of dataset rows to generate")
    parser.add_argument("--output", type=Path, default=BASE_DIR / "data" / "iot_training_dataset.csv")
    args = parser.parse_args()

    output_path = generate_dataset(args.output, args.rows)
    print(f"Generated dataset: {output_path} ({args.rows} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
