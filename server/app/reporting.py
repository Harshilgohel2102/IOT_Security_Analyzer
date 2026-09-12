from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def create_csv_report(scans: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp",
        "Device IP",
        "Hostname",
        "Vendor",
        "Risk",
        "Risk Score",
        "ML Label",
        "ML Confidence",
        "Anomaly Score",
        "Open Ports",
        "Issues",
        "Weak Credential Findings",
        "Configuration Issues",
        "Threat Indicators",
    ])
    for scan in scans:
        writer.writerow([
            scan.get("timestamp", ""),
            scan.get("device_ip", ""),
            scan.get("hostname", ""),
            scan.get("vendor", ""),
            scan.get("risk", ""),
            scan.get("risk_score", ""),
            scan.get("ml_label", ""),
            scan.get("ml_confidence", ""),
            scan.get("anomaly_score", ""),
            ", ".join(str(p) for p in scan.get("open_ports", [])),
            " | ".join(scan.get("issues", [])),
            " | ".join(scan.get("weak_credentials", [])),
            " | ".join(scan.get("config_issues", [])),
            " | ".join(scan.get("threat_indicators", [])),
        ])
    return output.getvalue()


def create_json_report(scans: list[dict[str, Any]], stats: dict[str, Any]) -> str:
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "stats": stats,
        "scans": scans,
    }
    return json.dumps(payload, indent=2)


def create_pdf_report(scans: list[dict[str, Any]], stats: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title = Paragraph("IoT Security Analyzer - Security Report", styles["Title"])
    story.append(title)
    story.append(Spacer(1, 20))
    
    # Generation info
    story.append(Paragraph(f"Generated at: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
    story.append(Paragraph(f"Report covers {len(scans)} devices from {stats.get('total_scans', 0)} total scans", styles["Normal"]))
    story.append(Spacer(1, 20))

    # Executive Summary
    summary_title = Paragraph("Executive Summary", styles["Heading2"])
    story.append(summary_title)
    story.append(Spacer(1, 10))
    
    summary_data = [
        ["Metric", "Value", "Description"],
        ["Total Devices Scanned", str(stats.get("total_devices", 0)), "Unique devices identified"],
        ["Total Scans Performed", str(stats.get("total_scans", 0)), "Individual scan operations"],
        ["Critical Risk Devices", str(stats.get("critical_risk", 0)), "Devices requiring immediate attention"],
        ["High Risk Devices", str(stats.get("high_risk", 0)), "Devices with significant vulnerabilities"],
        ["Devices with Weak Credentials", str(stats.get("weak_credential_devices", 0)), "Devices with default or weak passwords"],
        ["Devices with Config Issues", str(stats.get("config_issue_devices", 0)), "Devices with configuration problems"],
        ["Devices with Threat Indicators", str(stats.get("threat_indicator_devices", 0)), "Devices showing suspicious activity"],
    ]
    
    summary_table = Table(summary_data, colWidths=[120, 60, 200])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12214b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(summary_table)
    story.append(Spacer(1, 25))

    # Risk Distribution Chart (Text-based)
    risk_title = Paragraph("Risk Distribution", styles["Heading2"])
    story.append(risk_title)
    story.append(Spacer(1, 10))
    
    total = max(1, stats.get("total_devices", 0))
    risk_data = [
        ["Risk Level", "Count", "Percentage"],
        ["Critical", str(stats.get("critical_risk", 0)), f"{(stats.get('critical_risk', 0) / total) * 100:.1f}%"],
        ["High", str(stats.get("high_risk", 0)), f"{(stats.get('high_risk', 0) / total) * 100:.1f}%"],
        ["Medium", str(stats.get("medium_risk", 0)), f"{(stats.get('medium_risk', 0) / total) * 100:.1f}%"],
        ["Low", str(stats.get("low_risk", 0)), f"{(stats.get('low_risk', 0) / total) * 100:.1f}%"],
    ]
    
    risk_table = Table(risk_data, colWidths=[80, 50, 70])
    risk_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dc3545")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffcccc")),
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fff3cd")),
            ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#d1ecf1")),
            ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#d4edda")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(risk_table)
    story.append(Spacer(1, 25))

    # Device Details
    details_title = Paragraph("Device Details", styles["Heading2"])
    story.append(details_title)
    story.append(Spacer(1, 10))
    
    # Only show top 25 devices to keep report manageable
    display_scans = scans[:25]
    
    table_data = [["IP Address", "Hostname", "Risk Level", "Risk Score", "Open Ports", "Key Findings"]]
    
    for scan in display_scans:
        # Sanitize and truncate data for PDF
        ip = str(scan.get("device_ip", ""))[:15]
        hostname = str(scan.get("hostname", "-") or "-")[:20]
        risk = str(scan.get("risk", ""))[:10]
        score = str(scan.get("risk_score", ""))[:6]
        
        # Format ports
        ports = scan.get("open_ports", [])
        if isinstance(ports, list):
            ports_str = ", ".join(str(p) for p in ports[:8])  # Limit to 8 ports
            if len(ports) > 8:
                ports_str += f" (+{len(ports) - 8} more)"
        else:
            ports_str = str(ports)[:30]
        
        # Compile key findings
        findings = []
        issues = scan.get("issues", [])
        if issues:
            findings.extend([str(issue)[:40] for issue in issues[:2]])
        
        weak_creds = scan.get("weak_credentials", [])
        if weak_creds:
            findings.extend([f"Cred: {str(cred)[:35]}" for cred in weak_creds[:1]])
        
        threats = scan.get("threat_indicators", [])
        if threats:
            findings.extend([f"Threat: {str(threat)[:35]}" for threat in threats[:1]])
        
        findings_str = " | ".join(findings) if findings else "No significant findings"
        findings_str = findings_str[:80]  # Truncate for table
        
        table_data.append([ip, hostname, risk, score, ports_str, findings_str])

    # Create table with better column widths
    detail_table = Table(table_data, repeatRows=1, colWidths=[70, 80, 55, 50, 90, 140])
    detail_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12214b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(detail_table)
    
    if len(scans) > 25:
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Note: Showing 25 of {len(scans)} devices. Download CSV for complete dataset.", styles["Italic"]))
    
    story.append(Spacer(1, 20))
    story.append(Paragraph("This report was generated by IoT Security Analyzer. For more details, visit the web dashboard.", styles["Italic"]))

    doc.build(story)
    return buffer.getvalue()
