import io
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from app.database.db_service import db_service

log = logging.getLogger(__name__)

class ReportGenerator:
    """Generates publication-ready SOC Executive & Technical PDF Security Audit Reports."""

    def generate_pdf(self, title: str = "SOC Security Audit & Threat Intelligence Report") -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Palette matching the SOC Dark & Professional Blue Theme
        PRIMARY_HEX = "#087FE5"
        CYAN_HEX = "#00C8FF"
        DARK_TEXT = "#0F172A"
        MUTED_TEXT = "#475569"
        CRITICAL_RED = "#FF4560"

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor(PRIMARY_HEX),
            spaceAfter=4,
        )

        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor(MUTED_TEXT),
            spaceAfter=12,
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor(DARK_TEXT),
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor(DARK_TEXT),
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor(DARK_TEXT),
        )

        # Retrieve actual database metrics
        logs_res = db_service.get_logs(page=1, page_size=1000)
        alerts_res = db_service.get_alerts(page=1, page_size=500)
        ips = db_service.get_ip_intel_list()

        total_logs = logs_res["total"]
        alerts = alerts_res["items"]
        total_threats = len(alerts)
        now_str = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")

        story = []

        # Header Block
        story.append(Paragraph("CLOUD-BASED INTRUSION DETECTION DASHBOARD", title_style))
        story.append(Paragraph(f"Executive Threat Intelligence & SOC Audit Report | Generated: {now_str}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor(PRIMARY_HEX), spaceAfter=14))

        # Executive Summary Metrics
        crit_count = sum(1 for a in alerts if a.get("severity") == "Critical")
        high_count = sum(1 for a in alerts if a.get("severity") == "High")
        med_count = sum(1 for a in alerts if a.get("severity") == "Medium")
        low_count = sum(1 for a in alerts if a.get("severity") == "Low")
        suspicious_ips_count = len([ip for ip in ips if ip.get("risk_score", 0) > 0])

        summary_data = [
            [
                Paragraph("<b>Total Events Audited</b>", table_header_style),
                Paragraph("<b>Threats Detected</b>", table_header_style),
                Paragraph("<b>Critical Incidents</b>", table_header_style),
                Paragraph("<b>Suspicious IPs</b>", table_header_style),
                Paragraph("<b>Cloud Storage Status</b>", table_header_style),
            ],
            [
                Paragraph(f"<b>{total_logs:,}</b>", table_cell_style),
                Paragraph(f"<b>{total_threats:,}</b>", table_cell_style),
                Paragraph(f"<font color='{CRITICAL_RED}'><b>{crit_count}</b></font>", table_cell_style),
                Paragraph(f"<b>{suspicious_ips_count}</b>", table_cell_style),
                Paragraph(f"<b>{db_service.active_storage_provider.split(' ')[0]}</b>", table_cell_style),
            ]
        ]
        summary_table = Table(summary_data, colWidths=[108, 108, 108, 108, 108])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(PRIMARY_HEX)),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#F1F5F9")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 14))

        # Threat Severity & Category Distribution
        story.append(Paragraph("Threat Severity Breakdown", h2_style))
        sev_data = [
            [Paragraph("<b>Severity</b>", table_header_style), Paragraph("<b>Incident Count</b>", table_header_style), Paragraph("<b>Ratio</b>", table_header_style)],
            [Paragraph("Critical", table_cell_style), Paragraph(str(crit_count), table_cell_style), Paragraph(f"{(crit_count/max(1, total_threats))*100:.1f}%", table_cell_style)],
            [Paragraph("High", table_cell_style), Paragraph(str(high_count), table_cell_style), Paragraph(f"{(high_count/max(1, total_threats))*100:.1f}%", table_cell_style)],
            [Paragraph("Medium", table_cell_style), Paragraph(str(med_count), table_cell_style), Paragraph(f"{(med_count/max(1, total_threats))*100:.1f}%", table_cell_style)],
            [Paragraph("Low", table_cell_style), Paragraph(str(low_count), table_cell_style), Paragraph(f"{(low_count/max(1, total_threats))*100:.1f}%", table_cell_style)],
        ]
        sev_table = Table(sev_data, colWidths=[180, 180, 180])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 14))

        # Top Hostile IP Addresses
        story.append(Paragraph("Top Suspicious & Malicious Source IP Addresses", h2_style))
        top_ips = ips[:8]
        if top_ips:
            ip_table_data = [
                [
                    Paragraph("<b>IP Address</b>", table_header_style),
                    Paragraph("<b>Risk Score</b>", table_header_style),
                    Paragraph("<b>Threat Level</b>", table_header_style),
                    Paragraph("<b>Suspicious Events</b>", table_header_style),
                    Paragraph("<b>Location / ISP</b>", table_header_style),
                ]
            ]
            for item in top_ips:
                loc = f"{item.get('city', 'Local')}, {item.get('country', 'Private')}"
                ip_table_data.append([
                    Paragraph(str(item["ip_address"]), table_cell_style),
                    Paragraph(f"{item.get('risk_score', 0)}/100", table_cell_style),
                    Paragraph(str(item.get("threat_status", "Low")), table_cell_style),
                    Paragraph(str(item.get("suspicious_events", 0)), table_cell_style),
                    Paragraph(loc, table_cell_style),
                ])
            ip_table = Table(ip_table_data, colWidths=[110, 70, 80, 100, 180])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(ip_table)
        else:
            story.append(Paragraph("No suspicious IP addresses observed in processed logs.", body_style))

        story.append(Spacer(1, 14))

        # Critical Security Incidents
        story.append(Paragraph("Recent Priority Security Alerts", h2_style))
        top_alerts = alerts[:10]
        if top_alerts:
            alerts_data = [
                [
                    Paragraph("<b>Timestamp</b>", table_header_style),
                    Paragraph("<b>Source IP</b>", table_header_style),
                    Paragraph("<b>Attack Type</b>", table_header_style),
                    Paragraph("<b>Severity</b>", table_header_style),
                    Paragraph("<b>Evidence / Target</b>", table_header_style),
                ]
            ]
            for a in top_alerts:
                alerts_data.append([
                    Paragraph(str(a.get("timestamp", ""))[-8:], table_cell_style),
                    Paragraph(str(a.get("source_ip", "")), table_cell_style),
                    Paragraph(str(a.get("alert_type", "")), table_cell_style),
                    Paragraph(str(a.get("severity", "")), table_cell_style),
                    Paragraph(str(a.get("evidence", ""))[:45], table_cell_style),
                ])
            alerts_table = Table(alerts_data, colWidths=[70, 90, 130, 60, 190])
            alerts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(alerts_table)
        else:
            story.append(Paragraph("Zero unacknowledged security alerts.", body_style))

        story.append(Spacer(1, 14))

        # SOC Strategic Recommendations
        story.append(Paragraph("Strategic Cloud Security Recommendations", h2_style))
        recs = [
            "1. <b>Credential Spraying Defense:</b> Implement progressive IP rate limiting and adaptive MFA verification on login endpoints.",
            "2. <b>WAF Rule Update:</b> Enforce strict parameterized SQL validation and deny common SQL syntax patterns (UNION, OR 1=1) at Cloud CDN edge.",
            "3. <b>Administrative Endpoint Isolation:</b> Move sensitive path interfaces (/admin, /actuator, /.env) behind private VPN or Cloud Identity-Aware Proxy.",
            "4. <b>Cloud Object Storage Encryption:</b> Ensure all ingested security logs and reports in Cloud Storage have server-side encryption (SSE-KMS) enabled.",
        ]
        for r in recs:
            story.append(Paragraph(r, body_style))
            story.append(Spacer(1, 4))

        doc.build(story)
        return buffer.getvalue()

    def create_and_store_report(self, title: str = "SOC Security Audit & Threat Intelligence Report") -> Dict[str, Any]:
        pdf_bytes = self.generate_pdf(title)
        report_id = f"rep-{uuid.uuid4().hex[:8]}"
        filename = f"soc_security_audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"

        # Save to Storage (Cloud or fallback)
        storage_meta = db_service.storage_service.save_report_pdf(filename, pdf_bytes)

        # Get summary numbers
        logs = db_service.get_logs(page=1, page_size=1)
        alerts = db_service.get_alerts(page=1, page_size=1)

        report_record = {
            "id": report_id,
            "filename": filename,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": logs["total"],
            "threats_found": alerts["total"],
            "risk_level": "HIGH RISK" if alerts["total"] > 10 else "MEDIUM RISK",
            "file_path": storage_meta["file_path"],
            "storage_type": storage_meta["storage_type"]
        }
        db_service.save_report(report_record)

        return {
            "id": report_id,
            "filename": filename,
            "generated_at": report_record["generated_at"],
            "download_url": storage_meta["download_url"],
            "storage_type": storage_meta["storage_type"],
            "total_events": logs["total"],
            "threats_found": alerts["total"],
            "pdf_bytes": pdf_bytes
        }

report_generator = ReportGenerator()
