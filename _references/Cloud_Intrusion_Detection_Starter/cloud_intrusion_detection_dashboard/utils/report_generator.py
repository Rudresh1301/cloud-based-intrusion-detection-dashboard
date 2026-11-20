"""
PDF Security Report Generator using ReportLab.
Produces comprehensive, publication-ready SOC audit reports with executive summaries,
attack distribution tables, top threats, and remediation recommendations.
"""
import io
import html
import logging
from datetime import datetime
import pandas as pd
import streamlit as st

log = logging.getLogger(__name__)

@st.cache_data(show_spinner=False)
def generate_cached_pdf_report(analysis_data: dict) -> bytes:
    """Cached wrapper around PDF generation to prevent re-compilation on every rerun."""
    generator = SecurityReportGenerator()
    return generator.generate_report(analysis_data)

class SecurityReportGenerator:
    """Generates PDF audit documentation for SOC operations."""

    def __init__(self):
        self.styles = None

    def generate_report(self, analysis_data: dict) -> bytes:
        """
        Creates a PDF report from analysis results.
        Returns: bytes of PDF document.
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
        except ImportError as e:
            log.error(f"ReportLab import failed: {e}")
            raise RuntimeError("ReportLab is not installed. Please install 'reportlab' to generate PDF reports.")

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
        
        # Custom styles matching SOC aesthetics
        PRIMARY_HEX = "#087FE5"
        DARK_BG = "#080D19"
        TEXT_DARK = "#1E293B"
        MUTED_TEXT = "#64748B"
        
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor(PRIMARY_HEX),
            spaceAfter=4
        )
        
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor(MUTED_TEXT),
            spaceAfter=15
        )
        
        h2_style = ParagraphStyle(
            'ReportH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0D1526"),
            spaceBefore=12,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor(TEXT_DARK)
        )

        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            textColor=colors.white
        )

        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor(TEXT_DARK)
        )

        story = []

        # ── Header ──────────────────────────────────────────────
        story.append(Paragraph("CLOUD-BASED INTRUSION DETECTION SYSTEM", title_style))
        report_date = html.escape(str(analysis_data.get("report_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))))
        story.append(Paragraph(f"CONFIDENTIAL SECURITY INCIDENT & THREAT AUDIT REPORT • {report_date}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor(PRIMARY_HEX), spaceAfter=15))

        # ── Executive Summary ───────────────────────────────────
        story.append(Paragraph("1. Executive Summary", h2_style))
        
        tot_events = analysis_data.get("total_events", 0)
        tot_threats = analysis_data.get("threats_detected", 0)
        susp_ips = analysis_data.get("suspicious_ips", 0)
        blocked = analysis_data.get("blocked_attempts", 0)
        risk_info = analysis_data.get("risk_assessment", {})
        risk_level = html.escape(str(risk_info.get("level", "EVALUATING")))
        risk_pct = risk_info.get("percentage", 0)

        exec_text = (
            f"This audit provides an evaluation of application access and network interaction logs "
            f"processed by the Cloud Intrusion Detection engine. A total of <b>{tot_events:,}</b> log transactions were "
            f"inspected. The detection engine identified <b>{tot_threats:,}</b> suspicious events and attack signatures across "
            f"<b>{susp_ips:,}</b> distinct source IP addresses. <b>{blocked:,}</b> malicious interactions were actively blocked. "
            f"The composite system threat posture is evaluated at <b>{risk_level} ({risk_pct}%)</b>."
        )
        story.append(Paragraph(exec_text, body_style))
        story.append(Spacer(1, 10))

        # Metric summary table
        kpi_data = [
            [
                Paragraph("<b>Total Logs Processed</b>", body_style),
                Paragraph(f"<b>{tot_events:,}</b>", body_style),
                Paragraph("<b>Threats Flagged</b>", body_style),
                Paragraph(f"<font color='#FF4560'><b>{tot_threats:,}</b></font>", body_style),
            ],
            [
                Paragraph("<b>Suspicious IPs</b>", body_style),
                Paragraph(f"<b>{susp_ips:,}</b>", body_style),
                Paragraph("<b>Blocked Attempts</b>", body_style),
                Paragraph(f"<font color='#00D68F'><b>{blocked:,}</b></font>", body_style),
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[2.0*inch, 1.4*inch, 2.0*inch, 1.4*inch])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 15))

        # ── Severity Breakdown Table ─────────────────────────────
        story.append(Paragraph("2. Threat Severity Breakdown", h2_style))
        sev_counts = analysis_data.get("severity_counts", {})
        
        sev_table_data = [
            [
                Paragraph("<b>Severity Tier</b>", table_header_style),
                Paragraph("<b>Detected Count</b>", table_header_style),
                Paragraph("<b>Proportion</b>", table_header_style),
                Paragraph("<b>Recommended Action</b>", table_header_style),
            ],
            [
                Paragraph("<font color='#FF4560'><b>CRITICAL</b></font>", body_style),
                Paragraph(f"{sev_counts.get('Critical', 0)}", body_style),
                Paragraph(f"{round(sev_counts.get('Critical', 0)/(tot_threats or 1)*100, 1)}%", body_style),
                Paragraph("Immediate IP containment and host credential rotation", body_style),
            ],
            [
                Paragraph("<font color='#FFB020'><b>HIGH</b></font>", body_style),
                Paragraph(f"{sev_counts.get('High', 0)}", body_style),
                Paragraph(f"{round(sev_counts.get('High', 0)/(tot_threats or 1)*100, 1)}%", body_style),
                Paragraph("Review target endpoints and tighten firewall ACLs", body_style),
            ],
            [
                Paragraph("<font color='#8B5CF6'><b>MEDIUM</b></font>", body_style),
                Paragraph(f"{sev_counts.get('Medium', 0)}", body_style),
                Paragraph(f"{round(sev_counts.get('Medium', 0)/(tot_threats or 1)*100, 1)}%", body_style),
                Paragraph("Apply request rate-limiting on offending IPs", body_style),
            ],
            [
                Paragraph("<font color='#00C8FF'><b>LOW</b></font>", body_style),
                Paragraph(f"{sev_counts.get('Low', 0)}", body_style),
                Paragraph(f"{round(sev_counts.get('Low', 0)/(tot_threats or 1)*100, 1)}%", body_style),
                Paragraph("Log for baseline trend analysis", body_style),
            ],
        ]
        sev_table = Table(sev_table_data, colWidths=[1.3*inch, 1.1*inch, 1.1*inch, 3.3*inch])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0D1526")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 15))

        # ── Attack Category Distribution ────────────────────────
        story.append(Paragraph("3. Detected Attack Vector Breakdown", h2_style))
        attack_cats = analysis_data.get("attack_categories", {})
        
        cat_rows = [
            [
                Paragraph("<b>Attack Classification</b>", table_header_style),
                Paragraph("<b>Incident Frequency</b>", table_header_style),
                Paragraph("<b>% of Total Threats</b>", table_header_style),
            ]
        ]
        
        if attack_cats:
            for cat, count in sorted(attack_cats.items(), key=lambda x: x[1], reverse=True)[:6]:
                pct = round(count / (tot_threats or 1) * 100, 1)
                cat_rows.append([
                    Paragraph(f"<b>{html.escape(str(cat))}</b>", table_cell_style),
                    Paragraph(f"{count}", table_cell_style),
                    Paragraph(f"{pct}%", table_cell_style),
                ])
        else:
            cat_rows.append([
                Paragraph("No classified attacks in current dataset", table_cell_style),
                Paragraph("0", table_cell_style),
                Paragraph("0%", table_cell_style),
            ])

        cat_table = Table(cat_rows, colWidths=[3.2*inch, 1.8*inch, 1.8*inch])
        cat_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0D1526")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(cat_table)
        story.append(Spacer(1, 15))

        # ── Top Suspicious IPs ──────────────────────────────────
        story.append(Paragraph("4. High-Priority Offending IP Addresses", h2_style))
        top_ips = analysis_data.get("top_suspicious_ips", [])
        
        ip_rows = [
            [
                Paragraph("<b>Source IP Address</b>", table_header_style),
                Paragraph("<b>Incidents</b>", table_header_style),
                Paragraph("<b>Max Severity</b>", table_header_style),
                Paragraph("<b>Target Endpoints / Signatures</b>", table_header_style),
            ]
        ]
        
        if top_ips:
            for item in top_ips[:5]:
                ip = html.escape(str(item.get("source_ip", "Unknown")))
                cnt = html.escape(str(item.get("count", item.get("alerts", 0))))
                sev = html.escape(str(item.get("severity", "High")))
                raw_evid = str(item.get("evidence", item.get("last_seen", "Multiple suspicious events")))[:50]
                evid = html.escape(raw_evid)
                ip_rows.append([
                    Paragraph(f"<code>{ip}</code>", table_cell_style),
                    Paragraph(f"{cnt}", table_cell_style),
                    Paragraph(f"<b>{sev}</b>", table_cell_style),
                    Paragraph(f"{evid}", table_cell_style),
                ])
        else:
            ip_rows.append([
                Paragraph("No suspicious IPs recorded", table_cell_style),
                Paragraph("0", table_cell_style),
                Paragraph("N/A", table_cell_style),
                Paragraph("Clean log sample", table_cell_style),
            ])

        ip_table = Table(ip_rows, colWidths=[1.8*inch, 1.0*inch, 1.2*inch, 2.8*inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0D1526")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 15))

        # ── Security Recommendations ────────────────────────────
        story.append(Paragraph("5. Tactical Remediation Recommendations", h2_style))
        recs = analysis_data.get("recommendations", [
            "Enforce IP Rate Limiting: Deploy WAF token-bucket filtering on /login and search query parameters.",
            "Account Lockout & MFA: Lock accounts after 5 consecutive failed authentications; mandate multi-factor auth.",
            "Input Sanitization & Output Encoding: Parameterize all SQL queries and sanitize HTML to neutralize XSS payloads.",
            "Perimeter Blocking: Place high-frequency offending IPs on firewall temporary deny-lists."
        ])
        for idx, rec in enumerate(recs[:4], start=1):
            story.append(Paragraph(f"<b>{idx}.</b> {html.escape(str(rec))}", body_style))
            story.append(Spacer(1, 3))

        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
        story.append(Paragraph(
            "Cloud-Based Intrusion Detection System • Educational Security Prototype • Generated via ReportLab Automation",
            subtitle_style
        ))

        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data
