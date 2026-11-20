"""
Security Audit Report Generation Center.
Configures and renders downloadable executive PDF reports using ReportLab.
"""
from datetime import datetime
import streamlit as st
import pandas as pd
from utils.report_generator import SecurityReportGenerator, generate_cached_pdf_report
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ACCENT,
    COLOR_GREEN,
    APP_NAME,
)

def render_reports(analysis_results: dict):
    """Renders the executive report builder and PDF exporter."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">📄 Executive Security Reports</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Compile comprehensive compliance, forensics, and remediation audit documentation into downloadable PDF format.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    if not analysis_results:
        st.warning("No analysis findings available to compile report. Please analyze a dataset first.")
        return

    enriched_logs = analysis_results.get("enriched_logs", pd.DataFrame())
    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame())
    summary = analysis_results.get("dataset_summary", {})
    risk = analysis_results.get("risk_assessment", {})
    top_ips = analysis_results.get("top_suspicious_ips", [])
    recs = analysis_results.get("recommendations", [])

    col_cfg, col_prev = st.columns([1, 1.4])

    with col_cfg:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 20px;">
                <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 1rem; margin-bottom: 12px;">
                    Report Configuration
                </div>
            """,
            unsafe_allow_html=True
        )

        rep_title = st.text_input("Report Header Title", value="Cloud Security Threat & Audit Report")
        auditor_name = st.text_input("Auditor / Security Analyst", value="Lead SOC Analyst")
        
        st.markdown("**Sections to Include:**")
        inc_exec = st.checkbox("Executive Summary & Risk Level", value=True)
        inc_sev = st.checkbox("Severity Distribution Matrix", value=True)
        inc_vec = st.checkbox("Attack Vector Classifications", value=True)
        inc_ips = st.checkbox("Top Offending Hosts Dossier", value=True)
        inc_recs = st.checkbox("Tactical Remediation Guidance", value=True)

        st.markdown("</div>", unsafe_allow_html=True)
        st.write("")

        # Compile and generate PDF (cached)
        try:
            report_data = {
                "report_title": rep_title,
                "report_date": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
                "total_events": summary.get("total_records", len(enriched_logs)),
                "threats_detected": len(alerts_df),
                "suspicious_ips": alerts_df["source_ip"].nunique() if not alerts_df.empty else 0,
                "blocked_attempts": summary.get("blocked_attempts", 0),
                "risk_assessment": risk,
                "severity_counts": analysis_results.get("severity_counts", {}),
                "attack_categories": analysis_results.get("attack_categories", {}),
                "top_suspicious_ips": top_ips,
                "recommendations": recs,
            }
            pdf_bytes = generate_cached_pdf_report(report_data)

            st.download_button(
                label="📥 GENERATE & DOWNLOAD PDF AUDIT REPORT",
                data=pdf_bytes,
                file_name=f"soc_security_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )
        except Exception as e:
            st.error(f"PDF Generator notice: {e}")

    with col_prev:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 20px;">
                <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 1rem; margin-bottom: 12px;">
                    Report Content Summary
                </div>
                <div style="font-size: 0.85rem; color: {COLOR_MUTED}; line-height: 1.8;">
                    • <b>Document Title:</b> {rep_title}<br>
                    • <b>Total Events Inspected:</b> {summary.get('total_records', len(enriched_logs)):,} log entries<br>
                    • <b>Threat Signatures Flagged:</b> {len(alerts_df):,} detections<br>
                    • <b>Adversarial Hosts Isolated:</b> {alerts_df['source_ip'].nunique() if not alerts_df.empty else 0} distinct IP addresses<br>
                    • <b>Overall Risk Evaluation:</b> <span style="color: {risk.get('color', COLOR_GREEN)}; font-weight: bold;">{risk.get('level', 'LOW')} ({risk.get('percentage', 0)}%)</span><br>
                    • <b>Remediation Directives:</b> {len(recs)} prioritized controls
                </div>
                <div style="margin-top: 15px; padding: 12px; background: rgba(0, 168, 255, 0.08); border-left: 3px solid {COLOR_ACCENT}; border-radius: 6px; font-size: 0.8rem; color: {COLOR_TEXT};">
                    ℹ️ Built with Python <b>ReportLab</b>. Conforms to enterprise cybersecurity compliance guidelines.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
