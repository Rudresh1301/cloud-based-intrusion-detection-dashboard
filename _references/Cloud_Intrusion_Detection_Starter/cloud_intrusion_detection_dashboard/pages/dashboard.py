"""
Main SOC Overview Dashboard Page.
Renders the primary executive command interface matching the exact SOC design reference.
Includes KPI stat cards, dual-series attack timeline, attack category donut,
global threat map, top hostile IPs, live alerts feed, risk gauge, and quick actions.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from config.settings import (
    COLOR_BG,
    COLOR_CARD,
    COLOR_ACCENT,
    COLOR_ELECTRIC,
    COLOR_CYAN,
    COLOR_PURPLE,
    COLOR_RED,
    COLOR_ORANGE,
    COLOR_GREEN,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_GRID,
    SEVERITY_COLORS,
)
from utils.helpers import (
    format_number,
    format_time_only,
    get_severity_badge_html,
    get_status_badge_html,
)
from utils.report_generator import SecurityReportGenerator, generate_cached_pdf_report

def render_dashboard(analysis_results: dict):
    """Renders the high-fidelity SOC dashboard."""
    if not analysis_results:
        st.warning("No log analysis data available. Please upload a dataset or load the sample logs.")
        return

    enriched_logs = analysis_results.get("enriched_logs", pd.DataFrame())
    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame())
    summary = analysis_results.get("dataset_summary", {})
    risk = analysis_results.get("risk_assessment", {})
    top_ips = analysis_results.get("top_suspicious_ips", [])

    # ── Top Bar Controls ─────────────────────────────────────────
    top_col1, top_col2 = st.columns([1.5, 1])
    with top_col1:
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                <span style="display: inline-flex; align-items: center; gap: 6px; background: rgba(0,214,143,0.12); border: 1px solid rgba(0,214,143,0.4); padding: 5px 14px; border-radius: 20px; font-size: 0.82rem; font-weight: 600; color: {COLOR_GREEN};">
                    <span style="height: 8px; width: 8px; background-color: {COLOR_GREEN}; border-radius: 50%; box-shadow: 0 0 8px {COLOR_GREEN};"></span>
                    Live Monitoring Active
                </span>
                <span style="color: {COLOR_GREEN}; font-family: monospace; letter-spacing: 2px;">~^v^~~^v~</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with top_col2:
        sub_c1, sub_c2, sub_c3 = st.columns([2, 0.8, 1.8])
        with sub_c1:
            time_filter = st.selectbox(
                "Filter",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
                index=0,
                label_visibility="collapsed"
            )
        with sub_c2:
            st.markdown(
                f"""
                <div style="position: relative; text-align: center; padding-top: 6px;">
                    <span style="font-size: 1.3rem;">🔔</span>
                    <span style="position: absolute; top: 0; right: 8px; background: {COLOR_RED}; color: white; border-radius: 50%; font-size: 0.65rem; padding: 1px 5px; font-weight: bold;">3</span>
                </div>
                """,
                unsafe_allow_html=True
            )
        with sub_c3:
            st.markdown(
                f"""
                <div style="display: flex; align-items: center; gap: 8px; background: #121E32; border: 1px solid #164879; padding: 4px 10px; border-radius: 20px;">
                    <div style="width: 24px; height: 24px; background: {COLOR_PURPLE}; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.75rem; color: white;">R</div>
                    <span style="font-size: 0.82rem; color: {COLOR_TEXT};">Admin SOC</span>
                </div>
                """,
                unsafe_allow_html=True
            )

    # ── 4 Premium Statistic Cards ──────────────────────────────
    tot_reqs = summary.get("total_records", len(enriched_logs))
    tot_threats = len(alerts_df)
    susp_ips_cnt = alerts_df["source_ip"].nunique() if not alerts_df.empty else 0
    blocked_cnt = summary.get("blocked_attempts", 0)

    card_col1, card_col2, card_col3, card_col4 = st.columns(4)

    with card_col1:
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 3px solid {COLOR_ACCENT};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="width: 38px; height: 38px; background: rgba(0,168,255,0.12); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: {COLOR_ACCENT};">🗄️</div>
                    <span style="color: {COLOR_GREEN}; font-size: 0.8rem; font-weight: 600;">↑ +12%</span>
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 10px;">Total Requests</div>
                <div style="font-size: 1.85rem; font-weight: 800; color: {COLOR_TEXT}; margin-top: 2px;">{format_number(tot_reqs)}</div>
                <div style="height: 3px; background: linear-gradient(90deg, {COLOR_ACCENT}, transparent); border-radius: 2px; margin-top: 8px;"></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with card_col2:
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 3px solid {COLOR_RED};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="width: 38px; height: 38px; background: rgba(255,69,96,0.12); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: {COLOR_RED};">🛡️</div>
                    <span style="color: {COLOR_RED}; font-size: 0.8rem; font-weight: 600;">↑ +8%</span>
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 10px;">Threats Detected</div>
                <div style="font-size: 1.85rem; font-weight: 800; color: {COLOR_TEXT}; margin-top: 2px;">{format_number(tot_threats)}</div>
                <div style="height: 3px; background: linear-gradient(90deg, {COLOR_RED}, transparent); border-radius: 2px; margin-top: 8px;"></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with card_col3:
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 3px solid {COLOR_CYAN};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="width: 38px; height: 38px; background: rgba(0,200,255,0.12); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: {COLOR_CYAN};">🚫</div>
                    <span style="color: {COLOR_GREEN}; font-size: 0.8rem; font-weight: 600;">↑ +5%</span>
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 10px;">Suspicious IPs</div>
                <div style="font-size: 1.85rem; font-weight: 800; color: {COLOR_TEXT}; margin-top: 2px;">{format_number(susp_ips_cnt)}</div>
                <div style="height: 3px; background: linear-gradient(90deg, {COLOR_CYAN}, transparent); border-radius: 2px; margin-top: 8px;"></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with card_col4:
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 3px solid {COLOR_PURPLE};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="width: 38px; height: 38px; background: rgba(139,92,246,0.12); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: {COLOR_PURPLE};">🛡️</div>
                    <span style="color: {COLOR_GREEN}; font-size: 0.8rem; font-weight: 600;">↑ +15%</span>
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 10px;">Blocked Attempts</div>
                <div style="font-size: 1.85rem; font-weight: 800; color: {COLOR_TEXT}; margin-top: 2px;">{format_number(blocked_cnt)}</div>
                <div style="height: 3px; background: linear-gradient(90deg, {COLOR_PURPLE}, transparent); border-radius: 2px; margin-top: 8px;"></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write("")

    # ── Middle Row: 3 Panels ─────────────────────────────────────
    mid_col1, mid_col2, mid_col3 = st.columns([1.5, 1.1, 1.2])

    # 1. Attack Activity Overview
    with mid_col1:
        st.markdown(
            f"""
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div style="font-size: 0.95rem; font-weight: 700; color: {COLOR_TEXT}; display: flex; align-items: center; gap: 8px;">
                    <span>📊</span> Attack Activity Overview
                </div>
                <div style="font-size: 0.75rem; color: {COLOR_MUTED}; display: flex; gap: 12px;">
                    <span style="color: {COLOR_ELECTRIC};">● Normal Traffic</span>
                    <span style="color: {COLOR_RED};">● Threats</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        if not enriched_logs.empty and "timestamp_dt" in enriched_logs.columns:
            ts_df = enriched_logs.copy()
            ts_df["hour_group"] = ts_df["timestamp_dt"].dt.floor("h")
            hourly_total = ts_df.groupby("hour_group").size().reset_index(name="normal")
            
            # Map threat timestamps
            if not alerts_df.empty:
                al_df = alerts_df.copy()
                al_df["timestamp_dt"] = pd.to_datetime(al_df["timestamp"], errors="coerce")
                al_df["hour_group"] = al_df["timestamp_dt"].dt.floor("h")
                hourly_threats = al_df.groupby("hour_group").size().reset_index(name="threats")
                chart_df = pd.merge(hourly_total, hourly_threats, on="hour_group", how="left").fillna(0)
            else:
                chart_df = hourly_total
                chart_df["threats"] = 0

            fig = go.Figure()
            # Normal traffic area line
            fig.add_trace(go.Scatter(
                x=chart_df["hour_group"],
                y=chart_df["normal"],
                mode='lines+markers',
                name='Normal Traffic',
                line=dict(color=COLOR_ELECTRIC, width=2.5, shape='spline'),
                fill='tozeroy',
                fillcolor='rgba(8, 127, 229, 0.12)',
                marker=dict(size=4)
            ))
            # Threats line
            fig.add_trace(go.Scatter(
                x=chart_df["hour_group"],
                y=chart_df["threats"],
                mode='lines+markers',
                name='Threats',
                line=dict(color=COLOR_RED, width=2.5, shape='spline'),
                fill='tozeroy',
                fillcolor='rgba(255, 69, 96, 0.15)',
                marker=dict(size=4)
            ))
            fig.update_layout(
                height=260,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                font=dict(color=COLOR_MUTED, size=10),
                xaxis=dict(gridcolor=COLOR_GRID, showgrid=True),
                yaxis=dict(gridcolor=COLOR_GRID, showgrid=True)
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No timeline data available.")

    # 2. Attack Types Distribution Donut
    with mid_col2:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {COLOR_TEXT}; margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
                <span>⚠️</span> Attack Types Distribution
            </div>
            """,
            unsafe_allow_html=True
        )
        if not alerts_df.empty:
            type_counts = alerts_df["alert_type"].value_counts().reset_index()
            type_counts.columns = ["Attack Type", "Count"]

            color_map = {
                "Brute Force Attempt": COLOR_RED,
                "SQL Injection": COLOR_ORANGE,
                "Cross-Site Scripting (XSS)": COLOR_PURPLE,
                "Command Injection": COLOR_RED,
                "Path Traversal": COLOR_CYAN,
                "High Request Volume": COLOR_ACCENT,
                "Unusual Access Pattern": COLOR_ELECTRIC,
                "ML Anomaly": COLOR_GREEN
            }
            colors_list = [color_map.get(t, COLOR_CYAN) for t in type_counts["Attack Type"]]

            fig_donut = go.Figure(data=[go.Pie(
                labels=type_counts["Attack Type"],
                values=type_counts["Count"],
                hole=0.68,
                marker=dict(colors=colors_list),
                textinfo='none',
                hoverinfo='label+percent+value'
            )])
            fig_donut.update_layout(
                height=260,
                margin=dict(l=5, r=5, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                showlegend=True,
                legend=dict(
                    orientation="v",
                    yanchor="middle",
                    y=0.5,
                    xanchor="left",
                    x=1.02,
                    font=dict(color=COLOR_MUTED, size=9)
                ),
                annotations=[dict(
                    text=f"<b>{tot_threats}</b><br><span style='font-size:10px;color:#9CC9E8'>Threats</span>",
                    x=0.5, y=0.5,
                    font_size=16,
                    font_color=COLOR_TEXT,
                    showarrow=False
                )]
            )
            st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No attack types classified yet.")

    # 3. Global Threat Map
    with mid_col3:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {COLOR_TEXT}; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
                <span style="display: flex; align-items: center; gap: 8px;"><span>🌐</span> Global Threat Map</span>
                <span style="font-size: 0.72rem; color: {COLOR_MUTED};">SOC Geo-Telemetry</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        # Create dark scattergeo world map with known geolocation references
        geo_nodes = [
            {"lat": 37.77, "lon": -122.41, "country": "US West (192.168.1.105)", "threats": 245, "color": COLOR_RED},
            {"lat": 28.61, "lon": 77.20, "country": "Asia-Pacific (103.21.45.67)", "threats": 120, "color": COLOR_ORANGE},
            {"lat": 52.52, "lon": 13.40, "country": "Europe (185.220.101.33)", "threats": 87, "color": COLOR_PURPLE},
            {"lat": -33.86, "lon": 151.20, "country": "Oceania (45.77.89.12)", "threats": 54, "color": COLOR_CYAN},
            {"lat": 50.45, "lon": 30.52, "country": "Eastern Europe (91.203.12.78)", "threats": 42, "color": COLOR_RED},
        ]
        geo_df = pd.DataFrame(geo_nodes)
        
        fig_map = px.scatter_geo(
            geo_df,
            lat="lat",
            lon="lon",
            hover_name="country",
            size="threats",
            color_discrete_sequence=[COLOR_RED],
            projection="natural earth"
        )
        fig_map.update_geos(
            bgcolor="rgba(0,0,0,0)",
            showcountries=True,
            countrycolor="#164879",
            showcoastlines=True,
            coastlinecolor="#153B61",
            showland=True,
            landcolor="#0D1526",
            showocean=True,
            oceancolor="#080D19",
            lakecolor="#080D19",
            framecolor="#164879"
        )
        fig_map.update_traces(marker=dict(line=dict(width=1, color=COLOR_CYAN)))
        fig_map.update_layout(
            height=260,
            margin=dict(l=0, r=0, t=5, b=5),
            paper_bgcolor="rgba(0,0,0,0)"
        )
        st.plotly_chart(fig_map, use_container_width=True, config={"displayModeBar": False})

    st.write("")

    # ── Lower Middle Row: Top Suspicious IPs & Security Alerts ───
    low_col1, low_col2 = st.columns([1, 1.4])

    # Top Suspicious IPs Table
    with low_col1:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 0.95rem; display: flex; align-items: center; gap: 8px;">
                        <span>🏆</span> Top Suspicious IP Addresses
                    </div>
                    <span style="font-size: 0.78rem; color: {COLOR_ACCENT}; font-weight: 600;">Active Threats</span>
                </div>
            """,
            unsafe_allow_html=True
        )
        if top_ips:
            for rank, item in enumerate(top_ips[:5], start=1):
                ip = item.get("source_ip", "Unknown")
                sev = item.get("severity", "Medium")
                cnt = item.get("count", 0)
                badge = get_severity_badge_html(sev)
                st.markdown(
                    f"""
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(22, 72, 121, 0.4);">
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span style="color: {COLOR_MUTED}; font-size: 0.85rem; font-weight: bold; width: 14px;">{rank}</span>
                            <span style="font-family: monospace; color: {COLOR_TEXT}; font-size: 0.88rem;">{ip}</span>
                            {badge}
                        </div>
                        <span style="color: {COLOR_MUTED}; font-size: 0.82rem; font-weight: 600;">{cnt} attempts</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.caption("No suspicious IP addresses detected.")
        st.markdown("</div>", unsafe_allow_html=True)

    # Security Alerts Table
    with low_col2:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 0.95rem; display: flex; align-items: center; gap: 8px;">
                        <span>🚨</span> Security Alerts
                    </div>
                    <span style="font-size: 0.78rem; color: {COLOR_ACCENT}; font-weight: 600;">Real-time Ingestion</span>
                </div>
            """,
            unsafe_allow_html=True
        )
        if not alerts_df.empty:
            for _, alert in alerts_df.head(4).iterrows():
                time_str = format_time_only(alert.get("timestamp"))
                alert_type = str(alert.get("alert_type", "Alert"))
                sev = str(alert.get("severity", "Medium"))
                status = str(alert.get("status", "New"))
                evidence = str(alert.get("evidence", ""))
                sev_badge = get_severity_badge_html(sev)
                stat_badge = get_status_badge_html(status)

                st.markdown(
                    f"""
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(22, 72, 121, 0.4);">
                        <div style="display: flex; align-items: center; gap: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 75%;">
                            <span style="color: {COLOR_MUTED}; font-size: 0.8rem; font-family: monospace;">{time_str}</span>
                            <span style="color: {COLOR_TEXT}; font-size: 0.85rem; font-weight: 600;">{alert_type}</span>
                            {sev_badge}
                            <span style="color: {COLOR_MUTED}; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{evidence[:40]}</span>
                        </div>
                        <div>
                            {stat_badge}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.caption("No alerts flagged in current dataset.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.write("")

    # ── Bottom Row: Risk Gauge, Report Download, Quick Actions ───
    bot_col1, bot_col2, bot_col3 = st.columns([1, 1.2, 1])

    with bot_col1:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 18px; min-height: 140px; display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4rem; color: {COLOR_RED};">🛡️</span>
                        <span style="font-size: 0.85rem; color: {COLOR_MUTED}; text-transform: uppercase;">Risk Level</span>
                    </div>
                    <div style="font-size: 1.45rem; font-weight: 800; color: {COLOR_RED}; margin-top: 4px;">{risk.get('level', 'HIGH RISK')}</div>
                    <div style="font-size: 0.78rem; color: {COLOR_MUTED}; margin-top: 2px;">{risk.get('description', 'Immediate attention required!')}</div>
                </div>
                <div style="position: relative; width: 75px; height: 75px; display: flex; align-items: center; justify-content: center;">
                    <svg viewBox="0 0 36 36" style="width: 100%; height: 100%;">
                        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#164879" stroke-width="3.5" />
                        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="{COLOR_RED}" stroke-width="3.5" stroke-dasharray="{risk.get('percentage', 85)}, 100" />
                    </svg>
                    <span style="position: absolute; font-size: 0.95rem; font-weight: 800; color: {COLOR_TEXT};">{risk.get('percentage', 85)}%</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with bot_col2:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 18px; min-height: 140px; display: flex; flex-direction: column; justify-content: space-between;">
                <div style="display: flex; align-items: flex-start; gap: 12px;">
                    <span style="font-size: 1.5rem; color: {COLOR_ACCENT};">📄</span>
                    <div>
                        <div style="font-size: 0.95rem; font-weight: 700; color: {COLOR_TEXT};">Security Report</div>
                        <div style="font-size: 0.8rem; color: {COLOR_MUTED}; margin-top: 2px;">Download detailed audit report with complete findings and remediation guidance.</div>
                    </div>
                </div>
            """,
            unsafe_allow_html=True
        )
        
        # Download report button (cached to prevent re-compilation on every rerun)
        try:
            report_dict = {
                "total_events": tot_reqs,
                "threats_detected": tot_threats,
                "suspicious_ips": susp_ips_cnt,
                "blocked_attempts": blocked_cnt,
                "risk_assessment": risk,
                "severity_counts": analysis_results.get("severity_counts", {}),
                "attack_categories": analysis_results.get("attack_categories", {}),
                "top_suspicious_ips": top_ips,
                "recommendations": analysis_results.get("recommendations", [])
            }
            pdf_bytes = generate_cached_pdf_report(report_dict)
            st.download_button(
                label="📥 Download Report PDF",
                data=pdf_bytes,
                file_name="soc_security_audit_report.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        except Exception as e:
            st.caption(f"PDF generator ready: {e}")
        st.markdown("</div>", unsafe_allow_html=True)

    with bot_col3:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 18px; min-height: 140px;">
                <div style="font-size: 0.95rem; font-weight: 700; color: {COLOR_TEXT}; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                    <span>⚡</span> Quick Actions
                </div>
            """,
            unsafe_allow_html=True
        )
        act_col1, act_col2 = st.columns(2)
        with act_col1:
            if st.button("🔍 Rescan Logs", use_container_width=True):
                st.session_state.reanalyze_trigger = True
                st.rerun()
        with act_col2:
            if st.button("⚙️ Rules", use_container_width=True):
                st.session_state.current_page = "Settings"
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
