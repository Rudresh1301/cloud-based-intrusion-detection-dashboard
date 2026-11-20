"""
Attack Analytics and Statistical Intelligence Console.
Renders advanced Plotly visualizations:
- Hourly threat heat-signatures
- Most targeted endpoints
- Attack vector distributions
- Authentication pass/fail ratios
- Day-of-week incident frequencies
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ELECTRIC,
    COLOR_CYAN,
    COLOR_PURPLE,
    COLOR_RED,
    COLOR_ORANGE,
    COLOR_GREEN,
    COLOR_GRID,
    SEVERITY_COLORS,
)

@st.cache_data
def get_attack_vector_fig(alerts_df: pd.DataFrame):
    """Caches attack vector distribution pie chart."""
    if alerts_df is None or alerts_df.empty:
        return None
    counts = alerts_df["alert_type"].value_counts().reset_index()
    counts.columns = ["Attack Type", "Incidents"]
    fig1 = px.pie(
        counts,
        names="Attack Type",
        values="Incidents",
        hole=0.55,
        color_discrete_sequence=[COLOR_RED, COLOR_ORANGE, COLOR_PURPLE, COLOR_CYAN, COLOR_ELECTRIC]
    )
    fig1.update_layout(
        height=280,
        margin=dict(l=5, r=5, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLOR_MUTED, size=10),
        legend=dict(font=dict(size=9))
    )
    return fig1

@st.cache_data
def get_hourly_activity_fig(alerts_df: pd.DataFrame):
    """Caches hourly threat incidents distribution bar chart."""
    if alerts_df is None or alerts_df.empty:
        return None
    al_copy = alerts_df.copy()
    al_copy["timestamp_dt"] = pd.to_datetime(al_copy["timestamp"], errors="coerce")
    al_copy["hour"] = al_copy["timestamp_dt"].dt.hour
    hourly_counts = al_copy.groupby("hour").size().reindex(range(24), fill_value=0).reset_index(name="Incidents")
    
    fig2 = px.bar(
        hourly_counts,
        x="hour",
        y="Incidents",
        labels={"hour": "Hour of Day (00:00 - 23:00)", "Incidents": "Threat Alerts"},
        color="Incidents",
        color_continuous_scale=[[0, COLOR_ELECTRIC], [1, COLOR_RED]]
    )
    fig2.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False,
        font=dict(color=COLOR_MUTED, size=10),
        xaxis=dict(gridcolor=COLOR_GRID, tickmode='linear', tick0=0, dtick=3),
        yaxis=dict(gridcolor=COLOR_GRID)
    )
    return fig2

@st.cache_data
def get_top_endpoints_fig(enriched_logs: pd.DataFrame):
    """Caches top target endpoints horizontal bar chart."""
    if enriched_logs is None or enriched_logs.empty or "endpoint" not in enriched_logs.columns:
        return None
    top_eps = enriched_logs["endpoint"].value_counts().head(8).reset_index()
    top_eps.columns = ["Endpoint", "Hit Count"]
    fig3 = px.bar(
        top_eps,
        x="Hit Count",
        y="Endpoint",
        orientation="h",
        color_discrete_sequence=[COLOR_CYAN]
    )
    fig3.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLOR_MUTED, size=10),
        xaxis=dict(gridcolor=COLOR_GRID),
        yaxis=dict(autorange="reversed")
    )
    return fig3

@st.cache_data
def get_auth_verdict_fig(enriched_logs: pd.DataFrame):
    """Caches authentication verdict breakdown bar chart."""
    if enriched_logs is None or enriched_logs.empty:
        return None
    status_s = enriched_logs["status"].astype(str).str.lower()
    successes = int(status_s.isin(["success", "ok", "200"]).sum())
    fails = int(status_s.isin(["failed", "failure", "denied", "401", "403"]).sum())
    blocked = int(status_s.isin(["blocked", "dropped", "rejected"]).sum())

    auth_df = pd.DataFrame([
        {"Verdict": "Success / Allowed", "Count": successes, "Color": COLOR_GREEN},
        {"Verdict": "Authentication Failed", "Count": fails, "Color": COLOR_ORANGE},
        {"Verdict": "Security Blocked", "Count": blocked, "Color": COLOR_RED},
    ])
    fig4 = px.bar(
        auth_df,
        x="Verdict",
        y="Count",
        color="Verdict",
        color_discrete_map={
            "Success / Allowed": COLOR_GREEN,
            "Authentication Failed": COLOR_ORANGE,
            "Security Blocked": COLOR_RED
        }
    )
    fig4.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        font=dict(color=COLOR_MUTED, size=10),
        xaxis=dict(gridcolor=COLOR_GRID),
        yaxis=dict(gridcolor=COLOR_GRID)
    )
    return fig4

@st.cache_data
def get_dow_trend_fig(alerts_df: pd.DataFrame):
    """Caches day-of-week threat volume line chart."""
    if alerts_df is None or alerts_df.empty:
        return None
    al_dt = pd.to_datetime(alerts_df["timestamp"], errors="coerce")
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    day_counts = al_dt.dt.day_name().value_counts().reindex(days_order, fill_value=0).reset_index()
    day_counts.columns = ["Day", "Alerts"]
    
    fig5 = px.line(
        day_counts,
        x="Day",
        y="Alerts",
        markers=True,
        line_shape="spline",
        color_discrete_sequence=[COLOR_ELECTRIC]
    )
    fig5.update_traces(line=dict(width=3), marker=dict(size=7, color=COLOR_RED))
    fig5.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLOR_MUTED, size=10),
        xaxis=dict(gridcolor=COLOR_GRID),
        yaxis=dict(gridcolor=COLOR_GRID)
    )
    return fig5

@st.cache_data
def get_severity_fig(alerts_df: pd.DataFrame):
    """Caches threat severity proportions bar chart."""
    if alerts_df is None or alerts_df.empty:
        return None
    sev_df = alerts_df["severity"].value_counts().reset_index()
    sev_df.columns = ["Severity", "Count"]
    fig6 = px.bar(
        sev_df,
        x="Severity",
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS
    )
    fig6.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        font=dict(color=COLOR_MUTED, size=10),
        xaxis=dict(gridcolor=COLOR_GRID),
        yaxis=dict(gridcolor=COLOR_GRID)
    )
    return fig6

def render_attack_analytics(analysis_results: dict):
    """Renders high-density visual attack analytics."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">📈 Attack Vector Analytics & Telemetry</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Statistical exploration of attack vectors, temporal clusters, target saturation, and authentication behavior.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    enriched_logs = analysis_results.get("enriched_logs", pd.DataFrame()) if analysis_results else pd.DataFrame()
    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame()) if analysis_results else pd.DataFrame()

    if enriched_logs.empty:
        st.warning("No log data loaded. Please upload logs to populate attack analytics.")
        return

    # ── Row 1: Attack Distribution & Hourly Activity ─────────────
    r1_c1, r1_c2 = st.columns(2)

    with r1_c1:
        st.markdown("#### Attack Vector Distribution")
        fig1 = get_attack_vector_fig(alerts_df)
        if fig1 is not None:
            st.plotly_chart(fig1, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No attacks detected.")

    with r1_c2:
        st.markdown("#### Hourly Incident Activity (24-Hour Cycle)")
        fig2 = get_hourly_activity_fig(alerts_df)
        if fig2 is not None:
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No threat data for hourly breakdown.")

    st.write("")

    # ── Row 2: Most Targeted Endpoints & Auth Success/Fail ───────
    r2_c1, r2_c2 = st.columns(2)

    with r2_c1:
        st.markdown("#### Top Target Endpoints Saturation")
        fig3 = get_top_endpoints_fig(enriched_logs)
        if fig3 is not None:
            st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No endpoint data available.")

    with r2_c2:
        st.markdown("#### Authentication Verdict Breakdown")
        fig4 = get_auth_verdict_fig(enriched_logs)
        if fig4 is not None:
            st.plotly_chart(fig4, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No authentication records.")

    st.write("")

    # ── Row 3: Day-of-Week Trend & Severity Balance ──────────────
    r3_c1, r3_c2 = st.columns(2)

    with r3_c1:
        st.markdown("#### Day of Week Threat Volume")
        fig5 = get_dow_trend_fig(alerts_df)
        if fig5 is not None:
            st.plotly_chart(fig5, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No threat timeline records.")

    with r3_c2:
        st.markdown("#### Threat Severity Proportions")
        fig6 = get_severity_fig(alerts_df)
        if fig6 is not None:
            st.plotly_chart(fig6, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No threat severity records.")
