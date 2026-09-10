import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
import streamlit as st

from app.streamlit_client import DEFAULT_API_URL, FIMApiClient, FIMAPIError

logger = logging.getLogger("fim_ui")

# ------------------------------------------------------------------------------
# PAGE CONFIGURATION & ROOT SHELL
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="FIM+ — AI File Integrity Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------------------
# PREMIUM CYBERSECURITY SAAS CSS THEME (Linear + Vercel + Modern Security SaaS)
# ------------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap');

/* Base Application Settings */
html, body, [class*="css"], .stMarkdown {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #e2e8f0;
    -webkit-font-smoothing: antialiased;
}

/* Background canvas */
.stApp {
    background-color: #070a11;
    background-image: 
        radial-gradient(ellipse at 15% 0%, rgba(20, 32, 56, 0.45) 0%, transparent 60%),
        radial-gradient(ellipse at 85% 0%, rgba(15, 23, 42, 0.35) 0px, transparent 50%);
}

/* Monospace restricted strictly to technical artifacts */
code, pre, .mono, .stCode, div[data-testid="stMarkdownContainer"] code {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 11.5px;
    letter-spacing: -0.01em;
}

/* Sidebar Navigation Rail */
section[data-testid="stSidebar"] {
    background-color: #090d16;
    border-right: 1px solid #141d2e;
    box-shadow: 6px 0 24px rgba(0, 0, 0, 0.45);
}

section[data-testid="stSidebar"] > div {
    padding-top: 1.25rem;
    padding-bottom: 1.5rem;
}

/* Custom Nav Radio Styling */
section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    background: transparent;
    padding: 8px 12px;
    border-radius: 6px;
    margin-bottom: 3px;
    border: 1px solid transparent;
    transition: all 0.15s ease;
    cursor: pointer;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background: rgba(30, 41, 59, 0.45);
    border-color: rgba(51, 65, 85, 0.3);
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"],
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
    background: rgba(37, 99, 235, 0.12) !important;
    border: 1px solid rgba(59, 130, 246, 0.35) !important;
    border-left: 3px solid #2563eb !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p {
    color: #f8fafc !important;
    font-weight: 600 !important;
}

/* Hide default radio circle markers */
section[data-testid="stSidebar"] div[role="radiogroup"] div[data-testid="stRadioButtonCustomControl"] {
    display: none !important;
}

/* Header Component */
.app-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    padding: 4px 0 16px 0;
    margin-bottom: 24px;
    border-bottom: 1px solid #141d2e;
}

.header-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-bottom: 4px;
}

.header-title {
    font-size: 26px;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: -0.03em;
    line-height: 1.15;
    margin: 0;
}

.header-desc {
    font-size: 13px;
    color: #94a3b8;
    margin-top: 4px;
}

.header-meta {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 4px;
}

/* System Status Indicators */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

.status-healthy {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: #34d399;
}

.status-offline {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: #f87171;
}

.dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}
.dot-green { background-color: #10b981; box-shadow: 0 0 6px #10b981; }
.dot-red { background-color: #ef4444; box-shadow: 0 0 6px #ef4444; }
.dot-blue { background-color: #3b82f6; box-shadow: 0 0 6px #3b82f6; }
.dot-amber { background-color: #f59e0b; box-shadow: 0 0 6px #f59e0b; }

/* Refined SaaS Posture Surface */
.posture-surface {
    background: #0b101b;
    border: 1px solid #162033;
    border-radius: 6px;
    padding: 20px 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
}

.posture-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 12px;
    border-bottom: 1px solid #141d2e;
    margin-bottom: 16px;
}

.posture-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #94a3b8;
}

.posture-grid {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
    gap: 16px;
    align-items: center;
}

.posture-stat-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748b;
    margin-bottom: 2px;
}

.posture-stat-value {
    font-size: 28px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.1;
}

/* Action Surface */
.action-surface {
    background: #0b101b;
    border: 1px solid #162033;
    border-radius: 6px;
    padding: 18px 20px;
    margin-bottom: 20px;
}

/* Section Dividers & Headers */
.section-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 28px 0 12px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid #141d2e;
}

.section-title {
    font-size: 16px;
    font-weight: 600;
    color: #f1f5f9;
    letter-spacing: -0.01em;
    margin: 0;
}

.section-caption {
    font-size: 12px;
    color: #64748b;
}

/* Pipeline Flow */
.pipeline-container {
    display: grid;
    grid-template-columns: 1fr auto 1fr auto 1fr auto 1fr;
    gap: 8px;
    align-items: center;
    background: #080c15;
    border: 1px solid #131b2c;
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 24px;
}

.pipeline-step {
    display: flex;
    flex-direction: column;
}

.pipeline-step-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 2px;
}

.pipeline-step-desc {
    font-size: 11.5px;
    color: #94a3b8;
    line-height: 1.35;
}

.pipeline-arrow {
    color: #334155;
    font-size: 14px;
    font-weight: 700;
}

/* Severity Labels & Badges */
.sev-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 7px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}

.sev-critical {
    background: rgba(239, 68, 68, 0.12);
    border: 1px solid rgba(239, 68, 68, 0.4);
    color: #f87171;
}

.sev-high {
    background: rgba(249, 115, 22, 0.12);
    border: 1px solid rgba(249, 115, 22, 0.4);
    color: #fb923c;
}

.sev-medium {
    background: rgba(234, 179, 8, 0.12);
    border: 1px solid rgba(234, 179, 8, 0.4);
    color: #fde047;
}

.sev-low {
    background: rgba(100, 116, 139, 0.12);
    border: 1px solid rgba(100, 116, 139, 0.35);
    color: #cbd5e1;
}

.sev-neutral {
    background: rgba(148, 163, 184, 0.08);
    border: 1px solid #1e293b;
    color: #94a3b8;
}

/* Clean Native Tables */
.saas-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin: 8px 0 16px 0;
    font-size: 12.5px;
    border: 1px solid #141d2e;
    border-radius: 6px;
    overflow: hidden;
}

.saas-table th {
    background-color: #0b101b;
    color: #64748b;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 10px 14px;
    border-bottom: 1px solid #141d2e;
    text-align: left;
}

.saas-table td {
    padding: 9px 14px;
    border-bottom: 1px solid #0f172a;
    background-color: #070a11;
    color: #cbd5e1;
}

.saas-table tr:last-child td {
    border-bottom: none;
}

.saas-table tr:hover td {
    background-color: #0b111e;
}

/* Investigation Split Surfaces */
.investigation-panel {
    background: #090e18;
    border: 1px solid #141d2e;
    border-radius: 6px;
    padding: 18px 20px;
    margin-bottom: 16px;
}

.truth-col {
    background: rgba(15, 23, 42, 0.3);
    border: 1px solid #142033;
    border-top: 2px solid #3b82f6;
    border-radius: 4px;
    padding: 14px;
    height: 100%;
}

.ai-col {
    background: rgba(20, 20, 36, 0.3);
    border: 1px solid #1f1d38;
    border-top: 2px solid #8b5cf6;
    border-radius: 4px;
    padding: 14px;
    height: 100%;
}

.panel-col-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 10px;
}

.evidence-box {
    background: #05080f;
    border: 1px solid #141d2e;
    border-radius: 4px;
    padding: 10px 12px;
    margin-top: 8px;
    font-size: 12px;
    color: #cbd5e1;
}

/* Document-like Report Style */
.report-doc {
    background: #090e18;
    border: 1px solid #141d2e;
    border-radius: 6px;
    padding: 24px 28px;
    margin: 16px 0;
}

.report-section {
    margin-bottom: 20px;
}

.report-section-title {
    font-size: 13px;
    font-weight: 700;
    color: #f1f5f9;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 8px;
    padding-bottom: 4px;
    border-bottom: 1px solid #141d2e;
}

/* Timeline Ledger */
.timeline-item {
    display: flex;
    gap: 16px;
    padding: 12px 0;
    border-left: 2px solid #162033;
    margin-left: 12px;
    padding-left: 18px;
    position: relative;
}

.timeline-dot {
    position: absolute;
    left: -6px;
    top: 16px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #2563eb;
}

.timeline-content {
    flex: 1;
}

/* Onboarding / Clean Empty State */
.onboarding-card {
    text-align: center;
    padding: 48px 24px;
    background: #090e18;
    border: 1px dashed #1e293b;
    border-radius: 6px;
    margin: 20px 0;
}

.onboarding-title {
    font-size: 18px;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: -0.02em;
    margin-bottom: 6px;
}

.onboarding-desc {
    font-size: 13.5px;
    color: #94a3b8;
    max-width: 480px;
    margin: 0 auto 20px auto;
    line-height: 1.5;
}

/* Primary / Secondary Buttons */
button[kind="primary"] {
    background: #2563eb !important;
    border: 1px solid #3b82f6 !important;
    color: #ffffff !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    border-radius: 4px !important;
    padding: 6px 14px !important;
    transition: background 0.15s ease !important;
}

button[kind="primary"]:hover {
    background: #1d4ed8 !important;
    border-color: #60a5fa !important;
}

button[kind="secondary"] {
    background: #0d1320 !important;
    border: 1px solid #1e293b !important;
    color: #cbd5e1 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    border-radius: 4px !important;
    padding: 6px 14px !important;
}

button[kind="secondary"]:hover {
    background: #141d2e !important;
    color: #f8fafc !important;
    border-color: #334155 !important;
}

/* Streamlit Expander Polish */
div[data-testid="stExpander"] {
    background-color: #090e18 !important;
    border: 1px solid #141d2e !important;
    border-radius: 5px !important;
    margin-bottom: 8px !important;
}

/* Remove excessive whitespace at top of main container */
.main .block-container {
    padding-top: 1.8rem;
    padding-bottom: 3rem;
    max-width: 1400px;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# ------------------------------------------------------------------------------
if "api_url" not in st.session_state:
    st.session_state.api_url = DEFAULT_API_URL
if "latest_scan_id" not in st.session_state:
    st.session_state.latest_scan_id = None
if "selected_scan_id" not in st.session_state:
    st.session_state.selected_scan_id = ""
if "cached_changes" not in st.session_state:
    st.session_state.cached_changes = {}
if "nav_page" not in st.session_state:
    st.session_state.nav_page = "Overview"

# ------------------------------------------------------------------------------
# HELPERS & FORMATTERS
# ------------------------------------------------------------------------------
def get_client() -> FIMApiClient:
    return FIMApiClient(base_url=st.session_state.api_url)

def format_score(val: Optional[float]) -> str:
    if val is None:
        return "—"
    return f"{val:.4f}"

def format_time_display(dt_str: Optional[str]) -> str:
    if not dt_str:
        return ""
    try:
        # Handle ISO strings or SQLite string formats
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        # If timestamp is already a short time or other format, return as is
        return dt_str

def get_severity_badge(severity: Optional[str]) -> str:
    sev_str = (severity or "Low").capitalize()
    if sev_str == "Critical":
        return "<span class='sev-badge sev-critical'><span class='dot dot-red'></span>Critical</span>"
    elif sev_str == "High":
        return "<span class='sev-badge sev-high'><span class='dot dot-amber'></span>High</span>"
    elif sev_str == "Medium":
        return "<span class='sev-badge sev-medium'><span class='dot' style='background:#eab308;'></span>Medium</span>"
    else:
        return "<span class='sev-badge sev-low'><span class='dot dot-blue'></span>Low</span>"

def resolve_latest_scan_id(api: FIMApiClient) -> Optional[str]:
    if st.session_state.latest_scan_id:
        return st.session_state.latest_scan_id
    try:
        audit_records = api.get_audit()
        for rec in reversed(audit_records):
            if rec.get("action") == "SCAN_COMPLETED":
                details = rec.get("details", "")
                m = re.search(r"scan_id=([a-zA-Z0-9_-]+)", details)
                if m:
                    st.session_state.latest_scan_id = m.group(1)
                    return st.session_state.latest_scan_id
    except Exception:
        pass
    return None

client = get_client()
is_online, health_detail = client.get_health()

# Resolve monitoring status safely from config
monitoring_configured = False
try:
    if is_online:
        cfg = client.get_config()
        monitoring_configured = len(cfg.get("monitored_paths", [])) > 0
except Exception:
    monitoring_configured = False

# ------------------------------------------------------------------------------
# SIDEBAR NAVIGATION RAIL
# ------------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div style='display:flex; align-items:center; gap:10px; padding: 4px 0 16px 0; border-bottom:1px solid #141d2e; margin-bottom:12px;'>
            <div style='background:#101827; border:1px solid #1e293b; width:34px; height:34px; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:16px;'>
                🛡️
            </div>
            <div>
                <div style='font-size:16px; font-weight:800; letter-spacing:-0.02em; color:#f8fafc; line-height:1.1;'>FIM+</div>
                <div style='font-family:"JetBrains Mono", monospace; font-size:9.5px; color:#64748b; letter-spacing:0.1em; text-transform:uppercase;'>AI File Integrity</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    nav_options = [
        "Overview",
        "Scans",
        "Changes",
        "Reports",
        "Audit",
        "Configuration",
    ]
    
    current_index = nav_options.index(st.session_state.nav_page) if st.session_state.nav_page in nav_options else 0
    selected_page = st.radio("MAIN NAVIGATION", nav_options, index=current_index, label_visibility="collapsed")
    if selected_page != st.session_state.nav_page:
        st.session_state.nav_page = selected_page
        st.rerun()

    st.markdown("<div style='margin-top:auto; padding-top:24px;'></div>", unsafe_allow_html=True)
    st.markdown("<div style='border-top: 1px solid #141d2e; padding-top: 14px;'></div>", unsafe_allow_html=True)

    st.markdown("<div class='header-eyebrow' style='font-size:10px; margin-bottom:6px;'>SYSTEM STATUS</div>", unsafe_allow_html=True)
    if is_online:
        st.markdown(
            """
            <div class='status-pill status-healthy' style='width:100%; justify-content:flex-start; margin-bottom:6px;'>
                <span class='dot dot-green'></span> Connected
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class='status-pill status-offline' style='width:100%; justify-content:flex-start; margin-bottom:6px;'>
                <span class='dot dot-red'></span> Offline
            </div>
            """,
            unsafe_allow_html=True,
        )

    clean_host = st.session_state.api_url.replace("http://", "").replace("https://", "")
    st.markdown(f"<div style='font-family:\"JetBrains Mono\", monospace; font-size:10.5px; color:#64748b; margin-bottom:12px;'>API: {clean_host}</div>", unsafe_allow_html=True)

    with st.expander("API Endpoint Settings"):
        new_api = st.text_input("Base URL", value=st.session_state.api_url, key="api_url_cfg")
        if new_api != st.session_state.api_url:
            st.session_state.api_url = new_api
            st.rerun()

    st.markdown("<div style='font-size: 11px; color:#475569; line-height: 1.4; margin-top:8px;'>Enterprise Security Operations Console<br>Cryptographic proof &amp; AI investigation.</div>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TOP HEADER COMPONENT
# ------------------------------------------------------------------------------
def render_header(title: str, subtext: str, last_scan_time: Optional[str] = None):
    col_l, col_r = st.columns([3, 1])
    with col_l:
        st.markdown(
            f"""
            <div>
                <div class='header-eyebrow'>FIM+ / Security Operations</div>
                <h1 class='header-title'>{title}</h1>
                <div class='header-desc'>{subtext}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_r:
        time_meta = f"<div style='font-family:\"JetBrains Mono\", monospace; font-size:11px; color:#64748b; margin-top:3px;'>Last scan: {last_scan_time}</div>" if last_scan_time else ""
        if is_online:
            st.markdown(
                f"""
                <div class='header-meta'>
                    <div class='status-pill status-healthy'>
                        <span class='dot dot-green'></span> System Healthy
                    </div>
                    {time_meta}
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div class='header-meta'>
                    <div class='status-pill status-offline'>
                        <span class='dot dot-red'></span> API Unreachable
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    st.markdown("<div style='border-bottom: 1px solid #141d2e; margin: 12px 0 20px 0;'></div>", unsafe_allow_html=True)

def render_offline_state():
    st.markdown(
        """
        <div class='onboarding-card' style='border-color: #7f1d1d;'>
            <div class='header-eyebrow' style='color:#ef4444;'>CONNECTION ERROR</div>
            <div class='onboarding-title'>FIM+ Backend Offline</div>
            <div class='onboarding-desc'>
                The security console cannot establish an HTTP connection to the FIM+ API at <code>%s</code>.<br>
                Please ensure the FastAPI service is running.
            </div>
        </div>
        """ % st.session_state.api_url,
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns([2, 1, 2])
    with c2:
        if st.button("RECONNECT", use_container_width=True, type="primary"):
            st.rerun()


# ==============================================================================
# 1. OVERVIEW PAGE
# ==============================================================================
if st.session_state.nav_page == "Overview":
    latest_scan_id = resolve_latest_scan_id(client) if is_online else None
    changes = []
    latest_ts_formatted = None

    if is_online and latest_scan_id:
        try:
            changes = client.get_changes(latest_scan_id)
            st.session_state.cached_changes[latest_scan_id] = changes
            if changes:
                latest_ts_formatted = format_time_display(changes[0].get("detected_at"))
        except Exception as e:
            logger.error(f"Error fetching changes: {e}")

    render_header("Security Overview", "Know what changed. Understand why it matters.", last_scan_time=latest_ts_formatted)

    if not is_online:
        render_offline_state()
    elif not latest_scan_id:
        # Onboarding Empty State
        st.markdown(
            """
            <div class='onboarding-card'>
                <div class='header-eyebrow' style='color:#3b82f6;'>FILESYSTEM MONITORING</div>
                <div class='onboarding-title'>Your Filesystem is Not Monitored Yet</div>
                <div class='onboarding-desc'>
                    Create a trusted SHA-256 baseline of your configured target paths to establish ground-truth cryptographic custody.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        c1, c2, c3 = st.columns([1, 1, 1])
        with c2:
            if st.button("CREATE BASELINE", use_container_width=True, type="primary"):
                with st.spinner("Computing initial SHA-256 baseline..."):
                    try:
                        b_res = client.create_baseline()
                        st.success(f"Trusted baseline `{b_res.get('scan_id')}` established ({b_res.get('files_indexed')} files).")
                        st.rerun()
                    except FIMAPIError as ex:
                        st.error(str(ex))

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style='display:flex; justify-content:center; gap:24px; font-size:12px; color:#64748b;'>
                <div>1. Establish trusted state</div>
                <div>→</div>
                <div>2. Detect filesystem changes</div>
                <div>→</div>
                <div>3. Investigate with AI</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        # Calculate real metrics
        total_changes = len(changes)
        crit_count = sum(1 for c in changes if (c.get("severity") or "").capitalize() == "Critical")
        high_count = sum(1 for c in changes if (c.get("severity") or "").capitalize() == "High")
        med_count = sum(1 for c in changes if (c.get("severity") or "").capitalize() == "Medium")
        low_count = sum(1 for c in changes if (c.get("severity") or "").capitalize() == "Low" or c.get("severity") is None)

        # ----------------------------------------------------
        # DOMINANT SECURITY POSTURE SECTION
        # ----------------------------------------------------
        monitoring_indicator = "<span class='status-pill status-healthy' style='padding:2px 8px; font-size:10px;'><span class='dot dot-green'></span> Monitoring Active</span>" if monitoring_configured else ""
        
        # Fetch real-time security state from intelligence layer
        sec_state = {"incident_risk_level": "LOW", "incident_risk_score": 0.0, "primary_indicators": []}
        try:
            sec_state = client.get_security_state()
        except:
            pass
            
        risk_level = sec_state.get("incident_risk_level", "LOW")
        risk_score = sec_state.get("incident_risk_score", 0.0)
        primary_inds = sec_state.get("primary_indicators", [])
        
        if risk_level == "CRITICAL":
            posture_status = "<span class='sev-badge sev-critical' style='font-size:12px;'><span class='dot dot-red'></span> CRITICAL RISK</span>"
        elif risk_level == "HIGH":
            posture_status = "<span class='sev-badge sev-high' style='font-size:12px;'><span class='dot dot-amber'></span> HIGH RISK</span>"
        elif risk_level == "MEDIUM":
            posture_status = "<span class='sev-badge sev-medium' style='font-size:12px;'><span class='dot' style='background:#eab308;'></span> MEDIUM RISK</span>"
        else:
            posture_status = "<span class='sev-badge sev-low' style='font-size:12px;'><span class='dot dot-blue'></span> LOW RISK</span>"

        indicators_html = ""
        for ind in primary_inds[:2]:
            indicators_html += f"<div style='font-size:11px; color:#f87171; margin-top:4px;'>⚠️ {ind}</div>"

        st.markdown(
            f"""
            <div class='posture-surface'>
                <div class='posture-header'>
                    <div class='posture-eyebrow'>INCIDENT RISK POSTURE</div>
                    <div style='display:flex; align-items:center; gap:10px;'>
                        {monitoring_indicator}
                        {posture_status}
                    </div>
                </div>
                <div class='posture-grid'>
                    <div>
                        <div class='posture-stat-label'>TOTAL CHANGES</div>
                        <div class='posture-stat-value' style='color:#f8fafc; font-size:36px;'>{total_changes:02d}</div>
                        <div style='font-size:11.5px; color:#64748b;'>Observed deviations</div>
                    </div>
                    <div>
                        <div class='posture-stat-label' style='color:#ef4444;'>RISK SCORE</div>
                        <div class='posture-stat-value' style='color:#ef4444;'>{risk_score:.2f}</div>
                        <div style='font-size:11.5px; color:#64748b;'>Aggregated incident risk</div>
                    </div>
                    <div style='grid-column: span 3;'>
                        <div class='posture-stat-label' style='color:#94a3b8;'>PRIMARY INDICATORS</div>
                        {indicators_html if indicators_html else "<div style='font-size:11.5px; color:#64748b; margin-top:4px;'>No significant behavioral anomalies.</div>"}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ----------------------------------------------------
        # LATEST SCAN & DETECTION PIPELINE
        # ----------------------------------------------------
        col_scan, col_pipe = st.columns([1, 1])

        with col_scan:
            st.markdown(
                f"""
                <div class='action-surface'>
                    <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;'>
                        <span class='posture-eyebrow'>LATEST INTEGRITY SCAN</span>
                        <span class='status-pill status-healthy' style='padding:2px 6px; font-size:9.5px;'><span class='dot dot-green'></span> Completed</span>
                    </div>
                    <div style='font-size:15px; font-weight:600; color:#f8fafc; font-family:"JetBrains Mono", monospace; margin-bottom:4px;'>{latest_scan_id}</div>
                    <div style='font-size:12px; color:#94a3b8;'>
                        <b>{total_changes}</b> files changed &nbsp;•&nbsp; Timestamp: <code>{latest_ts_formatted or 'Recorded'}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                if st.button("RUN SCAN", use_container_width=True, type="primary", key="ov_run_scan"):
                    with st.spinner("Executing integrity scan..."):
                        try:
                            s_res = client.run_scan()
                            st.session_state.latest_scan_id = s_res.get("scan_id")
                            st.session_state.selected_scan_id = s_res.get("scan_id")
                            st.success(f"Scan `{s_res.get('scan_id')}` completed ({s_res.get('total_changes')} changes).")
                            st.rerun()
                        except FIMAPIError as ex:
                            st.error(str(ex))
            with btn_col2:
                if st.button("INVESTIGATE", use_container_width=True, type="secondary", key="ov_investigate"):
                    st.session_state.selected_scan_id = latest_scan_id
                    st.session_state.nav_page = "Changes"
                    st.rerun()

        with col_pipe:
            st.markdown(
                """
                <div class='action-surface' style='padding: 16px 18px;'>
                    <div class='posture-eyebrow' style='margin-bottom:12px;'>DETECTION PIPELINE</div>
                    <div style='display:grid; grid-template-columns: 1fr 1fr; gap:10px 16px;'>
                        <div>
                            <div style='font-family:"JetBrains Mono", monospace; font-size:11px; font-weight:700; color:#60a5fa;'>1. INTEGRITY</div>
                            <div style='font-size:11.5px; color:#94a3b8;'>SHA-256 canonical hashing guarantees cryptographic proof.</div>
                        </div>
                        <div>
                            <div style='font-family:"JetBrains Mono", monospace; font-size:11px; font-weight:700; color:#a78bfa;'>2. BEHAVIOR</div>
                            <div style='font-size:11.5px; color:#94a3b8;'>Isolation Forest scores velocity &amp; temporal anomaly.</div>
                        </div>
                        <div>
                            <div style='font-family:"JetBrains Mono", monospace; font-size:11px; font-weight:700; color:#34d399;'>3. SEMANTICS</div>
                            <div style='font-size:11.5px; color:#94a3b8;'>Neural embeddings measure functional code drift.</div>
                        </div>
                        <div>
                            <div style='font-family:"JetBrains Mono", monospace; font-size:11px; font-weight:700; color:#f87171;'>4. RISK</div>
                            <div style='font-size:11.5px; color:#94a3b8;'>Deterministic rules adjudicate reproducible severity.</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ----------------------------------------------------
        # RECENT ACTIVITY FEED
        # ----------------------------------------------------
        st.markdown(
            """
            <div class='section-header-row'>
                <h3 class='section-title'>Recent Activity</h3>
                <span class='section-caption'>Latest detected filesystem records</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if not changes:
            st.markdown(
                """
                <div class='onboarding-card' style='padding: 24px;'>
                    <div class='onboarding-title' style='font-size:15px;'>No integrity deviations detected</div>
                    <div class='onboarding-desc' style='margin-bottom:0;'>All monitored files are currently synchronized with the trusted cryptographic baseline.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            # Render clean, safe rows without raw unescaped table tags
            top_records = changes[:8]
            html_rows = []
            for c in top_records:
                sev_badge = get_severity_badge(c.get("severity"))
                fpath = c.get("file_path", "")
                ctype = c.get("change_type", "MODIFIED")
                crit = c.get("criticality", "Medium")
                a_score = format_score(c.get("anomaly_score"))
                d_score = format_score(c.get("drift_score"))
                ts_disp = format_time_display(c.get("detected_at"))

                html_rows.append(
                    f"<tr>"
                    f"<td>{sev_badge}</td>"
                    f"<td><code style='color:#f8fafc; font-weight:600;'>{fpath}</code></td>"
                    f"<td><span style='font-size:12px; font-weight:600;'>{ctype}</span></td>"
                    f"<td><span style='font-size:12px; color:#94a3b8;'>{crit}</span></td>"
                    f"<td><code>{a_score}</code></td>"
                    f"<td><code>{d_score}</code></td>"
                    f"<td><code style='color:#64748b;'>{ts_disp}</code></td>"
                    f"</tr>"
                )

            joined_rows = "".join(html_rows)
            table_markup = (
                "<table class='saas-table'>"
                "<thead><tr>"
                "<th>SEVERITY</th><th>FILE PATH</th><th>CHANGE</th><th>CRITICALITY</th><th>ANOMALY</th><th>DRIFT</th><th>TIME</th>"
                "</tr></thead>"
                f"<tbody>{joined_rows}</tbody>"
                "</table>"
            )
            st.markdown(table_markup, unsafe_allow_html=True)


# ==============================================================================
# 2. SCANS PAGE (2-Step Workflow)
# ==============================================================================
elif st.session_state.nav_page == "Scans":
    render_header("Integrity Scans", "Establish trust. Detect deviation.")

    if not is_online:
        render_offline_state()
    else:
        # Step 01: Establish Trusted Baseline
        st.markdown(
            """
            <div style='display:flex; align-items:center; gap:10px; margin-bottom:8px;'>
                <div style='background:#1e293b; color:#94a3b8; font-family:"JetBrains Mono", monospace; font-size:11px; font-weight:700; width:26px; height:26px; border-radius:4px; display:flex; align-items:center; justify-content:center;'>01</div>
                <h3 class='section-title'>Establish Trusted Baseline</h3>
            </div>
            <div style='font-size:13px; color:#94a3b8; margin-bottom:12px;'>
                Capture the authoritative, known-good SHA-256 state of all monitored files.
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_b_action, col_b_info = st.columns([1, 2])
        with col_b_action:
            if st.button("CREATE BASELINE", use_container_width=True, type="secondary", key="scan_pg_baseline"):
                with st.spinner("Generating SHA-256 digests and persisting baseline snapshot..."):
                    try:
                        b_res = client.create_baseline()
                        st.success(f"✓ Baseline established: `{b_res.get('scan_id')}` ({b_res.get('files_indexed')} files indexed)")
                    except FIMAPIError as ex:
                        st.error(f"Baseline error: {ex}")
        with col_b_info:
            try:
                cfg = client.get_config()
                p_count = len(cfg.get("monitored_paths", []))
                st.markdown(f"<div style='font-size:12px; color:#64748b; padding-top:6px;'>Active target configuration: <b>{p_count}</b> monitored location(s) defined.</div>", unsafe_allow_html=True)
            except Exception:
                pass

        st.markdown("<div style='border-bottom: 1px dashed #1e293b; margin: 24px 0;'></div>", unsafe_allow_html=True)

        # Step 02: Detect Changes
        st.markdown(
            """
            <div style='display:flex; align-items:center; gap:10px; margin-bottom:8px;'>
                <div style='background:#1e293b; color:#94a3b8; font-family:"JetBrains Mono", monospace; font-size:11px; font-weight:700; width:26px; height:26px; border-radius:4px; display:flex; align-items:center; justify-content:center;'>02</div>
                <h3 class='section-title'>Detect Changes</h3>
            </div>
            <div style='font-size:13px; color:#94a3b8; margin-bottom:12px;'>
                Compare current filesystem against the trusted baseline and trigger automated multi-signal AI enrichment.
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_s_action, col_s_info = st.columns([1, 2])
        with col_s_action:
            if st.button("RUN SCAN", use_container_width=True, type="primary", key="scan_pg_scan"):
                with st.spinner("Diffing filesystem state and computing AI enrichment..."):
                    try:
                        s_res = client.run_scan()
                        s_id = s_res.get("scan_id")
                        st.session_state.latest_scan_id = s_id
                        st.session_state.selected_scan_id = s_id
                        st.success(f"✓ Scan completed: `{s_id}`\n\nTotal Changes: {s_res.get('total_changes')} (Added: {s_res.get('added_count')}, Modified: {s_res.get('modified_count')}, Deleted: {s_res.get('deleted_count')})")
                    except FIMAPIError as ex:
                        st.error(f"Scan error: {ex}")
        with col_s_info:
            if st.session_state.latest_scan_id:
                st.markdown(f"<div style='font-size:12px; color:#64748b; padding-top:6px;'>Most recent scan: <code>{st.session_state.latest_scan_id}</code></div>", unsafe_allow_html=True)


# ==============================================================================
# 3. CHANGES / INVESTIGATION CONSOLE
# ==============================================================================
elif st.session_state.nav_page == "Changes":
    render_header("Change Investigation", "Investigate deviations detected by cryptographic monitoring.")

    if not is_online:
        render_offline_state()
    else:
        # Compact Scan Selector Toolbar
        c_sel_input, c_sel_btn = st.columns([3, 1])
        with c_sel_input:
            curr_val = st.session_state.selected_scan_id or st.session_state.latest_scan_id or ""
            target_scan = st.text_input("Scan ID", value=curr_val, placeholder="e.g. scan-0a1b2c3d4e5f", label_visibility="collapsed")
        with c_sel_btn:
            st.button("LOAD SCAN", use_container_width=True, type="primary")

        scan_id_query = target_scan.strip()

        if not scan_id_query:
            st.markdown(
                """
                <div class='onboarding-card'>
                    <div class='onboarding-title'>No Scan Selected</div>
                    <div class='onboarding-desc'>Enter a valid Scan ID or trigger an integrity scan to begin forensic investigation.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            try:
                changes = client.get_changes(scan_id_query)
                st.session_state.selected_scan_id = scan_id_query

                if not changes:
                    st.markdown(
                        f"""
                        <div class='onboarding-card'>
                            <div class='onboarding-title'>No Deviations in Scan</div>
                            <div class='onboarding-desc'>All monitored files in scan <code>{scan_id_query}</code> perfectly match baseline hashes.</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    # Clean Horizontal Filter Toolbar
                    st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)
                    f1, f2, f3, f4 = st.columns(4)
                    with f1:
                        sev_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], label_visibility="visible")
                    with f2:
                        type_filter = st.selectbox("Change Type", ["All", "MODIFIED", "ADDED", "DELETED"], label_visibility="visible")
                    with f3:
                        crit_filter = st.selectbox("Criticality", ["All", "Critical", "High", "Medium", "Low"], label_visibility="visible")
                    with f4:
                        search_term = st.text_input("Search Path", placeholder="Filter by path...", label_visibility="visible")

                    filtered = []
                    for ch in changes:
                        ch_sev = (ch.get("severity") or "Low").capitalize()
                        if sev_filter != "All" and ch_sev != sev_filter:
                            continue
                        if type_filter != "All" and ch.get("change_type") != type_filter:
                            continue
                        if crit_filter != "All" and ch.get("criticality") != crit_filter:
                            continue
                        if search_term and search_term.lower() not in ch.get("file_path", "").lower():
                            continue
                        filtered.append(ch)

                    # Severity sorting
                    sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, None: 0}
                    sorted_changes = sorted(
                        filtered,
                        key=lambda x: (
                            sev_order.get((x.get("severity") or "").capitalize(), 0),
                            x.get("anomaly_score") or 0.0,
                            x.get("drift_score") or 0.0
                        ),
                        reverse=True
                    )

                    st.markdown(f"<div style='font-size:12px; color:#64748b; margin: 12px 0 6px 0;'>Displaying <b>{len(sorted_changes)}</b> of <b>{len(changes)}</b> detected changes</div>", unsafe_allow_html=True)

                    # Overview Change Rows
                    t_rows = []
                    for ch in sorted_changes:
                        s_badge = get_severity_badge(ch.get("severity"))
                        fp = ch.get("file_path", "")
                        ct = ch.get("change_type", "MODIFIED")
                        cr = ch.get("criticality", "Medium")
                        a_sc = format_score(ch.get("anomaly_score"))
                        d_sc = format_score(ch.get("drift_score"))

                        t_rows.append(
                            f"<tr>"
                            f"<td>{s_badge}</td>"
                            f"<td><code style='color:#f8fafc; font-weight:600;'>{fp}</code></td>"
                            f"<td><span style='font-size:12px; font-weight:600;'>{ct}</span></td>"
                            f"<td><span style='font-size:12px; color:#94a3b8;'>{cr}</span></td>"
                            f"<td><code>{a_sc}</code></td>"
                            f"<td><code>{d_sc}</code></td>"
                            f"</tr>"
                        )

                    joined_t = "".join(t_rows)
                    st.markdown(
                        "<table class='saas-table'>"
                        "<thead><tr><th>SEVERITY</th><th>FILE PATH</th><th>CHANGE</th><th>CRITICALITY</th><th>ANOMALY</th><th>DRIFT</th></tr></thead>"
                        f"<tbody>{joined_t}</tbody>"
                        "</table>",
                        unsafe_allow_html=True,
                    )

                    # Forensic Investigation Detail Drawers
                    st.markdown(
                        """
                        <div class='section-header-row'>
                            <h3 class='section-title'>Forensic Detail Panels</h3>
                            <span class='section-caption'>Cryptographic Truth vs AI Investigation</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    for idx, ch in enumerate(sorted_changes):
                        fpath = ch.get("file_path", "")
                        ctype = ch.get("change_type", "MODIFIED")
                        sev_name = (ch.get("severity") or "Low").upper()

                        with st.expander(f"[{sev_name}] {ctype} — {fpath}", expanded=(idx == 0)):
                            st.markdown(
                                f"""
                                <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;'>
                                    <div style='font-size:16px; font-weight:700; color:#f8fafc;'>{fpath}</div>
                                    <div>{get_severity_badge(ch.get('severity'))}</div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                            col_truth, col_ai = st.columns(2)

                            with col_truth:
                                st.markdown(
                                    f"""
                                    <div class='truth-col'>
                                        <div class='panel-col-title' style='color:#60a5fa;'>WHAT CHANGED // Cryptographic Truth</div>
                                        <div style='font-size:12px; margin-bottom:6px;'><b>File Path:</b> <code style='color:#f8fafc;'>{fpath}</code></div>
                                        <div style='font-size:12px; margin-bottom:6px;'><b>Change Type:</b> <code style='color:#f8fafc;'>{ctype}</code></div>
                                        <div style='font-size:12px; margin-bottom:8px;'><b>Asset Tier:</b> {ch.get('criticality', 'Medium')}</div>
                                        <div style='font-size:11px; color:#64748b; margin-top:8px;'>Old SHA-256:</div>
                                        <div style='background:#05080f; border:1px solid #141d2e; padding:6px 8px; border-radius:3px; margin-bottom:6px;'>
                                            <code style='color:#94a3b8; font-size:11px;'>{ch.get('old_hash') or 'null (NEW FILE)'}</code>
                                        </div>
                                        <div style='font-size:11px; color:#64748b;'>New SHA-256:</div>
                                        <div style='background:#05080f; border:1px solid #141d2e; padding:6px 8px; border-radius:3px;'>
                                            <code style='color:#94a3b8; font-size:11px;'>{ch.get('new_hash') or 'null (DELETED FILE)'}</code>
                                        </div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

                            with col_ai:
                                st.markdown(
                                    f"""
                                    <div class='ai-col'>
                                        <div class='panel-col-title' style='color:#a78bfa;'>WHY IT MATTERS // AI Investigation</div>
                                        <div style='display:flex; gap:16px; margin-bottom:12px;'>
                                            <div>
                                                <div style='font-size:10.5px; font-family:"JetBrains Mono", monospace; color:#64748b;'>ANOMALY</div>
                                                <div style='font-size:16px; font-weight:700; font-family:"JetBrains Mono", monospace; color:#f8fafc;'>{format_score(ch.get('anomaly_score'))}</div>
                                            </div>
                                            <div>
                                                <div style='font-size:10.5px; font-family:"JetBrains Mono", monospace; color:#64748b;'>SEMANTIC DRIFT</div>
                                                <div style='font-size:16px; font-weight:700; font-family:"JetBrains Mono", monospace; color:#f8fafc;'>{format_score(ch.get('drift_score'))}</div>
                                            </div>
                                            <div>
                                                <div style='font-size:10.5px; font-family:"JetBrains Mono", monospace; color:#64748b;'>SEVERITY</div>
                                                <div style='margin-top:2px;'>{get_severity_badge(ch.get('severity'))}</div>
                                            </div>
                                        </div>
                                        
                                        <div style='border-top: 1px solid #1f1d38; padding-top: 8px; margin-top: 8px; margin-bottom: 8px;'>
                                            <div style='font-size:11px; font-weight:600; color:#60a5fa;'>SECURITY INTELLIGENCE</div>
                                            <div style='display:flex; gap:12px; margin-top:4px;'>
                                                <div style='font-size:11px;'><span style='color:#94a3b8;'>Novelty:</span> <span style='color:#f8fafc;'>{"YES" if isinstance(ch.get('evidence'), dict) and ch.get('evidence', {}).get('is_novel') else "NO"}</span></div>
                                                <div style='font-size:11px;'><span style='color:#94a3b8;'>Recurrence:</span> <span style='color:#f8fafc;'>{ch.get('evidence', {}).get('recurrence_count', 0) if isinstance(ch.get('evidence'), dict) else 0}x</span></div>
                                                <div style='font-size:11px;'><span style='color:#94a3b8;'>Primary Indicator:</span> <span style='color:#f8fafc;'>{ch.get('evidence', {}).get('attribution', {}).get('primary_reason', 'N/A') if isinstance(ch.get('evidence'), dict) else 'N/A'}</span></div>
                                            </div>
                                        </div>

                                        <div style='font-size:11px; font-weight:600; color:#94a3b8; margin-top:8px;'>ANOMALY REASON</div>
                                        <div class='evidence-box'>
                                            {ch.get('evidence', {}).get('anomaly_reason', 'N/A') if isinstance(ch.get('evidence'), dict) else 'N/A'}
                                        </div>
                                        <div style='font-size:11px; font-weight:600; color:#94a3b8; margin-top:8px;'>DRIFT REASON</div>
                                        <div class='evidence-box'>
                                            {ch.get('evidence', {}).get('drift_reason', 'N/A') if isinstance(ch.get('evidence'), dict) else 'N/A'}
                                        </div>
                                        <div style='font-size:11px; font-weight:600; color:#94a3b8; margin-top:8px;'>CRITICALITY WEIGHT</div>
                                        <div class='evidence-box' style='font-family:"JetBrains Mono", monospace;'>
                                            {ch.get('evidence', {}).get('criticality_weight', 'N/A') if isinstance(ch.get('evidence'), dict) else 'N/A'}
                                        </div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

            except FIMAPIError as ex:
                st.error(f"Investigation error: {ex}")


# ==============================================================================
# 4. REPORTS PAGE (Document-Style Security Briefing)
# ==============================================================================
elif st.session_state.nav_page == "Reports":
    render_header("Investigation Reports", "AI-assisted incident analysis grounded in observed evidence.")

    if not is_online:
        render_offline_state()
    else:
        r_sel_input, r_sel_btn = st.columns([3, 1])
        with r_sel_input:
            curr_val = st.session_state.selected_scan_id or st.session_state.latest_scan_id or ""
            rep_scan_input = st.text_input("Report Scan ID", value=curr_val, placeholder="e.g. scan-0a1b2c3d4e5f", label_visibility="collapsed")
        with r_sel_btn:
            st.button("FETCH REPORT", use_container_width=True, type="primary")

        target_scan_id = rep_scan_input.strip()

        if not target_scan_id:
            st.markdown(
                """
                <div class='onboarding-card'>
                    <div class='onboarding-title'>No Scan Specified</div>
                    <div class='onboarding-desc'>Enter a Scan ID to generate and view the synthesis intelligence report.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            try:
                with st.spinner(f"Retrieving intelligence report for `{target_scan_id}`..."):
                    rep_data = client.get_report(target_scan_id)

                s_id = rep_data.get("scan_id", target_scan_id)
                created_at = rep_data.get("created_at", "N/A")
                raw_rep_text = rep_data.get("report_text", "")

                parsed = None
                try:
                    parsed = json.loads(raw_rep_text)
                except Exception:
                    pass

                if isinstance(parsed, dict):
                    sev = parsed.get("incident_severity", "LOW")
                    risk_score = parsed.get("risk_score", 0.0)
                    confidence = int(parsed.get("confidence", 0.85) * 100)
                    gen_method = parsed.get("generation_method", "fallback")
                    
                    if gen_method == "groq":
                        model_name = os.environ.get("GROQ_MODEL", "Groq")
                        gen_display = f"Groq · {model_name}"
                    else:
                        gen_display = "Deterministic fallback"

                    # Document Header
                    st.markdown(
                        f"""
                        <div style='background:#090e18; border:1px solid #141d2e; border-radius:6px; padding:18px 24px; margin-bottom:20px;'>
                            <div style='display:flex; justify-content:space-between; align-items:center;'>
                                <div>
                                    <div class='header-eyebrow'>SECURITY INTELLIGENCE REPORT</div>
                                    <div style='font-size:20px; font-weight:700; color:#f8fafc;'>Scan Investigation Briefing</div>
                                </div>
                                <div style='text-align:right;'>
                                    <div style='font-family:"JetBrains Mono", monospace; font-size:12px; color:#f8fafc;'>{s_id}</div>
                                    <div style='font-size:11px; color:#64748b;'>Generation: <span style='color:#a78bfa;'>{gen_display}</span></div>
                                    <div style='font-size:11px; color:#64748b;'>Time: {created_at}</div>
                                </div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    c_rep1, c_rep2, c_rep3 = st.columns(3)
                    with c_rep1:
                        st.markdown(
                            f"""
                            <div class='action-surface'>
                                <div class='posture-stat-label'>INCIDENT SEVERITY</div>
                                <div style='margin-top:4px;'>{get_severity_badge(sev)}</div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    with c_rep2:
                        st.markdown(
                            f"""
                            <div class='action-surface'>
                                <div class='posture-stat-label'>COMPOSITE RISK</div>
                                <div class='posture-stat-value' style='color:#f8fafc; font-size:22px;'>{risk_score:.2f} <span style='font-size:12px; color:#64748b;'>/ 1.00</span></div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    with c_rep3:
                        st.markdown(
                            f"""
                            <div class='action-surface'>
                                <div class='posture-stat-label'>AUDIT CONFIDENCE</div>
                                <div class='posture-stat-value' style='color:#34d399; font-size:22px;'>{confidence}%</div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    # Document Surface
                    st.markdown("<div class='report-doc'>", unsafe_allow_html=True)
                    
                    exec_summary = parsed.get("executive_summary")
                    if exec_summary:
                        st.markdown(
                            f"""
                            <div class='report-section'>
                                <div class='report-section-title'>Executive Summary</div>
                                <div style='font-size:13.5px; line-height:1.6; color:#e2e8f0;'>{exec_summary}</div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    col_f, col_r = st.columns(2)
                    with col_f:
                        st.markdown("<div class='report-section-title'>Key Findings</div>", unsafe_allow_html=True)
                        findings = parsed.get("key_findings", [])
                        if findings:
                            for f in findings:
                                st.markdown(f"• <span style='font-size:13px; color:#cbd5e1;'>{f}</span>", unsafe_allow_html=True)
                        else:
                            st.caption("No key findings recorded.")

                    with col_r:
                        st.markdown("<div class='report-section-title'>Actionable Recommendations</div>", unsafe_allow_html=True)
                        recs = parsed.get("recommended_actions", [])
                        if recs:
                            for r in recs:
                                st.markdown(f"• <span style='font-size:13px; color:#cbd5e1;'>{r}</span>", unsafe_allow_html=True)
                        else:
                            st.caption("No specific actions required.")

                    limits = parsed.get("limitations", [])
                    if limits:
                        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
                        st.markdown("<div class='report-section-title'>Limitations &amp; Disclosures</div>", unsafe_allow_html=True)
                        for lim in limits:
                            st.markdown(f"<div style='font-size:12px; color:#94a3b8; margin-bottom:4px;'>⚠️ {lim}</div>", unsafe_allow_html=True)

                    st.markdown("</div>", unsafe_allow_html=True)

                    with st.expander("Raw Formatted JSON Report"):
                        st.json(parsed)
                else:
                    st.markdown(
                        f"""
                        <div class='report-doc'>
                            <div class='report-section-title'>Report Text</div>
                            <div style='font-size:13.5px; line-height:1.6;'>{raw_rep_text}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            except FIMAPIError as ex:
                st.markdown(
                    f"""
                    <div class='onboarding-card'>
                        <div class='onboarding-title'>No Report Available</div>
                        <div class='onboarding-desc'>{ex}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


# ==============================================================================
# 5. AUDIT PAGE (Vertical Ledger)
# ==============================================================================
elif st.session_state.nav_page == "Audit":
    render_header("Audit Trail", "Every security operation leaves a trace.")

    if not is_online:
        render_offline_state()
    else:
        try:
            records = client.get_audit()
            if not records:
                st.markdown(
                    """
                    <div class='onboarding-card'>
                        <div class='onboarding-title'>Audit Ledger is Empty</div>
                        <div class='onboarding-desc'>Cryptographic baselines, integrity scans, and configuration edits will be appended here.</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div class='section-header-row'>
                        <h3 class='section-title'>Chronological Event Ledger</h3>
                        <span class='section-caption'>Total Events: {len(records)}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                audit_rows = []
                for rec in reversed(records):
                    action = rec.get("action", "")
                    ts = rec.get("timestamp", "")
                    details = rec.get("details", "")

                    if "BASELINE" in action:
                        badge = "<span class='sev-badge' style='background:rgba(59,130,246,0.12); border:1px solid #3b82f6; color:#60a5fa;'>● BASELINE</span>"
                    elif "SCAN" in action:
                        badge = "<span class='sev-badge' style='background:rgba(16,185,129,0.12); border:1px solid #10b981; color:#34d399;'>● SCAN</span>"
                    elif "CONFIG" in action:
                        badge = "<span class='sev-badge' style='background:rgba(234,179,8,0.12); border:1px solid #eab308; color:#fde047;'>● CONFIG UPDATE</span>"
                    elif "FAILED" in action or "ERROR" in action:
                        badge = "<span class='sev-badge sev-critical'>● AI_ENRICHMENT_FAILED</span>"
                    else:
                        badge = f"<span class='sev-badge sev-neutral'>● {action}</span>"

                    warning_note = ""
                    if "AI_ENRICHMENT_FAILED" in action:
                        warning_note = "<div style='font-size:11.5px; color:#f87171; margin-top:2px;'>AI enrichment unavailable. Cryptographic scan results remain intact.</div>"

                    audit_rows.append(
                        f"<tr>"
                        f"<td><code style='color:#64748b;'>{ts}</code></td>"
                        f"<td>{badge}</td>"
                        f"<td><span style='font-size:12.5px; color:#e2e8f0;'>{details}</span>{warning_note}</td>"
                        f"</tr>"
                    )

                joined_audit = "".join(audit_rows)
                st.markdown(
                    "<table class='saas-table'>"
                    "<thead><tr><th>TIMESTAMP</th><th>ACTION</th><th>DETAILS</th></tr></thead>"
                    f"<tbody>{joined_audit}</tbody>"
                    "</table>",
                    unsafe_allow_html=True,
                )

        except FIMAPIError as ex:
            st.error(f"Audit log error: {ex}")


# ==============================================================================
# 6. CONFIGURATION PAGE
# ==============================================================================
elif st.session_state.nav_page == "Configuration":
    render_header("Monitoring Configuration", "Manage monitored filesystem locations and criticality rules.")

    if not is_online:
        render_offline_state()
    else:
        try:
            curr_cfg = client.get_config()
        except FIMAPIError as ex:
            st.error(f"Failed to load config: {ex}")
            curr_cfg = {"monitored_paths": [], "criticality_rules": {"extensions": {}}}

        # Monitored Locations
        st.markdown(
            """
            <div class='section-header-row' style='margin-top:0;'>
                <h3 class='section-title'>Monitored Locations</h3>
                <span class='section-caption'>Filesystem directories monitored for modifications</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        m_paths = curr_cfg.get("monitored_paths", [])
        updated_paths = []

        for idx, mp in enumerate(m_paths):
            c1, c2, c3 = st.columns([5, 2, 1])
            with c1:
                p_val = st.text_input(f"Path #{idx+1}", value=mp.get("path", ""), key=f"cfg_p_{idx}")
            with c2:
                crit_options = ["Critical", "High", "Medium", "Low"]
                default_idx = crit_options.index(mp.get("criticality", "Medium")) if mp.get("criticality") in crit_options else 2
                c_val = st.selectbox(f"Priority #{idx+1}", crit_options, index=default_idx, key=f"cfg_c_{idx}")
            with c3:
                st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
                remove_it = st.checkbox("Remove", key=f"cfg_del_{idx}")

            if not remove_it and p_val.strip():
                updated_paths.append({"path": p_val.strip(), "criticality": c_val})

        with st.expander("+ Add Target Location"):
            a1, a2 = st.columns([3, 1])
            with a1:
                add_p = st.text_input("Directory or File Path", key="cfg_add_p")
            with a2:
                add_c = st.selectbox("Priority Tier", ["Critical", "High", "Medium", "Low"], index=2, key="cfg_add_c")
            if st.button("Add to Target Set"):
                if add_p.strip():
                    updated_paths.append({"path": add_p.strip(), "criticality": add_c})
                    st.success(f"Added `{add_p.strip()}`. Click 'SAVE CHANGES' below to commit.")

        # Criticality Rules
        st.markdown(
            """
            <div class='section-header-row'>
                <h3 class='section-title'>Criticality Rules</h3>
                <span class='section-caption'>Extension-to-priority mapping</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        ext_rules = curr_cfg.get("criticality_rules", {}).get("extensions", {})
        
        # Present extension rules table
        ext_rows = []
        for ext, cr in ext_rules.items():
            ext_rows.append(f"<tr><td><code>{ext}</code></td><td>{get_severity_badge(cr)}</td></tr>")
        
        joined_ext = "".join(ext_rows)
        st.markdown(
            "<table class='saas-table' style='max-width:500px;'>"
            "<thead><tr><th>EXTENSION</th><th>PRIORITY</th></tr></thead>"
            f"<tbody>{joined_ext}</tbody>"
            "</table>",
            unsafe_allow_html=True,
        )

        ext_json = st.text_area(
            "Modify Criticality Mappings (JSON)",
            value=json.dumps(ext_rules, indent=2),
            height=120,
            help="JSON map of file extensions to 'Critical' | 'High' | 'Medium' | 'Low'."
        )

        st.markdown("<div style='margin-top:16px;'></div>", unsafe_allow_html=True)

        if st.button("SAVE CHANGES", type="primary"):
            try:
                parsed_exts = json.loads(ext_json)
                if not isinstance(parsed_exts, dict):
                    st.error("Extension rules must be a valid JSON dictionary.")
                else:
                    payload = {
                        "monitored_paths": updated_paths,
                        "criticality_rules": {"extensions": parsed_exts}
                    }
                    client.update_config(payload)
                    st.success("Configuration successfully updated and persisted.")
                    st.rerun()
            except json.JSONDecodeError:
                st.error("Invalid JSON format in criticality mappings.")
            except FIMAPIError as ex:
                st.error(f"Failed to save configuration: {ex}")

        # Real-time Monitoring Controls
        st.markdown(
            """
            <div class='section-header-row'>
                <h3 class='section-title'>Real-Time Monitoring (Watchdog)</h3>
                <span class='section-caption'>Continuous filesystem intelligence</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        mon_col1, mon_col2, mon_col3 = st.columns([1, 1, 2])
        with mon_col1:
            if st.button("START MONITOR", use_container_width=True, type="primary"):
                try:
                    res = client.start_monitor()
                    st.success(res.get("status", "Started"))
                except FIMAPIError as ex:
                    st.error(f"Failed to start watchdog: {ex}")
        with mon_col2:
            if st.button("STOP MONITOR", use_container_width=True, type="secondary"):
                try:
                    res = client.stop_monitor()
                    st.success(res.get("status", "Stopped"))
                except FIMAPIError as ex:
                    st.error(f"Failed to stop watchdog: {ex}")
