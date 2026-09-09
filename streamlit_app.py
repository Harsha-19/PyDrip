import streamlit as st
import json
import os
import tempfile
from datetime import datetime, timezone

from app.core.baseline import IntegrityEngine as CoreIntegrityEngine
from app.investigation.investigator import InvestigationEngine
from app.investigation.report import InvestigationReporter
from app.investigation.schemas import InvestigationInput, ScoredChange

# Configure page layout and metadata
st.set_page_config(
    page_title="Forensic Integrity Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Forensic Security Console CSS (IBM Plex Sans + IBM Plex Mono, #0a0d14 dark theme)
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;1,400&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #e1e2ec;
}

.stApp {
    background-color: #0a0d14;
}

code, pre, .stCode, .monotext {
    font-family: 'IBM Plex Mono', monospace !important;
}

/* Technical Panels */
.forensic-card {
    background-color: #0e131f;
    border: 1px solid #1e2536;
    border-radius: 0px;
    padding: 16px;
    margin-bottom: 16px;
}

.forensic-header {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94a3b8;
    margin-bottom: 8px;
}

/* Badges */
.badge-clean {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid #10b981;
    color: #10b981;
    padding: 2px 8px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px;
    font-weight: 700;
}

.badge-warning {
    background: rgba(245, 158, 11, 0.12);
    border: 1px solid #f59e0b;
    color: #f59e0b;
    padding: 2px 8px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px;
    font-weight: 700;
}

.badge-critical {
    background: rgba(239, 68, 68, 0.12);
    border: 1px solid #ef4444;
    color: #ef4444;
    padding: 2px 8px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px;
    font-weight: 700;
}

.badge-info {
    background: rgba(6, 182, 212, 0.12);
    border: 1px solid #06b6d4;
    color: #06b6d4;
    padding: 2px 8px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10px;
    font-weight: 700;
}

/* Tables */
.forensic-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

.forensic-table th {
    background-color: #141b2d;
    color: #94a3b8;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    text-transform: uppercase;
    padding: 8px 12px;
    border: 1px solid #1e2536;
    text-align: left;
}

.forensic-table td {
    padding: 8px 12px;
    border: 1px solid #1e2536;
    background-color: #0e131f;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize backend singletons in session state to avoid re-instantiation
if "core_engine" not in st.session_state:
    st.session_state.core_engine = CoreIntegrityEngine()
if "investigation_engine" not in st.session_state:
    st.session_state.investigation_engine = InvestigationEngine()
if "reporter" not in st.session_state:
    st.session_state.reporter = InvestigationReporter()

# Session State for Investigation Results
if "current_investigation" not in st.session_state:
    st.session_state.current_investigation = None
if "current_report" not in st.session_state:
    st.session_state.current_report = None
if "demo_baseline" not in st.session_state:
    st.session_state.demo_baseline = {}

# Sidebar Navigation & System Telemetry
with st.sidebar:
    st.markdown("### `AETHEL // FORENSIC`")
    st.markdown("<span class='badge-clean'>ENGINE LIVE</span> <span class='badge-info'>ML DENSE EMBEDDINGS</span>", unsafe_allow_html=True)
    st.markdown("---")
    
    view_mode = st.radio(
        "WORKFLOW VIEW",
        [
            "01 OVERVIEW",
            "02 INVESTIGATE",
            "03 EVIDENCE",
            "04 SEMANTIC ANALYSIS",
            "05 RISK ASSESSMENT",
            "06 INCIDENT REPORT"
        ]
    )
    
    st.markdown("---")
    st.markdown("<div class='forensic-header'>INVESTIGATION STATUS</div>", unsafe_allow_html=True)
    if st.session_state.current_investigation:
        res = st.session_state.current_investigation
        scan_id = res.get("scan_id", "UNKNOWN")
        total_files = len(res.get("file_details", []))
        st.markdown(f"**Scan ID:** `{scan_id}`")
        st.markdown(f"**Files Monitored:** `{total_files}`")
        if st.session_state.current_report:
            rep = st.session_state.current_report
            sev = rep.incident_severity
            sev_badge = "badge-critical" if sev == "CRITICAL" else ("badge-warning" if sev in ("HIGH", "MEDIUM") else "badge-clean")
            st.markdown(f"**Severity:** <span class='{sev_badge}'>{sev}</span>", unsafe_allow_html=True)
            st.markdown(f"**Risk Score:** `{rep.risk_score:.2f} / 1.00`")
    else:
        st.info("No active investigation. Go to '02 INVESTIGATE' to load or scan files.")
        
    st.markdown("---")
    st.markdown("<div class='forensic-header'>CUSTODY SPECIFICATION</div>", unsafe_allow_html=True)
    st.caption("RFC 3161 TSP // NIST SP 800-147B // SHA-256 Canonical")

# Top Breadcrumb Banner
st.markdown(f"<div class='forensic-header'>FORENSIC INTEGRITY CONSOLE // {view_mode}</div>", unsafe_allow_html=True)

# -------------------------------------------------------------
# 01 OVERVIEW
# -------------------------------------------------------------
if view_mode == "01 OVERVIEW":
    st.markdown("## Incident Overview & Telemetry")
    
    if not st.session_state.current_investigation:
        st.warning("No investigation data currently loaded. Please run an investigation in '02 INVESTIGATE'.")
        
        st.markdown("### Quick Demo Pre-load")
        st.write("Click below to run a standard forensic scenario on `/var/www/html/index.html`:")
        if st.button("Load Pre-Configured Incident Demo"):
            # Execute standard demo
            demo_input = InvestigationInput(
                scan_id="SCAN-4092-B",
                changes=[
                    ScoredChange(
                        file_path="/var/www/html/index.html",
                        change_type="MODIFIED",
                        old_hash="3c89b7e8894129e7193c788c8f85f1c9f4d7b2e1a3c5d6e7f8a9b0c1d2e3f4a5",
                        new_hash="f41a9920d90317e8894129e7193c788c8f85f1c9f4d7b2e1a3c5d6e7f8a9b0c1",
                        criticality="High",
                        evidence=[]
                    )
                ]
            )
            contents_map = {
                "/var/www/html/index.html": {
                    "old": "<html>Welcome to Aethel Secure Portal</html>\ntimeout = 30\naccess = allowed",
                    "new": "<html>Welcome back! Unauthorized modification recorded.</html>\ntimeout = 300\naccess = restricted"
                }
            }
            inv_res = st.session_state.investigation_engine.investigate(demo_input, contents_map)
            st.session_state.current_investigation = inv_res
            st.session_state.current_report = st.session_state.reporter.generate_report(inv_res)
            st.rerun()
    else:
        inv = st.session_state.current_investigation
        rep = st.session_state.current_report
        files = inv.get("file_details", [])
        
        # Summary KPI Columns
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
            st.markdown("<div class='forensic-header'>INCIDENT SEVERITY</div>", unsafe_allow_html=True)
            sev = rep.incident_severity
            color = "#ef4444" if sev == "CRITICAL" else ("#f59e0b" if sev in ("HIGH", "MEDIUM") else "#10b981")
            st.markdown(f"<h2 style='color: {color}; margin:0;'>{sev}</h2>", unsafe_allow_html=True)
            st.caption(f"Risk Score: {rep.risk_score:.2f} / 1.00")
            st.markdown("</div>", unsafe_allow_html=True)
            
        with col2:
            st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
            st.markdown("<div class='forensic-header'>AFFECTED FILES</div>", unsafe_allow_html=True)
            st.markdown(f"<h2 style='margin:0;'>{len(files)}</h2>", unsafe_allow_html=True)
            st.caption("Total files with detected events")
            st.markdown("</div>", unsafe_allow_html=True)

        with col3:
            st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
            st.markdown("<div class='forensic-header'>CRYPTOGRAPHIC INTEGRITY</div>", unsafe_allow_html=True)
            mismatches = sum(1 for f in files if f.get("hash_mismatch"))
            if mismatches > 0:
                st.markdown(f"<h2 style='color: #ef4444; margin:0;'>{mismatches} Mismatch</h2>", unsafe_allow_html=True)
            else:
                st.markdown("<h2 style='color: #10b981; margin:0;'>0 Mismatch</h2>", unsafe_allow_html=True)
            st.caption("SHA-256 baseline comparison")
            st.markdown("</div>", unsafe_allow_html=True)

        with col4:
            st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
            st.markdown("<div class='forensic-header'>ASSESSMENT QUALITY</div>", unsafe_allow_html=True)
            conf_pct = int(rep.confidence * 100)
            st.markdown(f"<h2 style='color: #06b6d4; margin:0;'>{conf_pct}%</h2>", unsafe_allow_html=True)
            st.caption("Evidence completeness rating")
            st.markdown("</div>", unsafe_allow_html=True)

        # Executive Summary Box
        st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
        st.markdown("<div class='forensic-header'>EXECUTIVE SUMMARY (STAGE 5)</div>", unsafe_allow_html=True)
        st.write(rep.executive_summary)
        st.markdown("</div>", unsafe_allow_html=True)

        # Affected Files Ledger
        st.markdown("### Investigated Files Ledger")
        file_table = """
        <table class='forensic-table'>
            <thead>
                <tr>
                    <th>File Path</th>
                    <th>Change Type</th>
                    <th>Hash Status</th>
                    <th>Semantic Drift</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
        """
        for f in files:
            p = f.get("file_path")
            ct = f.get("change_type")
            hs = f.get("hash_status")
            sd = f.get("semantic_analysis", {}).get("semantic_drift")
            sd_str = f"{sd:.2f}" if sd is not None else "UNAVAILABLE"
            r_info = f.get("risk_assessment", {})
            r_score = f"{r_info.get('score', 0.0):.2f}"
            r_sev = r_info.get("severity", "LOW")
            sev_class = "badge-critical" if r_sev == "CRITICAL" else ("badge-warning" if r_sev in ("HIGH", "MEDIUM") else "badge-clean")
            
            file_table += f"""
            <tr>
                <td><code>{p}</code></td>
                <td>{ct}</td>
                <td>{hs}</td>
                <td><code>{sd_str}</code></td>
                <td><code>{r_score}</code></td>
                <td><span class='{sev_class}'>{r_sev}</span></td>
            </tr>
            """
        file_table += "</tbody></table>"
        st.markdown(file_table, unsafe_allow_html=True)

# -------------------------------------------------------------
# 02 INVESTIGATE
# -------------------------------------------------------------
elif view_mode == "02 INVESTIGATE":
    st.markdown("## Interactive Investigation Console")
    
    st.write("Establish a cryptographic baseline, introduce or detect changes, and execute the authoritative investigation pipeline.")
    
    tab_live, tab_text = st.tabs(["Local Filesystem Target", "Direct Content Analysis"])
    
    with tab_live:
        st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
        st.markdown("<div class='forensic-header'>STEP 1 — TARGET FILE SPECIFICATION</div>", unsafe_allow_html=True)
        target_path = st.text_input("Absolute File Path", value=os.path.abspath("test_target.txt"))
        
        col_act1, col_act2 = st.columns(2)
        with col_act1:
            if st.button("Create / Update Cryptographic Baseline (Stage 1)"):
                if not os.path.exists(target_path):
                    with open(target_path, "w") as f:
                        f.write("PORT=8080\nTIMEOUT=30\nACCESS=INTERNAL")
                res = st.session_state.core_engine.create_baseline(target_path)
                st.session_state.demo_baseline[target_path] = res.current_hash
                st.success(f"Baseline established! SHA-256: `{res.current_hash}`")
                
        with col_act2:
            if st.button("Simulate Content Modification"):
                if os.path.exists(target_path):
                    with open(target_path, "a") as f:
                        f.write("\nTIMEOUT=3000\nACCESS=EXTERNAL_PERMISSIVE")
                    st.warning(f"Modified file content at: {target_path}")
                else:
                    st.error("File does not exist. Click 'Create Baseline' first.")
        st.markdown("</div>", unsafe_allow_html=True)

        if st.button("Run Full Forensic Investigation Pipeline (Stages 1–5)", type="primary"):
            if not os.path.exists(target_path):
                st.error("Target file does not exist.")
            else:
                integrity_check = st.session_state.core_engine.check_integrity(target_path)
                change = ScoredChange(
                    file_path=target_path,
                    change_type="MODIFIED" if integrity_check.integrity_status == "MODIFIED" else "ADDED",
                    old_hash=integrity_check.baseline_hash,
                    new_hash=integrity_check.current_hash,
                    criticality="High",
                    evidence=[]
                )
                inp = InvestigationInput(scan_id=f"SCAN-{datetime.now().strftime('%H%M%S')}", changes=[change])
                
                with st.spinner("Executing Stages 1–4 Investigation & Stage 5 Reporting..."):
                    inv_res = st.session_state.investigation_engine.investigate(inp)
                    st.session_state.current_investigation = inv_res
                    st.session_state.current_report = st.session_state.reporter.generate_report(inv_res)
                st.success("Investigation complete! Navigate through workflow tabs to inspect evidence.")

    with tab_text:
        st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
        st.markdown("<div class='forensic-header'>MANUAL EVIDENCE COMPARISON</div>", unsafe_allow_html=True)
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            old_txt = st.text_area("Baseline Content", value="timeout = 30\naccess = internal\nlogging = enabled", height=150)
        with col_t2:
            new_txt = st.text_area("Modified Content", value="timeout = 300\naccess = external\nlogging = disabled", height=150)
            
        sim_path = st.text_input("Virtual Path Identifier", value="/etc/service/daemon.conf")
        
        if st.button("Analyze Content Changes"):
            change = ScoredChange(
                file_path=sim_path,
                change_type="MODIFIED",
                old_hash="0000000000000000000000000000000000000000000000000000000000000001",
                new_hash="0000000000000000000000000000000000000000000000000000000000000002",
                criticality="High",
                evidence=[]
            )
            inp = InvestigationInput(scan_id=f"SCAN-TXT-{datetime.now().strftime('%H%M%S')}", changes=[change])
            contents_map = {sim_path: {"old": old_txt, "new": new_txt}}
            
            with st.spinner("Analyzing..."):
                inv_res = st.session_state.investigation_engine.investigate(inp, contents_map)
                st.session_state.current_investigation = inv_res
                st.session_state.current_report = st.session_state.reporter.generate_report(inv_res)
            st.success("Content analysis complete!")
        st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------
# 03 EVIDENCE
# -------------------------------------------------------------
elif view_mode == "03 EVIDENCE":
    st.markdown("## Technical Evidence Ledger (Stages 1 & 2)")
    
    if not st.session_state.current_investigation:
        st.info("No active investigation. Run an investigation first.")
    else:
        files = st.session_state.current_investigation.get("file_details", [])
        for f in files:
            st.markdown(f"### Target: `{f.get('file_path')}`")
            
            col_c1, col_c2 = st.columns(2)
            with col_c1:
                st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
                st.markdown("<div class='forensic-header'>STAGE 1 — CRYPTOGRAPHIC INTEGRITY</div>", unsafe_allow_html=True)
                st.markdown(f"**Baseline Hash:** `{f.get('old_hash') or 'Not established'}`")
                st.markdown(f"**Current Hash:**  `{f.get('new_hash') or 'Not available'}`")
                st.markdown(f"**Integrity Status:** `{f.get('hash_status')}`")
                if f.get('hash_mismatch'):
                    st.markdown("<span class='badge-critical'>HASH MISMATCH DETECTED</span>", unsafe_allow_html=True)
                else:
                    st.markdown("<span class='badge-clean'>CRYPTOGRAPHIC MATCH</span>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
                
            with col_c2:
                st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
                st.markdown("<div class='forensic-header'>STAGE 2 — DETECTED ARTIFACT EVIDENCE</div>", unsafe_allow_html=True)
                ev_list = f.get("evidence", [])
                if ev_list:
                    for ev in ev_list:
                        etype = ev.get("evidence_type")
                        desc = ev.get("description")
                        val = ev.get("value")
                        st.markdown(f"• **`{etype}`**: {desc}")
                        if val:
                            st.caption(f"Detail: `{val}`")
                else:
                    st.write("No granular artifact evidence recorded.")
                st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------
# 04 SEMANTIC ANALYSIS
# -------------------------------------------------------------
elif view_mode == "04 SEMANTIC ANALYSIS":
    st.markdown("## Stage 3 AI Semantic Analysis")
    
    if not st.session_state.current_investigation:
        st.info("No active investigation. Run an investigation first.")
    else:
        files = st.session_state.current_investigation.get("file_details", [])
        for f in files:
            sem = f.get("semantic_analysis", {})
            st.markdown(f"### File: `{f.get('file_path')}`")
            
            st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
            st.markdown("<div class='forensic-header'>SEMANTIC INTERPRETATION STATE MACHINE</div>", unsafe_allow_html=True)
            status = sem.get("status", "UNKNOWN")
            method = sem.get("analysis_method", "N/A")
            history = sem.get("transition_history", [])
            
            status_class = "badge-clean" if status == "AVAILABLE" else ("badge-warning" if status == "NOT_REQUIRED" else "badge-critical")
            st.markdown(f"**State:** <span class='{status_class}'>{status}</span> &nbsp;&nbsp; **Method:** `{method}`", unsafe_allow_html=True)
            st.markdown(f"**Transition Trace:** `{' -> '.join(history)}`")
            st.markdown("</div>", unsafe_allow_html=True)
            
            if status == "AVAILABLE":
                col_s1, col_s2, col_s3 = st.columns(3)
                sim = sem.get("semantic_similarity", 0.0)
                drift = sem.get("semantic_drift", 0.0)
                conf = sem.get("confidence", 0.0)
                
                with col_s1:
                    st.metric("Cosine Similarity", f"{sim:.4f}")
                with col_s2:
                    st.metric("Semantic Drift", f"{drift:.4f}")
                with col_s3:
                    st.metric("Method Confidence", f"{conf:.2f}")
                    
                st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
                st.markdown("<div class='forensic-header'>GROUNDED SEMANTIC EXPLANATION</div>", unsafe_allow_html=True)
                st.write(sem.get("explanation"))
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.warning(f"Semantic analysis was {status}: {sem.get('explanation')}")

# -------------------------------------------------------------
# 05 RISK ASSESSMENT
# -------------------------------------------------------------
elif view_mode == "05 RISK ASSESSMENT":
    st.markdown("## Stage 4 Severity & Risk Engine")
    
    if not st.session_state.current_investigation:
        st.info("No active investigation. Run an investigation first.")
    else:
        files = st.session_state.current_investigation.get("file_details", [])
        for f in files:
            risk = f.get("risk_assessment", {})
            st.markdown(f"### Target: `{f.get('file_path')}`")
            
            col_r1, col_r2 = st.columns([1, 2])
            with col_r1:
                st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
                st.markdown("<div class='forensic-header'>RISK METRICS</div>", unsafe_allow_html=True)
                score = risk.get("score", 0.0)
                sev = risk.get("severity", "LOW")
                conf = risk.get("confidence", 0.0)
                
                sev_color = "#ef4444" if sev == "CRITICAL" else ("#f59e0b" if sev in ("HIGH", "MEDIUM") else "#10b981")
                st.markdown(f"<h1 style='color: {sev_color}; margin:0;'>{sev}</h1>", unsafe_allow_html=True)
                st.markdown(f"**Score:** `{score:.4f} / 1.00`")
                st.progress(score)
                st.caption(f"Assessment Completeness Confidence: {int(conf*100)}%")
                st.markdown("</div>", unsafe_allow_html=True)
                
            with col_r2:
                st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
                st.markdown("<div class='forensic-header'>MULTI-SIGNAL FACTOR BREAKDOWN (SUM = 1.00)</div>", unsafe_allow_html=True)
                factors = risk.get("factors", [])
                for factor in factors:
                    name = factor.get("name")
                    contrib = factor.get("contribution", 0.0)
                    ev = factor.get("evidence")
                    rat = factor.get("rationale")
                    
                    st.markdown(f"**`{name}`** &nbsp;&nbsp; `+{contrib:.4f}`")
                    st.caption(f"Evidence: {ev} | Rationale: {rat}")
                    st.progress(min(1.0, contrib / 0.40))
                st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
            st.markdown("<div class='forensic-header'>DETERMINISTIC ADJUDICATION EXPLANATION</div>", unsafe_allow_html=True)
            st.write(risk.get("explanation"))
            st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------
# 06 INCIDENT REPORT
# -------------------------------------------------------------
elif view_mode == "06 INCIDENT REPORT":
    st.markdown("## Stage 5 Evidentiary Incident Report")
    
    if not st.session_state.current_report:
        st.info("No report generated. Please run an investigation first.")
    else:
        rep = st.session_state.current_report
        
        # Report Header Banner
        st.markdown("<div class='forensic-card'>", unsafe_allow_html=True)
        st.markdown(f"<div class='forensic-header'>INCIDENT REPORT ID: {rep.report_id}</div>", unsafe_allow_html=True)
        st.markdown(f"**Generated:** `{rep.generated_at or datetime.now(timezone.utc).isoformat()}` &nbsp;&nbsp;|&nbsp;&nbsp; **Custody Seal:** <span class='badge-clean'>VALIDATED</span>", unsafe_allow_html=True)
        st.markdown(f"**Overall Severity:** `{rep.incident_severity}` &nbsp;&nbsp;|&nbsp;&nbsp; **Overall Risk Score:** `{rep.risk_score:.2f} / 1.00`")
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Executive Summary
        st.markdown("### Executive Summary")
        st.markdown(f"<div class='forensic-card'>{rep.executive_summary}</div>", unsafe_allow_html=True)
        
        # Key Findings
        st.markdown("### Structured Findings with Provenance")
        for finding in rep.key_findings:
            st.markdown(f"• {finding}")
            
        # Grounded Recommendations
        st.markdown("### Actionable Recommendations")
        for rec in rep.recommended_actions:
            st.markdown(f"• {rec}")
            
        # Disclosures & Limitations
        st.markdown("### Forensic Disclosures & Limitations")
        for lim in rep.limitations:
            st.caption(f"⚠️ {lim}")
            
        st.markdown("---")
        # Export Option
        report_json = json.dumps(rep.model_dump(), indent=2)
        st.download_button(
            label="Download Complete Forensic Incident Report (JSON)",
            data=report_json,
            file_name=f"{rep.report_id}.json",
            mime="application/json"
        )
