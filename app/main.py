"""FIM+ Core Integrity Engine & Backend API.

Main FastAPI application entry point wiring together all core endpoints.
"""

from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI, HTTPException, status

from app.config import ConfigError, load_config, save_config
from app.core.baseline import BaselineError, MonitoredPathNotFoundError, create_baseline
from app.core.scanner import NoBaselineFoundError, ScanError, run_scan
from app.database import (
    append_audit_log,
    get_audit_history,
    get_changes_by_scan_id,
    get_scan_report_by_scan_id,
    initialize_database,
)
from app.models import (
    AppConfig,
    AuditLogRecord,
    BaselineSummaryResponse,
    ChangeContract,
    HealthResponse,
    ReportResponse,
    ScanSummaryResponse,
)
from pydantic import BaseModel

class SecurityStateResponse(BaseModel):
    incident_risk_score: float
    incident_risk_level: str
    security_state: str
    alert: bool
    affected_files: int
    primary_indicators: List[str]
    last_scan_id: str
    detected_at: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for database initialization on startup."""
    initialize_database()
    yield


app = FastAPI(
    title="FIM+ Core Integrity Engine & Backend API",
    description="Cryptographic File Integrity Monitoring backend API (JP-018)",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ==============================================================================
# HEALTH & CONFIGURATION ENDPOINTS
# ==============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Return system health status."""
    return HealthResponse(status="ok")


@app.get("/config", response_model=AppConfig, tags=["Configuration"])
def get_config() -> AppConfig:
    """Get the current validated YAML configuration."""
    try:
        return load_config()
    except ConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@app.put("/config", response_model=AppConfig, tags=["Configuration"])
def put_config(new_config: AppConfig) -> AppConfig:
    """Update and persist the YAML configuration, recording in the audit log."""
    try:
        save_config(new_config)
        # Record configuration update in append-only audit log
        append_audit_log(
            action="CONFIG_UPDATE",
            details=f"Monitored paths: {len(new_config.monitored_paths)}, rules: {len(new_config.criticality_rules.extensions)}",
        )
        return load_config()
    except ConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ==============================================================================
# INTEGRITY MONITORING ENDPOINTS (BASELINE & SCAN)
# ==============================================================================

@app.post("/baseline", response_model=BaselineSummaryResponse, tags=["Integrity Core"])
def post_baseline() -> BaselineSummaryResponse:
    """Scan configured paths, compute SHA-256 digests, and store a new baseline snapshot."""
    try:
        return create_baseline()
    except MonitoredPathNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except BaselineError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@app.post("/scan", response_model=ScanSummaryResponse, tags=["Integrity Core"])
def post_scan() -> ScanSummaryResponse:
    """Scan current filesystem, compare against latest baseline, and persist detected changes."""
    try:
        return run_scan(auto_enrich=True)
    except NoBaselineFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except MonitoredPathNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except ScanError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@app.get("/changes/{scan_id}", response_model=List[ChangeContract], tags=["Integrity Core"])
def get_changes(scan_id: str) -> List[ChangeContract]:
    """Retrieve all detected changes for a given scan_id adhering to the shared JSON contract."""
    rows = get_changes_by_scan_id(scan_id)
    # Parse rows into ChangeContract models (extra validation)
    return [ChangeContract.model_validate(row) for row in rows]


@app.get("/security/state", response_model=SecurityStateResponse, tags=["Integrity Core"])
def get_security_state() -> SecurityStateResponse:
    """Derive real-time incident security state from the latest scan."""
    from app.database import get_latest_baseline_scan_id
    from app.security_intelligence import calculate_incident_risk, calculate_security_state
    import json
    
    # We find the latest scan with changes.
    # To keep it fast, we can just get all changes for the latest scan_id.
    from app.database import get_db_connection, DEFAULT_DB_PATH
    with get_db_connection(DEFAULT_DB_PATH) as conn:
        cursor = conn.execute("SELECT DISTINCT scan_id, detected_at FROM changes ORDER BY detected_at DESC LIMIT 1;")
        row = cursor.fetchone()
        if not row:
            return SecurityStateResponse(
                incident_risk_score=0.0,
                incident_risk_level="LOW",
                security_state="NORMAL",
                alert=False,
                affected_files=0,
                primary_indicators=[],
                last_scan_id="none",
                detected_at=""
            )
        latest_scan_id = row["scan_id"]
        detected_at = row["detected_at"]
    
    changes = get_changes_by_scan_id(latest_scan_id)
    parsed_changes = []
    indicators = set()
    for ch in changes:
        ch_dict = dict(ch)
        if ch_dict.get("evidence"):
            try:
                ev = json.loads(ch_dict["evidence"])
                ch_dict["evidence"] = ev
                if ev.get("attribution", {}).get("primary_reason") and ev["attribution"]["primary_reason"] != "Routine behavioral activity":
                    indicators.add(ev["attribution"]["primary_reason"])
                if ev.get("is_novel"):
                    indicators.add("Previously unseen behavior")
            except:
                pass
        parsed_changes.append(ch_dict)
        
    incident = calculate_incident_risk(parsed_changes)
    state = calculate_security_state(incident["incident_risk_score"])
    
    return SecurityStateResponse(
        incident_risk_score=incident["incident_risk_score"],
        incident_risk_level=incident["incident_risk_level"],
        security_state=state,
        alert=state in ("HIGH", "CRITICAL"),
        affected_files=incident["affected_files"],
        primary_indicators=list(indicators),
        last_scan_id=latest_scan_id,
        detected_at=detected_at
    )


@app.post("/monitor/start", tags=["Monitoring"])
def start_monitor():
    """Start the real-time FIM watchdog observer."""
    from app.monitor import start_monitoring
    try:
        cfg = load_config()
        start_monitoring(cfg)
        append_audit_log("WATCHDOG_STARTED", "Real-time filesystem monitoring activated")
        return {"status": "Watchdog started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitor/stop", tags=["Monitoring"])
def stop_monitor():
    """Stop the real-time FIM watchdog observer."""
    from app.monitor import stop_monitoring
    try:
        stop_monitoring()
        append_audit_log("WATCHDOG_STOPPED", "Real-time filesystem monitoring deactivated")
        return {"status": "Watchdog stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==============================================================================
# AUDIT & REPORTING ENDPOINTS
# ==============================================================================

@app.get("/audit", response_model=List[AuditLogRecord], tags=["Audit"])
def get_audit() -> List[AuditLogRecord]:
    """Return full append-only audit history in chronological order."""
    rows = get_audit_history()
    return [AuditLogRecord.model_validate(row) for row in rows]


@app.get("/report/{scan_id}", response_model=ReportResponse, tags=["Reporting"])
def get_report(scan_id: str) -> ReportResponse:
    """Retrieve stored investigation report for a scan_id, or generate it from scored changes."""
    report = get_scan_report_by_scan_id(scan_id)
    if report:
        return ReportResponse(
            scan_id=report["scan_id"],
            report_text=report["report_text"],
            created_at=report["created_at"],
        )

    # Check if scan exists in changes table
    changes = get_changes_by_scan_id(scan_id)
    if not changes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation report not found for scan_id: {scan_id}",
        )

    # Generate report on demand using InvestigationReporter orchestrating LLM + Fallback
    try:
        from app.investigation.report import InvestigationReporter
        from app.database import insert_scan_report
        import json

        file_details = []
        for ch in changes:
            ev = {}
            if ch.get("evidence"):
                try:
                    ev = json.loads(ch["evidence"])
                except Exception:
                    pass
            
            file_details.append({
                "file_path": ch["file_path"],
                "change_type": ch["change_type"],
                "criticality": ch.get("criticality", "Medium"),
                "old_hash": ch.get("old_hash"),
                "new_hash": ch.get("new_hash"),
                "hash_status": "Hash mismatch detected" if ch["change_type"] == "MODIFIED" else (
                    "New hash recorded" if ch["change_type"] == "ADDED" else "Old hash recorded"
                ),
                "hash_mismatch": ch["change_type"] == "MODIFIED",
                "anomaly_score": ch.get("anomaly_score"),
                "drift_score": ch.get("drift_score"),
                "semantic_drift_score": ch.get("drift_score"),
                "security_intelligence": ev,
                "evidence": [],
                "risk_assessment": {
                    "score": (ch.get("drift_score") or 0.5) if ch.get("severity") in ("High", "Critical") else 0.1,
                    "severity": (ch.get("severity") or "LOW").upper(),
                    "confidence": 0.85
                },
                "severity_assessment": {
                    "severity": (ch.get("severity") or "LOW").upper(),
                    "numeric_score": 50.0,
                    "reasons": []
                }
            })

        reporter = InvestigationReporter()
        inv_result = {"scan_id": scan_id, "file_details": file_details}
        final_rep = reporter.generate_report(inv_result)
        report_text = final_rep.model_dump_json(indent=2)

        insert_scan_report(scan_id=scan_id, report_text=report_text)
        created_at = final_rep.generated_at

        return ReportResponse(
            scan_id=scan_id,
            report_text=report_text,
            created_at=created_at,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report for scan_id {scan_id}: {exc}",
        )

