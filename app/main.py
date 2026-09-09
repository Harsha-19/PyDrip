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
        return run_scan()
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
    """Retrieve stored investigation report for a scan_id."""
    report = get_scan_report_by_scan_id(scan_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation report not found for scan_id: {scan_id}",
        )
    return ReportResponse(
        scan_id=report["scan_id"],
        report_text=report["report_text"],
        created_at=report["created_at"],
    )
