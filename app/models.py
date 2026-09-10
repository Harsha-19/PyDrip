"""Core integrity engine models, enums, constants, and shared contracts for FIM+."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ChangeType(str, Enum):
    """Permitted change types for file integrity monitoring."""
    ADDED = "ADDED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"


class Criticality(str, Enum):
    """Permitted criticality levels."""
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"


class Severity(str, Enum):
    """Permitted severity levels populated post-scoring."""
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"


# --- SHARED CHANGE CONTRACT ---
# Must match Section 7 of PRD exactly.
# Note: Rohith's module will populate anomaly_score, drift_score, severity later.
class ChangeContract(BaseModel):
    """Shared JSON contract for file changes.
    
    Fields:
    - scan_id: string
    - file_path: string
    - change_type: ADDED | DELETED | MODIFIED
    - old_hash: string | null
    - new_hash: string | null
    - criticality: Critical | High | Medium | Low
    - anomaly_score: float | null (initially null)
    - drift_score: float | null (initially null)
    - severity: Critical | High | Medium | Low | null (initially null)
    - detected_at: timestamp string (ISO 8601 format)
    """
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    file_path: str
    change_type: ChangeType
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    criticality: Criticality
    anomaly_score: Optional[float] = None
    drift_score: Optional[float] = None
    severity: Optional[Severity] = None
    detected_at: str
    evidence: Optional[Any] = None


# --- CONFIGURATION MODELS ---
class MonitoredPathConfig(BaseModel):
    """Configuration for a single monitored path."""
    model_config = ConfigDict(extra="forbid")

    path: str
    criticality: Criticality = Criticality.Medium


class CriticalityRulesConfig(BaseModel):
    """File extension to criticality mapping rules."""
    model_config = ConfigDict(extra="forbid")

    extensions: Dict[str, Criticality] = Field(default_factory=dict)


class AppConfig(BaseModel):
    """Top-level configuration schema loaded from YAML."""
    model_config = ConfigDict(extra="forbid")

    monitored_paths: List[MonitoredPathConfig]
    criticality_rules: CriticalityRulesConfig


# --- DATABASE RECORD MODELS (for type annotations and serialization) ---
class BaselineRecord(BaseModel):
    """Represents a row in the SQLite 'baselines' table."""
    id: Optional[int] = None
    scan_id: str
    file_path: str
    sha256: str
    size_bytes: int
    mtime: float
    criticality: Criticality
    created_at: str


class AuditLogRecord(BaseModel):
    """Represents an entry in the append-only audit_log."""
    id: Optional[int] = None
    action: str
    details: str
    timestamp: str


class ReportResponse(BaseModel):
    """Represents a stored scan report returned by GET /report/{scan_id}."""
    scan_id: str
    report_text: str
    created_at: str


# --- SUMMARY / STATUS MODELS ---
class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"


class BaselineSummaryResponse(BaseModel):
    """Summary response returned by POST /baseline."""
    scan_id: str
    files_indexed: int
    created_at: str
    status: str = "success"


class ScanSummaryResponse(BaseModel):
    """Summary response returned by POST /scan."""
    scan_id: str
    baseline_scan_id: Optional[str] = None
    added_count: int
    deleted_count: int
    modified_count: int
    total_changes: int
    scanned_at: str
