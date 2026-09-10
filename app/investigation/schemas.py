from typing import Literal
from pydantic import BaseModel, Field

# ---------------------------------------------------------
# INPUT MODELS
# ---------------------------------------------------------

class ChangeEvidence(BaseModel):
    evidence_type: str
    description: str
    value: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class SemanticResult(BaseModel):
    """
    Structured outcome of Stage 3 AI Semantic Analysis.
    Confidence represents a deterministic method-based estimate (e.g., neural dense embedding
    vs. sequence matching fallback) adjusted for input characteristics, not statistical model certainty.
    """
    status: Literal["NOT_REQUIRED", "PENDING", "ANALYZING", "AVAILABLE", "FALLBACK", "UNAVAILABLE", "ERROR"]
    semantic_similarity: float | None = None
    semantic_drift: float | None = None
    analysis_method: Literal["sentence_transformer", "fallback"] | None = None
    confidence: float | None = None
    explanation: str | None = None
    transition_history: list[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    name: str
    contribution: float = Field(ge=0.0, le=1.0)
    evidence: str
    rationale: str


class RiskResult(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    factors: list[RiskFactor] = Field(default_factory=list)
    explanation: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class ScoredChange(BaseModel):
    file_path: str
    change_type: Literal["ADDED", "DELETED", "MODIFIED"]
    old_hash: str | None = None
    new_hash: str | None = None
    criticality: Literal["Critical", "High", "Medium", "Low"]
    anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)
    drift_score: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: list[ChangeEvidence]
    semantic_analysis: SemanticResult | None = None
    risk_assessment: RiskResult | None = None


class InvestigationInput(BaseModel):
    scan_id: str
    changes: list[ScoredChange]


# ---------------------------------------------------------
# OUTPUT MODELS
# ---------------------------------------------------------

class InvestigationFinding(BaseModel):
    title: str
    description: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    evidence: list[str]
    confidence: float = Field(ge=0.0, le=1.0)


class InvestigationReport(BaseModel):
    scan_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    executive_summary: str
    findings: list[InvestigationFinding]
    evidence_summary: list[str]
    possible_causes: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_actions: list[str]
