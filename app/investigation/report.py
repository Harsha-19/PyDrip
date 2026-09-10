import os
import json
import urllib.request
import urllib.error
import logging

logger = logging.getLogger(__name__)
from abc import ABC, abstractmethod
from typing import Literal
from pydantic import BaseModel, Field

class FinalInvestigationReport(BaseModel):
    """
    Pydantic model representing the human-readable forensic report structure.
    """
    report_id: str = Field(default="REP-UNKNOWN")
    scan_id: str
    generated_at: str = Field(default="")
    incident_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    generation_method: Literal["groq", "fallback", "deterministic"] = Field(default="fallback")
    executive_summary: str
    key_findings: list[str] = Field(default_factory=list)
    evidence_analysis: list[str] = Field(default_factory=list)
    evidence_ledger: list[dict] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    possible_causes: list[str] = Field(default_factory=list)
    confidence_assessment: str = Field(default="")
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

class ReportGenerator(ABC):
    @abstractmethod
    def generate(self, investigation_result: dict) -> FinalInvestigationReport:
        pass

class LLMReportGenerator(ReportGenerator):
    """
    Generates a natural language report using Groq API.
    Raises exceptions cleanly if network fails or API key is absent.
    """
    def generate(self, investigation_result: dict) -> FinalInvestigationReport:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY is missing. Cannot use Groq.")
            
        model = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")
            
        prompt = (
            "You are the FIM+ Security Investigation Analyst.\n\n"
            "Your job is to explain structured file-integrity evidence to a security analyst.\n\n"
            "The supplied evidence is authoritative.\n"
            "Never invent facts.\n"
            "Never invent files, timestamps, hashes, scores, severity, risk, historical events, or attack attribution.\n"
            "Never calculate or override SHA-256.\n"
            "Never calculate or override anomaly score.\n"
            "Never calculate or override semantic drift.\n"
            "Never calculate or override severity.\n"
            "Never calculate or override incident risk.\n"
            "Never change the security state.\n\n"
            "Treat deterministic FIM+ calculations as authoritative.\n\n"
            "Clearly distinguish:\n"
            "1. Cryptographic facts\n"
            "2. Behavioral indicators\n"
            "3. Semantic indicators\n"
            "4. Historical context\n"
            "5. Deterministic incident risk\n"
            "6. Analyst interpretation\n\n"
            "Do not claim malicious intent unless the supplied evidence explicitly supports such a conclusion.\n"
            "When evidence is insufficient, say that evidence is insufficient.\n\n"
            "Produce a concise professional security investigation report.\n\n"
            "Respond purely in JSON format exactly matching these keys:\n"
            "executive_summary (string), incident_severity (string), key_findings (array of strings), "
            "evidence_analysis (array of strings), affected_files (array of strings), "
            "possible_causes (array of strings), confidence_assessment (string), recommended_actions (array of strings), "
            "limitations (array of strings)."
        )
        
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps({
                "model": model,
                "messages": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": json.dumps(investigation_result)}
                ],
                "response_format": { "type": "json_object" }
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "FIM_Plus/1.0"
            }
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result_json = json.loads(response.read())
                content = result_json["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                parsed["scan_id"] = investigation_result.get("scan_id", "UNKNOWN")
                parsed["generation_method"] = "groq"
                return FinalInvestigationReport(**parsed)
        except Exception as e:
            raise RuntimeError(f"Groq API request/parsing failed: {e}")

class InvestigationReporter:
    """
    Orchestrates report generation, ensuring LLM isolation and deterministic severity override.
    """
    def __init__(self):
        from app.investigation.fallbackai import TemplateReportGenerator
        self.template_generator = TemplateReportGenerator()
        self.llm_generator = LLMReportGenerator()
        
    def generate_report(self, investigation_result: dict) -> FinalInvestigationReport:
        # 1. Deterministically calculate overall incident severity.
        # This completely isolates the severity score from the LLM's opinion.
        files = investigation_result.get("file_details", [])
        
        # New: Use Security Intelligence Orchestrator if available
        parsed_changes = []
        for f in files:
            parsed = dict(f)
            # Re-map so calculate_incident_risk can read it
            parsed["anomaly_score"] = f.get("anomaly_score")
            parsed["drift_score"] = f.get("drift_score")
            parsed["severity"] = f.get("severity_assessment", {}).get("severity", "LOW")
            sec_int = f.get("security_intelligence", {})
            parsed["novelty_score"] = sec_int.get("novelty_score", 0.0)
            parsed["recurrence_score"] = sec_int.get("recurrence_score", 0.0)
            parsed_changes.append(parsed)
            
        try:
            from app.security_intelligence import calculate_incident_risk, calculate_security_state
            incident_data = calculate_incident_risk(parsed_changes)
            overall_severity = incident_data["incident_risk_level"]
            max_risk = incident_data["incident_risk_score"]
        except ImportError:
            # Fallback to old heuristic
            severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            overall_severity = "LOW"
            max_rank = 1
            max_risk = 0.0
            
            for f in files:
                sev = f.get("severity_assessment", {}).get("severity", "LOW")
                if severity_ranks.get(sev, 1) > max_rank:
                    max_rank = severity_ranks.get(sev, 1)
                    overall_severity = sev
                risk = f.get("risk_assessment", {}).get("score", 0.0)
                if risk > max_risk:
                    max_risk = risk

        # 2. Attempt Groq generation
        report = None
        try:
            report = self.llm_generator.generate(investigation_result)
            logger.info("Groq report generation succeeded.")
        except Exception as e:
            # 3. Fallback to template if Groq is unavailable or fails validation
            logger.warning(f"Groq generation failed ({type(e).__name__}: {e}). Triggering deterministic fallback.")
            logger.info("Fallback report generation started.")
            report = self.template_generator.generate(investigation_result)
            logger.info("Fallback report generation succeeded.")
            
        # 4. Enforce Severity & Risk Rule
        # Guarantee that no matter what the LLM or template emitted, the final
        # severity and risk score match the deterministic pipeline computation.
        report.incident_severity = overall_severity
        report.risk_score = round(max_risk, 4)
        
        return report
