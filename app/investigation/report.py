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
    generation_method: Literal["llm", "fallback", "deterministic"] = Field(default="fallback")
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
    Generates a natural language report using OpenAI's API.
    Raises exceptions cleanly if network fails or API key is absent.
    """
    def generate(self, investigation_result: dict) -> FinalInvestigationReport:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is missing. Cannot use LLM.")
            
        prompt = (
            "You are generating a cybersecurity file-integrity investigation report.\n"
            "Use ONLY the supplied structured investigation data.\n"
            "Do not invent evidence, events, users, processes, timestamps, causes, or technical facts.\n"
            "Do not calculate a new severity. Do not change or override the supplied severity.\n"
            "Clearly distinguish observed evidence from interpretation.\n"
            "Possible causes must be presented as possibilities, not confirmed facts.\n"
            "Every important claim must be traceable to supplied evidence.\n"
            "Produce a professional investigation report for a security/IT audience.\n"
            "Respond purely in JSON format exactly matching these keys:\n"
            "executive_summary (string), incident_severity (string), key_findings (array of strings), "
            "evidence_analysis (array of strings), affected_files (array of strings), "
            "possible_causes (array of strings), confidence_assessment (string), recommended_actions (array of strings)."
        )
        
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps({
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": json.dumps(investigation_result)}
                ],
                "response_format": { "type": "json_object" }
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
        )
        
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                result_json = json.loads(response.read())
                content = result_json["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                parsed["scan_id"] = investigation_result.get("scan_id", "UNKNOWN")
                parsed["generation_method"] = "llm"
                return FinalInvestigationReport(**parsed)
        except Exception as e:
            raise RuntimeError(f"LLM API request/parsing failed: {e}")

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
        severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        overall_severity = "LOW"
        max_rank = 1
        
        for f in files:
            sev = f.get("severity_assessment", {}).get("severity", "LOW")
            if severity_ranks.get(sev, 1) > max_rank:
                max_rank = severity_ranks.get(sev, 1)
                overall_severity = sev

        # 2. Attempt LLM generation
        report = None
        try:
            report = self.llm_generator.generate(investigation_result)
            logger.info("LLM report generation succeeded.")
        except Exception as e:
            # 3. Fallback to template if LLM is unavailable or fails validation
            logger.warning(f"LLM generation failed ({type(e).__name__}: {e}). Triggering deterministic fallback.")
            logger.info("Fallback report generation started.")
            report = self.template_generator.generate(investigation_result)
            logger.info("Fallback report generation succeeded.")
            
        # 4. Enforce Severity & Risk Rule
        # Guarantee that no matter what the LLM or template emitted, the final
        # severity and risk score match the deterministic pipeline computation.
        max_risk = 0.0
        for f in files:
            risk = f.get("risk_assessment", {}).get("score", 0.0)
            if risk > max_risk:
                max_risk = risk
                
        report.incident_severity = overall_severity
        report.risk_score = round(max_risk, 4)
        
        return report
