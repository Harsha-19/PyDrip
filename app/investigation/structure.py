import os
import json
from typing import List
from app.investigation.schemas import ChangeEvidence

class StructureDetector:
    def analyze(self, file_path: str) -> List[ChangeEvidence]:
        evidence = []
        if not os.path.exists(file_path):
            evidence.append(ChangeEvidence(
                evidence_type="StructureAnalysis",
                description="Failed to analyze structure: file does not exist.",
                confidence=1.0
            ))
            return evidence
            
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".json":
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    key_count = len(data) if isinstance(data, dict) else len(data) if isinstance(data, list) else 0
                    evidence.append(ChangeEvidence(
                        evidence_type="StructureAnalysis",
                        description=f"Valid JSON document",
                        value=f"Root element count: {key_count}",
                        confidence=1.0
                    ))
            except json.JSONDecodeError:
                evidence.append(ChangeEvidence(
                    evidence_type="StructureAnalysis",
                    description="Invalid JSON format",
                    confidence=1.0
                ))
            except Exception as e:
                 evidence.append(ChangeEvidence(
                    evidence_type="StructureAnalysis",
                    description=f"Error parsing JSON: {str(e)}",
                    confidence=1.0
                ))
        else:
            evidence.append(ChangeEvidence(
                evidence_type="StructureAnalysis",
                description="Unsupported analysis explicitly reported for this file type.",
                confidence=1.0
            ))
            
        return evidence
