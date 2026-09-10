import os
import difflib
from typing import List, Optional
from app.investigation.schemas import ChangeEvidence

class ContentDetector:
    def is_binary(self, file_path: str) -> bool:
        """
        Naive check for binary files by scanning for null bytes.
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:
                    return True
            return False
        except Exception:
            return True # Fallback to safe binary assumption on error

    def analyze(self, file_path: str, baseline_content: Optional[str] = None) -> List[ChangeEvidence]:
        evidence = []
        
        if not os.path.exists(file_path):
            evidence.append(ChangeEvidence(
                evidence_type="ContentAnalysis",
                description="File missing, cannot perform content diff.",
                confidence=1.0
            ))
            return evidence

        if self.is_binary(file_path):
            evidence.append(ChangeEvidence(
                evidence_type="ContentAnalysis",
                description="Binary modification detected, content diff unavailable.",
                confidence=1.0
            ))
            return evidence

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                current_content = f.read()
        except UnicodeDecodeError:
             evidence.append(ChangeEvidence(
                evidence_type="ContentAnalysis",
                description="Binary modification detected, content diff unavailable.",
                confidence=1.0
            ))
             return evidence
        except Exception as e:
             evidence.append(ChangeEvidence(
                evidence_type="ContentAnalysis",
                description=f"Error reading content: {str(e)}",
                confidence=1.0
            ))
             return evidence

        # If baseline content exists, run diff
        if baseline_content is not None:
            base_lines = baseline_content.splitlines()
            curr_lines = current_content.splitlines()
            
            # Exact match short-circuit
            if base_lines == curr_lines:
                evidence.append(ChangeEvidence(
                    evidence_type="ContentAnalysis",
                    description="Content is unchanged.",
                    confidence=1.0
                ))
                return evidence
                
            diff = list(difflib.unified_diff(base_lines, curr_lines, n=0))
            
            additions = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
            deletions = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
            
            evidence.append(ChangeEvidence(
                evidence_type="ContentAnalysis",
                description="Content changed",
                value=f"Additions: {additions}, Deletions: {deletions}",
                confidence=1.0
            ))
        else:
             evidence.append(ChangeEvidence(
                evidence_type="ContentAnalysis",
                description="No baseline content provided to compare.",
                confidence=1.0
            ))
            
        return evidence
