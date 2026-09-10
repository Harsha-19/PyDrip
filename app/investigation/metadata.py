import os
import time
from typing import List
from app.investigation.schemas import ChangeEvidence

class MetadataDetector:
    def analyze(self, file_path: str) -> List[ChangeEvidence]:
        evidence = []
        if not os.path.exists(file_path):
            evidence.append(ChangeEvidence(
                evidence_type="MetadataAnalysis",
                description="Failed to analyze metadata: file does not exist on disk.",
                confidence=1.0
            ))
            return evidence
            
        try:
            stat = os.stat(file_path)
            size = stat.st_size
            mtime = stat.st_mtime
            
            evidence.append(ChangeEvidence(
                evidence_type="MetadataAnalysis",
                description="Current File Size",
                value=f"{size} bytes",
                confidence=1.0
            ))
            evidence.append(ChangeEvidence(
                evidence_type="MetadataAnalysis",
                description="Last Modified Time",
                value=time.ctime(mtime),
                confidence=1.0
            ))
        except Exception as e:
            evidence.append(ChangeEvidence(
                evidence_type="MetadataAnalysis",
                description=f"Error accessing metadata: {str(e)}",
                confidence=1.0
            ))
            
        return evidence
