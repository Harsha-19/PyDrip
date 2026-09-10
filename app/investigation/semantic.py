import difflib
from typing import Optional
from app.investigation.drift import SemanticDriftDetector
from app.investigation.schemas import SemanticResult, ChangeEvidence

class SemanticAnalyzer:
    """
    Stage 3 AI Semantic Analysis Engine.
    Answers: 'WHAT DOES THE CHANGE MEAN?'

    Architecture & State Machine:
      - NOT_REQUIRED: For ADDED/DELETED files, or metadata-only changes with unchanged content.
      - UNAVAILABLE: For binary/unsupported formats or missing/empty content.
      - PENDING -> ANALYZING: Content modification detected.
      - ANALYZING -> AVAILABLE: Primary model (SentenceTransformer) succeeds.
      - ANALYZING -> FALLBACK -> AVAILABLE: Primary model fails, deterministic fallback succeeds.
      - ANALYZING -> FALLBACK -> ERROR: Both primary model and fallback fail.

    Confidence:
      - Confidence scores represent deterministic, defensible method-based confidence estimates
        (heuristic methodology rating based on technique fidelity and input characteristics),
        NOT statistical/probabilistic model certainty.

    Fallback Terminology Note:
      - Reusable deterministic semantic logic in the codebase: app/investigation/fallbackai.py
        contains TemplateReportGenerator for Stage 5 incident reports, but does not contain
        reusable string/sentence comparison routines.
      - Fallback utilizes difflib.SequenceMatcher.ratio(), which computes sequence similarity
        (Ratcliff and Obershelp Gestalt pattern matching algorithm), NOT token-overlap similarity.
    """

    PRIMARY_BASE_CONFIDENCE = 0.90
    FALLBACK_BASE_CONFIDENCE = 0.60

    def __init__(self, drift_detector: SemanticDriftDetector):
        self.primary_model = drift_detector

    def _generate_explanation(self, drift: float, method: str) -> str:
        """
        Deterministically explains the meaning based on drift score without hallucinating facts.
        Canonical semantic drift scale: 0.0 (identical) to 1.0 (completely drifted).
        """
        method_prefix = "Dense semantic embedding analysis indicates: " if method == "sentence_transformer" else "Deterministic sequence similarity fallback indicates: "
        
        if drift < 0.05:
            body = "The changes appear to be superficial wording or formatting adjustments with no material semantic impact."
        elif drift < 0.20:
            body = "The modifications introduce minor semantic variations, likely clarifying existing meaning."
        elif drift < 0.50:
            body = "The content changes represent a moderate shift in semantic meaning, suggesting revised intent."
        else:
            body = "The modifications drastically alter the semantic meaning of the content, indicating a complete rewrite or reversal of intent."
            
        return method_prefix + body

    def _calculate_primary_confidence(self, old_content: str, new_content: str) -> float:
        """
        Calculates a deterministic, defensible method-based confidence estimate for SentenceTransformer.
        Adjusts for input characteristics such as truncation or extreme brevity.
        """
        conf = self.PRIMARY_BASE_CONFIDENCE
        max_len = max(len(old_content), len(new_content))
        min_len = min(len(old_content), len(new_content))
        
        # Deduct if content exceeds MAX_TEXT_SIZE because text was truncated
        if max_len > SemanticDriftDetector.MAX_TEXT_SIZE:
            conf -= 0.15
        # Deduct slightly if content is extremely brief (< 10 chars)
        elif min_len < 10:
            conf -= 0.05
            
        return round(conf, 2)

    def _fallback_analysis(self, old_content: str, new_content: str, history: list[str]) -> SemanticResult:
        """
        Deterministic sequence similarity fallback using difflib.SequenceMatcher.
        Computes sequence similarity ratio in [0.0, 1.0] and derived drift = 1.0 - similarity.
        """
        history.append("FALLBACK")
        try:
            old_tokens = old_content.split()
            new_tokens = new_content.split()
            matcher = difflib.SequenceMatcher(None, old_tokens, new_tokens)
            similarity = round(float(matcher.ratio()), 4)
            drift = round(float(1.0 - similarity), 4)

            history.append("AVAILABLE")
            return SemanticResult(
                status="AVAILABLE",
                semantic_similarity=similarity,
                semantic_drift=drift,
                analysis_method="fallback",
                confidence=self.FALLBACK_BASE_CONFIDENCE,
                explanation=self._generate_explanation(drift, method="fallback"),
                transition_history=history
            )
        except Exception:
            history.append("ERROR")
            return SemanticResult(
                status="ERROR",
                semantic_similarity=None,
                semantic_drift=None,
                analysis_method=None,
                confidence=None,
                explanation="Both primary model and deterministic sequence fallback failed.",
                transition_history=history
            )

    def analyze(
        self,
        change_type: str,
        old_content: Optional[str],
        new_content: Optional[str],
        evidence: list[ChangeEvidence]
    ) -> SemanticResult:
        """
        Executes the Stage 3 Semantic Analysis state machine.
        """
        # 1. State: NOT_REQUIRED for non-MODIFIED changes (ADDED, DELETED)
        if change_type != "MODIFIED":
            return SemanticResult(
                status="NOT_REQUIRED",
                explanation=f"File change type is {change_type}; semantic diff analysis is not required.",
                transition_history=["NOT_REQUIRED"]
            )

        # 2. State: UNAVAILABLE for binary or unsupported formats
        is_binary = any("Binary modification detected" in e.description for e in evidence if e.evidence_type == "ContentAnalysis")
        if is_binary:
            return SemanticResult(
                status="UNAVAILABLE",
                explanation="Binary or unsupported file content cannot undergo text semantic analysis.",
                transition_history=["UNAVAILABLE"]
            )

        # 3. Check for content diff vs metadata-only changes
        has_content_diff = any(e.evidence_type == "ContentAnalysis" and "Additions" in str(e.value) for e in evidence)
        if not has_content_diff and (old_content and new_content and old_content.strip() != new_content.strip()):
            has_content_diff = True

        has_meta_change = any(e.evidence_type == "MetadataAnalysis" for e in evidence)

        if not has_content_diff:
            # Distinguish metadata-only modification from truly unchanged files
            if has_meta_change:
                explanation = "Metadata modification detected by Stage 2, but file content is unchanged; semantic analysis is not required."
            else:
                explanation = "File content is unchanged; semantic analysis is not required."
            return SemanticResult(
                status="NOT_REQUIRED",
                explanation=explanation,
                transition_history=["NOT_REQUIRED"]
            )

        # 4. State: UNAVAILABLE if content payload is missing or empty
        if old_content is None or new_content is None or not old_content.strip() or not new_content.strip():
            return SemanticResult(
                status="UNAVAILABLE",
                explanation="Content data is missing or empty; semantic analysis unavailable.",
                transition_history=["UNAVAILABLE"]
            )

        # 5. Lifecycle transitions: PENDING -> ANALYZING
        history = ["PENDING", "ANALYZING"]

        # 6. Execute Primary Model (SentenceTransformer)
        try:
            # calculate_similarity_and_drift preserves canonical (1 - similarity) / 2 formula
            similarity, drift = self.primary_model.calculate_similarity_and_drift(old_content, new_content)
            if drift is None or similarity is None:
                return SemanticResult(
                    status="UNAVAILABLE",
                    explanation="Primary semantic model returned empty results.",
                    transition_history=["UNAVAILABLE"]
                )

            history.append("AVAILABLE")
            confidence = self._calculate_primary_confidence(old_content, new_content)
            return SemanticResult(
                status="AVAILABLE",
                semantic_similarity=similarity,
                semantic_drift=drift,
                analysis_method="sentence_transformer",
                confidence=confidence,
                explanation=self._generate_explanation(drift, method="sentence_transformer"),
                transition_history=history
            )
        except Exception:
            # 7. Transition: ANALYZING -> FALLBACK (and then AVAILABLE or ERROR)
            return self._fallback_analysis(old_content, new_content, history)

