import re
from typing import Optional, List, Literal
from app.investigation.schemas import ChangeEvidence, SemanticResult, RiskFactor, RiskResult

class RiskEngine:
    """
    Stage 4 — Severity & Risk Engine.
    Answers: 'HOW RISKY IS THE CHANGE?'

    Evaluates risk strictly from observed evidence produced by Stages 1–3.
    Never invents evidence, declares attacker presence, or fabricates risk scores.

    Authoritative Factor Weights (Sum = 1.00):
      1. Cryptographic Integrity (Stage 1): Max 0.40
      2. Semantic Impact (Stage 3): Max 0.30
      3. Content Mutation (Stage 2): Max 0.15
      4. Metadata & Structure (Stage 2): Max 0.15

    Severity Thresholds:
      - 0.00 to < 0.25: LOW
      - 0.25 to < 0.55: MEDIUM
      - 0.55 to < 0.80: HIGH
      - 0.80 to 1.00: CRITICAL
    """

    INTEGRITY_MAX = 0.40
    SEMANTIC_MAX = 0.30
    CONTENT_MAX = 0.15
    META_STRUCT_MAX = 0.15

    def _evaluate_integrity(self, change_type: str, hash_mismatch: bool) -> RiskFactor:
        """
        Evaluates cryptographic integrity impact from Stage 1.
        Rationale: A SHA-256 hash mismatch proves that the current file differs
        from the trusted baseline and is therefore a strong integrity-change indicator.
        """
        if change_type == "MODIFIED":
            if hash_mismatch:
                return RiskFactor(
                    name="cryptographic_integrity",
                    contribution=0.40,
                    evidence="SHA-256 hash mismatch detected against baseline.",
                    rationale="A SHA-256 hash mismatch proves that the current file differs from the trusted baseline and is therefore a strong integrity-change indicator."
                )
            else:
                return RiskFactor(
                    name="cryptographic_integrity",
                    contribution=0.05,
                    evidence="Cryptographic hash matches baseline.",
                    rationale="Content hash is identical; integrity of file data is preserved despite metadata updates."
                )
        elif change_type == "DELETED":
            return RiskFactor(
                name="cryptographic_integrity",
                contribution=0.30,
                evidence="File deletion detected.",
                rationale="File removal breaches the filesystem baseline state."
            )
        elif change_type == "ADDED":
            return RiskFactor(
                name="cryptographic_integrity",
                contribution=0.20,
                evidence="Unregistered file creation detected.",
                rationale="Introduction of an unbaselined file into the monitored environment."
            )
        else: # UNCHANGED or unrecognized
            return RiskFactor(
                name="cryptographic_integrity",
                contribution=0.00,
                evidence="Cryptographic baseline verified intact.",
                rationale="Cryptographic baseline matches current state; no integrity violation."
            )

    def _evaluate_semantic(self, semantic_res: Optional[SemanticResult]) -> RiskFactor:
        """
        Evaluates semantic impact from Stage 3.
        Distinguishes unavailable evidence from zero-drift, and accounts for fallback provenance.
        """
        if not semantic_res or semantic_res.status in ("NOT_REQUIRED", "UNAVAILABLE", "ERROR"):
            status_desc = semantic_res.status if semantic_res else "UNAVAILABLE"
            return RiskFactor(
                name="semantic_impact",
                contribution=0.00,
                evidence=f"Semantic analysis status: {status_desc}.",
                rationale=f"Semantic evidence is {status_desc.lower()}; no semantic risk contribution applied without fabricating zero drift."
            )

        drift = semantic_res.semantic_drift if semantic_res.semantic_drift is not None else 0.0
        method = semantic_res.analysis_method or "unknown"

        if method == "sentence_transformer":
            contribution = round(min(self.SEMANTIC_MAX, drift * self.SEMANTIC_MAX), 4)
            return RiskFactor(
                name="semantic_impact",
                contribution=contribution,
                evidence=f"Semantic drift: {drift:.2f} (SentenceTransformer dense embedding).",
                rationale=f"Dense semantic embedding analysis indicates a drift score of {drift:.2f}, reflecting operational meaning change."
            )
        elif method == "fallback":
            # Lexical fallback is discounted (max 0.20) to reflect absence of deep conceptual understanding
            contribution = round(min(0.20, drift * 0.20), 4)
            return RiskFactor(
                name="semantic_impact",
                contribution=contribution,
                evidence=f"Semantic drift: {drift:.2f} (Deterministic sequence similarity fallback).",
                rationale=f"Deterministic sequence similarity indicates lexical drift of {drift:.2f}; discounted to reflect lack of deep semantic comprehension."
            )
        else:
            return RiskFactor(
                name="semantic_impact",
                contribution=0.00,
                evidence="Unrecognized semantic analysis method.",
                rationale="Semantic analysis method unrecognized; no risk contribution applied."
            )

    def _evaluate_content(self, evidence: List[ChangeEvidence]) -> RiskFactor:
        """
        Evaluates physical content mutation volume and binary flags from Stage 2.
        Line count is a transparent deterministic heuristic representing physical diff magnitude,
        NOT business or security impact (which is captured by semantic and structural analysis).
        """
        content_evs = [e for e in evidence if e.evidence_type == "ContentAnalysis"]
        
        is_binary = any("Binary modification detected" in e.description for e in content_evs)
        if is_binary:
            return RiskFactor(
                name="content_mutation",
                contribution=0.12,
                evidence="Binary file modification detected.",
                rationale="Opaque non-textual modification detected without textual line diff visibility."
            )

        # Parse line counts from evidence values (e.g. "Additions: 3, Deletions: 1")
        total_changed_lines = 0
        has_change_evidence = False
        for e in content_evs:
            if e.value and ("Additions" in e.value or "Deletions" in e.value):
                has_change_evidence = True
                adds = re.search(r"Additions:\s*(\d+)", e.value)
                dels = re.search(r"Deletions:\s*(\d+)", e.value)
                if adds:
                    total_changed_lines += int(adds.group(1))
                if dels:
                    total_changed_lines += int(dels.group(1))

        if not has_change_evidence or total_changed_lines == 0:
            return RiskFactor(
                name="content_mutation",
                contribution=0.00,
                evidence="Content is unchanged or diff unavailable.",
                rationale="No textual modifications detected in file content."
            )

        if total_changed_lines > 50:
            contrib = 0.15
            level = "Large-volume"
        elif total_changed_lines >= 10:
            contrib = 0.10
            level = "Moderate"
        else:
            contrib = 0.05
            level = "Focused"

        return RiskFactor(
            name="content_mutation",
            contribution=contrib,
            evidence=f"Content diff: {total_changed_lines} lines modified.",
            rationale=f"{level} physical line modification ({total_changed_lines} lines). Line count reflects physical mutation volume, not business impact."
        )

    def _evaluate_metadata_and_structure(self, evidence: List[ChangeEvidence], change_type: str = "MODIFIED") -> RiskFactor:
        """
        Evaluates file permissions, size, mtime, and structural schema changes from Stage 2.
        """
        if change_type == "UNCHANGED":
            return RiskFactor(
                name="metadata_structure",
                contribution=0.00,
                evidence="Metadata and structure intact.",
                rationale="No operational metadata or structural configuration changes detected."
            )

        contrib = 0.0
        reasons = []

        meta_evs = [e for e in evidence if e.evidence_type == "MetadataAnalysis"]
        struct_evs = [e for e in evidence if e.evidence_type == "StructureAnalysis"]

        # Permission change
        if any("permission" in e.description.lower() for e in meta_evs):
            contrib += 0.08
            reasons.append("File permissions updated")

        # Structural changes
        if any("root element" in str(e.value).lower() or "keys" in str(e.value).lower() for e in struct_evs):
            contrib += 0.07
            reasons.append("Configuration schema/structure altered")

        # Size change (distinguishing actual size modification from informational "Current File Size")
        if any("size altered" in e.description.lower() or "size changed" in e.description.lower() or ("size" in e.description.lower() and "current file size" not in e.description.lower()) for e in meta_evs):
            contrib += 0.03
            reasons.append("File size altered")

        # Timestamp change only (distinguishing actual timestamp update from informational "Last Modified Time")
        if any("mtime altered" in e.description.lower() or "timestamp updated" in e.description.lower() or ("modified time" in e.description.lower() and "last modified time" not in e.description.lower()) for e in meta_evs):
            if "File permissions updated" not in reasons and "File size altered" not in reasons:
                contrib += 0.02
                reasons.append("Modification timestamp updated")

        final_contrib = round(min(self.META_STRUCT_MAX, contrib), 4)
        if final_contrib == 0.0:
            return RiskFactor(
                name="metadata_structure",
                contribution=0.00,
                evidence="Metadata and structure intact.",
                rationale="No operational metadata or structural configuration changes detected."
            )

        return RiskFactor(
            name="metadata_structure",
            contribution=final_contrib,
            evidence="; ".join(reasons) + ".",
            rationale=f"System attributes and configuration structure altered ({'; '.join(reasons)})."
        )

    def _calculate_confidence(
        self,
        change_type: str,
        evidence: List[ChangeEvidence],
        semantic_res: Optional[SemanticResult]
    ) -> float:
        """
        Calculates assessment confidence reflecting evidence completeness for the actual scenario.
        Missing or unavailable evidence directly reduces confidence.
        """
        # Base Stage 1 completeness
        stage1_conf = 0.30
        # Base Stage 2 completeness
        stage2_conf = 0.30
        has_detector_error = any("error" in e.description.lower() or "missing" in e.description.lower() for e in evidence)
        if has_detector_error:
            stage2_conf -= 0.15

        # Check if semantic analysis was applicable
        is_modified = (change_type == "MODIFIED")
        has_content_change = any(e.evidence_type == "ContentAnalysis" and ("Additions" in str(e.value) or "Binary" in e.description) for e in evidence)
        
        if is_modified and has_content_change:
            # Semantic analysis was required
            if semantic_res and semantic_res.status == "AVAILABLE":
                method_conf = semantic_res.confidence or 0.60
                stage3_conf = round(0.40 * method_conf, 2)
            else:
                # UNAVAILABLE, ERROR, or missing: confidence penalized to reflect missing semantic visibility
                stage3_conf = 0.00
            total_conf = stage1_conf + stage2_conf + stage3_conf
        else:
            # Semantic analysis was NOT_REQUIRED (e.g. metadata-only change, ADDED, DELETED)
            # Evaluates completeness of all applicable evidence (Stage 1 + Stage 2)
            s1 = 0.50
            s2 = 0.50 if not has_detector_error else 0.30
            total_conf = s1 + s2

        return round(max(0.10, min(1.0, total_conf)), 2)

    def _generate_explanation(
        self,
        severity: str,
        score: float,
        factors: List[RiskFactor],
        semantic_res: Optional[SemanticResult]
    ) -> str:
        """
        Generates a deterministic, grounded explanation answering:
        'Why did the system assign this severity and risk score?'
        Never claims malware, attacker, or compromise without evidence.
        """
        contrib_factors = [f for f in factors if f.contribution > 0.0]
        if not contrib_factors:
            return f"Risk is classified as {severity} (score: {score:.2f}) because no significant integrity, semantic, or structural changes were detected."

        details = []
        for f in contrib_factors:
            if f.name == "cryptographic_integrity":
                details.append(f.evidence)
            elif f.name == "content_mutation":
                details.append(f.evidence)
            elif f.name == "semantic_impact":
                details.append(f.evidence)
            elif f.name == "metadata_structure":
                details.append(f.evidence)

        core_msg = f"Risk is classified as {severity} (score: {score:.2f}) based on observed evidence: {'; '.join(details)}."

        if semantic_res:
            if semantic_res.analysis_method == "fallback":
                core_msg += " Note: Semantic drift was evaluated using deterministic sequence similarity fallback."
            elif semantic_res.status in ("UNAVAILABLE", "ERROR"):
                core_msg += " Note: Semantic analysis was unavailable, so semantic risk contribution was not applied."

        return core_msg

    def evaluate(
        self,
        file_path: str,
        change_type: str,
        hash_mismatch: bool,
        evidence: List[ChangeEvidence],
        semantic_result: Optional[SemanticResult] = None
    ) -> RiskResult:
        """
        Executes the Stage 4 Severity and Risk Engine.
        """
        # 1. Evaluate individual factors
        f_integrity = self._evaluate_integrity(change_type, hash_mismatch)
        f_semantic = self._evaluate_semantic(semantic_result)
        f_content = self._evaluate_content(evidence)
        f_meta = self._evaluate_metadata_and_structure(evidence, change_type)

        factors = [f_integrity, f_semantic, f_content, f_meta]

        # 2. Compute normalized total score
        raw_score = sum(f.contribution for f in factors)
        score = round(max(0.0, min(1.0, raw_score)), 4)

        # 3. Determine severity based on documented deterministic thresholds
        if score < 0.25:
            severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
        elif score < 0.55:
            severity = "MEDIUM"
        elif score < 0.80:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        # 4. Calculate assessment confidence reflecting evidence completeness
        confidence = self._calculate_confidence(change_type, evidence, semantic_result)

        # 5. Generate grounded explanation
        explanation = self._generate_explanation(severity, score, factors, semantic_result)

        return RiskResult(
            score=score,
            severity=severity,
            factors=factors,
            explanation=explanation,
            confidence=confidence
        )
