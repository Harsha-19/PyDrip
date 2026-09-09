"""
Semantic drift detection module.

Phase 7: Pretrained content-level semantic drift detection using sentence-transformers (all-MiniLM-L6-v2).
Operates at the individual file change level:
MODIFIED + text content -> drift_score in [0.0, 1.0]
ADDED / DELETED / binary / missing content -> None
"""
from typing import List, Dict, Any, Optional
import numpy as np

# Global singleton instance for model reuse
_MODEL_INSTANCE: Optional[Any] = None


def get_model() -> Any:
    """
    Returns the cached singleton all-MiniLM-L6-v2 SentenceTransformer.
    Lazy-loaded to optimize memory and startup time.
    """
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        from sentence_transformers import SentenceTransformer
        _MODEL_INSTANCE = SentenceTransformer("all-MiniLM-L6-v2")
    return _MODEL_INSTANCE


def calculate_drift(
    old_content: Optional[str],
    new_content: Optional[str],
    model: Optional[Any] = None
) -> Optional[float]:
    """
    Calculates semantic drift score in [0.0, 1.0] between two text strings.
    
    Formula:
        cosine_similarity = dot(old_embedding, new_embedding)  # with normalized embeddings
        drift_score = clip(1.0 - cosine_similarity, 0.0, 1.0)
    
    Returns:
        float in [0.0, 1.0] where higher indicates greater semantic change.
        None if either content is None (e.g. ADDED, DELETED, binary, unreadable).
    """
    if old_content is None or new_content is None:
        return None
    if not isinstance(old_content, str) or not isinstance(new_content, str):
        return None

    # Fast-path exact identity
    if old_content == new_content:
        return 0.0

    # Both empty or whitespace-only
    if old_content.strip() == "" and new_content.strip() == "":
        return 0.0

    if model is None:
        model = get_model()

    embeddings = model.encode([old_content, new_content], normalize_embeddings=True)
    cosine_similarity = float(np.dot(embeddings[0], embeddings[1]))
    drift_score = float(np.clip(1.0 - cosine_similarity, 0.0, 1.0))
    return round(drift_score, 4)


def calculate_change_drift(
    change: Dict[str, Any],
    model: Optional[Any] = None
) -> Optional[float]:
    """
    Evaluates a single raw change dict.
    
    Returns:
        float in [0.0, 1.0] if change_type == 'MODIFIED' and both contents are non-None.
        None for ADDED, DELETED, binary, or missing content.
    """
    if not isinstance(change, dict):
        return None

    change_type = change.get("change_type")
    if change_type != "MODIFIED":
        return None

    old_content = change.get("old_content")
    new_content = change.get("new_content")

    if old_content is None or new_content is None:
        return None

    return calculate_drift(old_content, new_content, model=model)


def calculate_batch_drift(
    changes: List[Dict[str, Any]],
    model: Optional[Any] = None
) -> List[Optional[float]]:
    """
    Vectorized evaluation across a list of change dicts.
    Batches embedding calls for optimal performance while preserving input ordering.
    
    Returns:
        List of Optional[float] matching the exact length and order of changes.
    """
    if not isinstance(changes, list):
        raise ValueError("changes must be a list")

    results: List[Optional[float]] = [None] * len(changes)
    pending_indices: List[int] = []
    pending_pairs: List[tuple[str, str]] = []

    for idx, ch in enumerate(changes):
        if not isinstance(ch, dict):
            continue
        if ch.get("change_type") != "MODIFIED":
            continue

        old_c = ch.get("old_content")
        new_c = ch.get("new_content")

        if old_c is None or new_c is None:
            continue
        if not isinstance(old_c, str) or not isinstance(new_c, str):
            continue

        if old_c == new_c or (old_c.strip() == "" and new_c.strip() == ""):
            results[idx] = 0.0
            continue

        pending_indices.append(idx)
        pending_pairs.append((old_c, new_c))

    if pending_pairs:
        if model is None:
            model = get_model()

        # Gather unique strings to avoid redundant embeddings
        unique_texts = list({text for pair in pending_pairs for text in pair})
        embeddings = model.encode(unique_texts, normalize_embeddings=True, batch_size=32)
        emb_map = {text: emb for text, emb in zip(unique_texts, embeddings)}

        for idx, (old_c, new_c) in zip(pending_indices, pending_pairs):
            cos_sim = float(np.dot(emb_map[old_c], emb_map[new_c]))
            drift = float(np.clip(1.0 - cos_sim, 0.0, 1.0))
            results[idx] = round(drift, 4)

    return results
