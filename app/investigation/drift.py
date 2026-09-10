import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

class SemanticDriftDetector:
    """
    Detects semantic drift between two versions of text/config content.
    Loads the sentence-transformer model once upon initialization.
    """
    
    # Maximum string length (characters) to process to avoid huge RAM/CPU usage on large files
    MAX_TEXT_SIZE = 50000 

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        # Load the model once in the constructor. This prevents reloading per-file.
        # all-MiniLM-L6-v2 is small, CPU-friendly, and highly efficient.
        try:
            self.model = SentenceTransformer(model_name)
        except Exception:
            try:
                from ai_scoring.drift import get_model
                self.model = get_model()
            except Exception:
                self.model = SentenceTransformer(model_name, local_files_only=True)

    def calculate_similarity_and_drift(self, old_content: str | None, new_content: str | None) -> tuple[float | None, float | None]:
        """
        Calculates both cosine similarity and canonical semantic drift score.

        CANONICAL FORMULA PRESERVATION:
        - SentenceTransformer embeddings are evaluated using cosine similarity in range [-1.0, 1.0].
        - The canonical drift score is defined as: drift = (1.0 - cosine_similarity) / 2.0.
        - This maps similarity 1.0 -> drift 0.0, similarity 0.0 -> drift 0.5, similarity -1.0 -> drift 1.0.
        - This formula is the authoritative canonical behavior across the project and must NOT be changed.

        Returns:
            - (None, None) if either content is None or empty.
            - (1.0, 0.0) if text is exactly identical.
            - (similarity, drift_score) as floats.
        """
        if not old_content or not new_content:
            return None, None
            
        old_content = old_content.strip()
        new_content = new_content.strip()
        
        if not old_content or not new_content:
            return None, None
            
        if old_content == new_content:
            return 1.0, 0.0

        # Truncate for performance (protects against massive logs/binaries)
        old_content = old_content[:self.MAX_TEXT_SIZE]
        new_content = new_content[:self.MAX_TEXT_SIZE]

        # Generate embeddings
        embeddings = self.model.encode([old_content, new_content])
        old_emb = embeddings[0].reshape(1, -1)
        new_emb = embeddings[1].reshape(1, -1)
        
        # Compute cosine similarity
        raw_sim = float(cosine_similarity(old_emb, new_emb)[0][0])
        similarity = max(-1.0, min(1.0, raw_sim))
        
        # Canonical drift normalization: (1.0 - similarity) / 2.0
        drift_score = (1.0 - similarity) / 2.0
        drift_score = max(0.0, min(1.0, float(drift_score)))
        
        return round(similarity, 4), round(drift_score, 4)

    def calculate_drift(self, old_content: str | None, new_content: str | None) -> float | None:
        """
        Calculates the canonical semantic drift score between old and new text.
        Preserves existing canonical formula: drift = (1.0 - cosine_similarity) / 2.0.
        """
        _, drift = self.calculate_similarity_and_drift(old_content, new_content)
        return drift
