# JP-018 — AI-Augmented File Integrity Monitoring (FIM+)

## Module
AI/ML Scoring Layer

## Purpose
This module turns hash-detected file changes into:
* anomaly_score
* drift_score
* severity
* evidence

## Main interface
```python
score_changes(change_list, scan_history)
```

## Technology
* Python 3.11+
* scikit-learn
* sentence-transformers
* NumPy
* Pandas
* pytest

## Current status
`Phase 2 — Project Scaffold`

Actual algorithm implementation begins in later phases.
