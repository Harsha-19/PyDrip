# AI/ML Scoring Layer JSON Contract

This document defines the exact data contract between Harsha's Core FIM / Scan Engine, Rohith's AI/ML Scoring Layer, and Paritosh's Report / Dashboard Layer.

## 1. Raw Change Schema
An individual detected change entering the AI/ML layer.

* `file_path` (string, required): Absolute or relative path to the modified file.
* `change_type` (string, required): Must be one of `ADDED`, `DELETED`, `MODIFIED`.
* `criticality` (string, optional): Must be one of `Critical`, `High`, `Medium`, `Low`.
* `old_hash` (string, nullable): Hash of previous file. Null for ADDED files.
* `new_hash` (string, nullable): Hash of current file. Null for DELETED files.
* `old_content` (string, nullable): Previous content. Null for binary/unreadable/deleted files.
* `new_content` (string, nullable): Current content. Null for binary/unreadable/added files.
* `detected_at` (string, optional): ISO-8601 timestamp.

## 2. Historical Scan Schema
A batch of historical changes for anomaly detection.

```json
[
  {
    "scan_id": "scan_001",
    "detected_at": "2026-09-08T14:10:00",
    "changes": [
      {
        "file_path": "/configs/app.conf",
        "change_type": "MODIFIED",
        "criticality": "Medium"
      }
    ]
  }
]
```

## 3. Output Schema
The enriched output of `score_changes(change_list, scan_history)`.
Preserves original change fields and adds:

* `anomaly_score` (float, nullable): How unusual the batch is. Not a maliciousness probability.
* `drift_score` (float, nullable): Semantic difference. Null if content unavailable or binary.
* `severity` (string): Deterministic severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* `evidence` (object): Human-readable reasons for severity factors:
  * `anomaly_reason` (string)
  * `drift_reason` (string)
  * `criticality_reason` (string)
  * `severity_reason` (string)

## 4. Content Handling Rules
- `old_content` and `new_content` are optional. Missing content must not crash scoring.
- Semantic drift applies only when appropriate text/config content is available.
- Binary/non-text files should not be sent through the embedding model.
- Do not invent fake drift scores when content is unavailable.

## 5. Evidence Structure
Every severity result must be traceable to evidence. Do not put only raw numbers into evidence fields. Explain what the score means in plain English (e.g., "The change batch was unusually large...").
