from fastapi import FastAPI
from pydantic import BaseModel
from app.investigation.schemas import InvestigationInput
from app.investigation.investigator import InvestigationEngine
from app.investigation.report import InvestigationReporter
from app.core.baseline import IntegrityEngine as CoreIntegrityEngine
from pydantic import Field

app = FastAPI(
    title="AI Investigation Engine",
    version="0.1.0"
)

# Instantiate singletons so ML models load only once on startup
engine = InvestigationEngine()
reporter = InvestigationReporter()
core_engine = CoreIntegrityEngine()

class InvestigateRequest(BaseModel):
    input_data: InvestigationInput
    file_contents_map: dict | None = None

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ai-investigation-engine"
    }

class CoreRequest(BaseModel):
    file_path: str = Field(..., description="Absolute path to the file on the backend filesystem.")

@app.post("/core/baseline")
def create_baseline(request: CoreRequest):
    """
    Establish a cryptographic baseline (SHA-256) for a file.
    """
    return core_engine.create_baseline(request.file_path)

@app.post("/core/check")
def check_integrity(request: CoreRequest):
    """
    Compute current SHA-256 hash and compare it against the established baseline.
    """
    return core_engine.check_integrity(request.file_path)

@app.post("/investigate")
def investigate_endpoint(request: InvestigateRequest):
    """
    Executes the full AI Investigation Engine pipeline for a batch of FIM changes.
    """
    # 1. Execute deterministic investigation logic
    investigation_result = engine.investigate(request.input_data, request.file_contents_map)
    
    # 2. Generate final human-readable report and enforce severity rules
    final_report = reporter.generate_report(investigation_result)
    
    return final_report

if __name__ == "__main__":
    import uvicorn
    print("Starting AI Investigation Engine API Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)