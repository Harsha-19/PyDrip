from pydantic import BaseModel
from typing import Literal

class FileIdentity(BaseModel):
    name: str
    path: str
    type: str
    size: int
    sha256: str

class IntegrityResult(BaseModel):
    file: FileIdentity
    baseline_hash: str | None
    current_hash: str | None
    integrity_status: Literal["UNCHANGED", "MODIFIED", "ERROR"]
    error_message: str | None = None
