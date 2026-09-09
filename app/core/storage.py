from abc import ABC, abstractmethod
from typing import Dict, Optional

class BaselineStore(ABC):
    @abstractmethod
    def save_baseline(self, file_path: str, sha256_hash: str) -> None:
        pass

    @abstractmethod
    def get_baseline(self, file_path: str) -> Optional[str]:
        pass

class InMemoryBaselineStore(BaselineStore):
    def __init__(self):
        self._store: Dict[str, str] = {}

    def save_baseline(self, file_path: str, sha256_hash: str) -> None:
        self._store[file_path] = sha256_hash

    def get_baseline(self, file_path: str) -> Optional[str]:
        return self._store.get(file_path)
