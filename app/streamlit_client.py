import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import requests
import streamlit as st

logger = logging.getLogger("fim_ui.api_client")

DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT = 10.0


class FIMAPIError(Exception):
    """Encapsulates backend API communication or HTTP errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, detail: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


class FIMApiClient:
    """Centralized HTTP API client for FIM+ FastAPI backend."""

    def __init__(self, base_url: str = DEFAULT_API_URL, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def get_health(self) -> Tuple[bool, Optional[str]]:
        """GET /health - Check if backend is alive.
        
        Returns:
            (is_online: bool, status_message_or_error: str)
        """
        try:
            resp = requests.get(self._url("/health"), timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return True, data.get("status", "ok")
            return False, f"HTTP {resp.status_code}: {resp.text}"
        except requests.exceptions.RequestException as exc:
            return False, str(exc)

    def get_config(self) -> Dict[str, Any]:
        """GET /config - Fetch current validated YAML configuration."""
        try:
            resp = requests.get(self._url("/config"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to fetch config (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while fetching config: {exc}") from exc

    def update_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """PUT /config - Save updated YAML configuration."""
        try:
            resp = requests.put(self._url("/config"), json=config_data, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to update config (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while updating config: {exc}") from exc

    def create_baseline(self) -> Dict[str, Any]:
        """POST /baseline - Capture trusted SHA-256 state."""
        try:
            resp = requests.post(self._url("/baseline"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Baseline creation failed (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error during baseline creation: {exc}") from exc

    def run_scan(self) -> Dict[str, Any]:
        """POST /scan - Compare current state against baseline."""
        try:
            resp = requests.post(self._url("/scan"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Scan failed (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error during scan: {exc}") from exc

    def get_changes(self, scan_id: str) -> List[Dict[str, Any]]:
        """GET /changes/{scan_id} - Fetch detected changes."""
        try:
            resp = requests.get(self._url(f"/changes/{scan_id}"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to fetch changes (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while fetching changes: {exc}") from exc

    def get_report(self, scan_id: str) -> Dict[str, Any]:
        """GET /report/{scan_id} - Fetch or generate investigation report."""
        try:
            resp = requests.get(self._url(f"/report/{scan_id}"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to fetch report (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while fetching report: {exc}") from exc

    def get_audit(self) -> List[Dict[str, Any]]:
        """GET /audit - Fetch append-only audit trail."""
        try:
            resp = requests.get(self._url("/audit"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to fetch audit log (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while fetching audit log: {exc}") from exc

    def get_security_state(self) -> Dict[str, Any]:
        """GET /security/state - Fetch real-time incident state."""
        try:
            resp = requests.get(self._url("/security/state"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to fetch security state (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while fetching security state: {exc}") from exc

    def start_monitor(self) -> Dict[str, Any]:
        """POST /monitor/start - Start real-time watchdog."""
        try:
            resp = requests.post(self._url("/monitor/start"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to start monitor (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while starting monitor: {exc}") from exc

    def stop_monitor(self) -> Dict[str, Any]:
        """POST /monitor/stop - Stop real-time watchdog."""
        try:
            resp = requests.post(self._url("/monitor/stop"), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            err_msg = self._extract_error(resp)
            raise FIMAPIError(f"Failed to stop monitor (HTTP {resp.status_code}): {err_msg}", resp.status_code, err_msg)
        except requests.exceptions.RequestException as exc:
            raise FIMAPIError(f"Connection error while stopping monitor: {exc}") from exc

    @staticmethod
    def _extract_error(resp: requests.Response) -> str:
        try:
            data = resp.json()
            if isinstance(data, dict):
                return data.get("detail") or data.get("message") or json.dumps(data)
            return str(data)
        except Exception:
            return resp.text or f"Status {resp.status_code}"
