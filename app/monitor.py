"""
Real-time filesystem monitoring using watchdog.
"""
import time
import threading
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.models import AppConfig

logger = logging.getLogger("pydrip.monitor")

# Global state for monitor thread
_observer: Observer = None
_debounce_timer: threading.Timer = None
_debounce_interval = 1.0  # seconds

class FIMEventHandler(FileSystemEventHandler):
    """Debounced event handler that triggers a full core scanner run."""
    def on_any_event(self, event):
        # Ignore directory events, focus on files
        if event.is_directory:
            return
            
        global _debounce_timer
        if _debounce_timer is not None:
            _debounce_timer.cancel()
            
        _debounce_timer = threading.Timer(_debounce_interval, self.trigger_scan)
        _debounce_timer.start()

    def trigger_scan(self):
        logger.info("Real-time filesystem change detected. Triggering FIM scan.")
        try:
            from app.core.scanner import run_scan
            # We run the scan and rely on auto_enrich=True
            summary = run_scan(auto_enrich=True)
            if summary.total_changes > 0:
                logger.info(f"Monitor triggered scan {summary.scan_id}: {summary.total_changes} changes detected.")
        except Exception as e:
            logger.error(f"Monitor triggered scan failed: {e}")

def start_monitoring(config: AppConfig):
    """Start the watchdog observer."""
    global _observer
    if _observer is not None and _observer.is_alive():
        logger.warning("Monitor is already running.")
        return

    _observer = Observer()
    event_handler = FIMEventHandler()
    project_root = Path(__file__).resolve().parent.parent

    for monitored in config.monitored_paths:
        raw_path = Path(monitored.path)
        target_dir = raw_path if raw_path.is_absolute() else (project_root / raw_path).resolve()
        
        if target_dir.exists():
            _observer.schedule(event_handler, str(target_dir), recursive=True)
            logger.info(f"Watching directory: {target_dir}")
        else:
            logger.warning(f"Could not watch missing directory: {target_dir}")

    _observer.start()
    logger.info("Watchdog observer started.")

def stop_monitoring():
    """Stop the watchdog observer."""
    global _observer, _debounce_timer
    if _debounce_timer is not None:
        _debounce_timer.cancel()
        _debounce_timer = None

    if _observer is not None:
        _observer.stop()
        _observer.join()
        _observer = None
        logger.info("Watchdog observer stopped.")
