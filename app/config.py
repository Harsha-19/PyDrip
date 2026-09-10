"""Configuration loader and writer for FIM+.

Loads and validates YAML configuration using Pydantic models.
"""

from pathlib import Path
from typing import Optional, Union
import yaml
from pydantic import ValidationError

from app.models import AppConfig

# Default location for the config file relative to project root
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


class ConfigError(Exception):
    """Raised when configuration file is missing, malformed, or invalid."""
    pass


def load_config(config_path: Optional[Union[str, Path]] = None) -> AppConfig:
    """Load and validate the YAML configuration from file.

    Args:
        config_path: Optional explicit path to the YAML file.

    Returns:
        Validated AppConfig instance.

    Raises:
        ConfigError: If file not found, YAML malformed, or validation fails.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Malformed YAML in configuration file: {exc}") from exc
    except Exception as exc:
        raise ConfigError(f"Failed to read configuration file: {exc}") from exc

    if not isinstance(raw_data, dict):
        raise ConfigError("Configuration file must contain a valid YAML mapping/dictionary.")

    try:
        return AppConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ConfigError(f"Configuration validation failed: {exc}") from exc


def save_config(config: AppConfig, config_path: Optional[Union[str, Path]] = None) -> None:
    """Validate and write the AppConfig instance to the YAML file.

    Args:
        config: Validated AppConfig instance to save.
        config_path: Optional explicit path to the YAML file.

    Raises:
        ConfigError: If writing to file fails.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    try:
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        config_dict = config.model_dump(mode="json")
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config_dict, f, sort_keys=False, default_flow_style=False)
    except Exception as exc:
        raise ConfigError(f"Failed to write configuration file: {exc}") from exc
