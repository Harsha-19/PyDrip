"""Unit tests for YAML configuration loading, saving, validation, and error handling."""

from pathlib import Path
import pytest
import yaml

from app.config import ConfigError, load_config, save_config
from app.models import AppConfig, Criticality, CriticalityRulesConfig, MonitoredPathConfig


def test_load_default_config():
    """Verify that default config/config.yaml loads successfully."""
    config = load_config()
    assert isinstance(config, AppConfig)
    assert len(config.monitored_paths) >= 1
    assert config.monitored_paths[0].path == "./sample_data"
    assert config.monitored_paths[0].criticality == Criticality.Medium
    assert config.criticality_rules.extensions[".env"] == Criticality.Critical
    assert config.criticality_rules.extensions[".conf"] == Criticality.High
    assert config.criticality_rules.extensions[".cfg"] == Criticality.High
    assert config.criticality_rules.extensions[".py"] == Criticality.Medium
    assert config.criticality_rules.extensions[".txt"] == Criticality.Low


def test_load_nonexistent_config_raises_config_error(tmp_path: Path):
    """Verify loading a nonexistent file raises ConfigError."""
    non_existent = tmp_path / "does_not_exist.yaml"
    with pytest.raises(ConfigError) as exc_info:
        load_config(non_existent)
    assert "not found" in str(exc_info.value).lower()


def test_load_malformed_yaml_raises_config_error(tmp_path: Path):
    """Verify loading malformed YAML syntax raises ConfigError."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("monitored_paths: [unclosed list", encoding="utf-8")
    with pytest.raises(ConfigError) as exc_info:
        load_config(bad_yaml)
    assert "malformed yaml" in str(exc_info.value).lower()


def test_load_invalid_criticality_in_yaml_raises_config_error(tmp_path: Path):
    """Verify invalid criticality in YAML raises ConfigError."""
    invalid_crit_yaml = tmp_path / "invalid_crit.yaml"
    invalid_crit_yaml.write_text(
        """
monitored_paths:
  - path: "./data"
    criticality: "SuperCritical"
criticality_rules:
  extensions:
    ".txt": "Low"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc_info:
        load_config(invalid_crit_yaml)
    assert "validation failed" in str(exc_info.value).lower()


def test_load_non_dict_yaml_raises_config_error(tmp_path: Path):
    """Verify loading top-level YAML array or primitive raises ConfigError."""
    list_yaml = tmp_path / "list.yaml"
    list_yaml.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc_info:
        load_config(list_yaml)
    assert "valid yaml mapping" in str(exc_info.value).lower()


def test_save_and_reload_custom_config(tmp_path: Path):
    """Verify saving a valid AppConfig and reloading it preserves all fields."""
    custom_yaml = tmp_path / "custom_config.yaml"
    new_cfg = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path="./custom_dir", criticality=Criticality.High),
            MonitoredPathConfig(path="./other_dir", criticality=Criticality.Low),
        ],
        criticality_rules=CriticalityRulesConfig(
            extensions={
                ".json": Criticality.Medium,
                ".pem": Criticality.Critical,
            }
        ),
    )

    save_config(new_cfg, custom_yaml)
    assert custom_yaml.is_file()

    reloaded = load_config(custom_yaml)
    assert len(reloaded.monitored_paths) == 2
    assert reloaded.monitored_paths[0].path == "./custom_dir"
    assert reloaded.monitored_paths[0].criticality == Criticality.High
    assert reloaded.criticality_rules.extensions[".pem"] == Criticality.Critical
