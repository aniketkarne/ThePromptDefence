"""Regression tests for config resolution.

Two defects are covered here:

1. **Precedence was inverted.** The README documents the priority order as
   "Environment variables — best for containers, CI, and scripted deployments"
   first, then ``shield_config.json``, then defaults. The implementation did
   the opposite: ``shield_config.json`` was applied *after* the environment
   was read and overwrote every env var. ``SHIELD_RISK_THRESHOLD=0.9`` was
   silently ignored whenever a ``shield_config.json`` happened to be present.

2. **A broken config file printed to stdout.** stdout is the MCP stdio
   transport — a stray ``print()`` there corrupts the JSON-RPC stream and
   breaks the server handshake. The failure path now logs to stderr.
"""
import json
import os
import sys
from pathlib import Path

import pytest

from shield_mcp.utils import config as config_module  # noqa: F401


@pytest.fixture
def reload_config():
    """Re-import the config module with a clean environment and CWD."""
    saved_environ = dict(os.environ)
    saved_cwd = os.getcwd()
    saved_module = sys.modules.pop("shield_mcp.utils.config")

    def _reload(env=None, cwd=None, shield_config=None, raw_config=None):
        for key in list(os.environ):
            if key.startswith("SHIELD_") or key == "HF_HOME":
                del os.environ[key]
        os.environ.update(env or {})
        if cwd is not None:
            os.chdir(cwd)
        if raw_config is not None:
            # Written *after* the chdir, so the file the module reads is the
            # broken one — not a stray copy left in the original directory.
            Path("shield_config.json").write_text(raw_config)
        elif shield_config is not None:
            Path("shield_config.json").write_text(json.dumps(shield_config))
        import shield_mcp.utils.config as fresh
        return fresh.Config()

    yield _reload

    os.chdir(saved_cwd)
    os.environ.clear()
    os.environ.update(saved_environ)
    sys.modules["shield_mcp.utils.config"] = saved_module


def test_env_vars_take_precedence_over_json_file(reload_config, tmp_path):
    cfg = reload_config(
        env={"SHIELD_RISK_THRESHOLD": "0.9", "SHIELD_MODEL_NAME": "from-env"},
        cwd=tmp_path,
        shield_config={"risk_threshold": 0.3, "model_name": "from-json"},
    )
    assert cfg.risk_threshold == 0.9
    assert cfg.model_name == "from-env"


def test_json_file_used_when_env_not_set(reload_config, tmp_path):
    cfg = reload_config(
        cwd=tmp_path,
        shield_config={"risk_threshold": 0.3, "model_name": "from-json"},
    )
    assert cfg.risk_threshold == 0.3
    assert cfg.model_name == "from-json"


def test_json_file_fills_gaps_left_by_env(reload_config, tmp_path):
    cfg = reload_config(
        env={"SHIELD_RISK_THRESHOLD": "0.9"},
        cwd=tmp_path,
        shield_config={"risk_threshold": 0.3, "model_name": "from-json"},
    )
    # env wins where it is set ...
    assert cfg.risk_threshold == 0.9
    # ... and the file still supplies everything env did not set.
    assert cfg.model_name == "from-json"


def test_offline_mode_env_var_wins_over_json(reload_config, tmp_path):
    cfg = reload_config(
        env={"SHIELD_OFFLINE_MODE": "false"},
        cwd=tmp_path,
        shield_config={"offline_mode": True},
    )
    assert cfg.offline_mode is False


def test_offline_mode_from_json_when_env_unset(reload_config, tmp_path):
    cfg = reload_config(cwd=tmp_path, shield_config={"offline_mode": True})
    assert cfg.offline_mode is True


def test_broken_config_does_not_print_to_stdout(reload_config, tmp_path, capsys):
    cfg = reload_config(cwd=tmp_path, raw_config="{ this is not valid json ")
    captured = capsys.readouterr()
    assert captured.out == "", f"Config failure wrote to stdout: {captured.out!r}"
    # The server must still start with working defaults.
    assert cfg.risk_threshold == 0.7


def test_broken_config_file_is_actually_read(reload_config, tmp_path):
    """Guard the test above: the broken file must be the one on disk."""
    reload_config(cwd=tmp_path, raw_config="{ this is not valid json ")
    assert (tmp_path / "shield_config.json").exists()
    assert "this is not valid json" in (tmp_path / "shield_config.json").read_text()


def test_config_path_env_var_points_at_explicit_file(reload_config, tmp_path):
    explicit = tmp_path / "custom" / "shield.json"
    explicit.parent.mkdir()
    explicit.write_text(json.dumps({"risk_threshold": 0.42}))

    cfg = reload_config(
        env={"SHIELD_CONFIG_PATH": str(explicit)},
        cwd=tmp_path,
        shield_config={"risk_threshold": 0.3},
    )
    assert cfg.risk_threshold == 0.42
