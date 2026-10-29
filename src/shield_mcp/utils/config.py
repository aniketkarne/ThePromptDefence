import os
import json
import logging
from pathlib import Path

logger = logging.getLogger("shield-mcp")

# Standard HuggingFace cache location
_HF_CACHE_DIR = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface"))

# Setting name -> environment variable that overrides it. A setting whose env
# var is explicitly set is never overridden by shield_config.json — env vars
# are the highest-priority source.
_ENV_OVERRIDES = {
    "risk_threshold": "SHIELD_RISK_THRESHOLD",
    "log_dir": "SHIELD_LOG_DIR",
    "model_name": "SHIELD_MODEL_NAME",
    "model_cache_dir": "HF_HOME",
    "offline_mode": "SHIELD_OFFLINE_MODE",
}


def _get_version() -> str:
    """Read version from pyproject.toml via importlib.metadata (single source of truth)."""
    try:
        from importlib.metadata import version
        return version("ThePromptDefence")
    except Exception:
        return "unknown"


class Config:
    def __init__(self):
        # Environment variables are the highest-priority source (README
        # "Configuration"). shield_config.json fills in the gaps but never
        # overrides a value that was explicitly set in the environment.
        self._env_set = {
            key: os.environ.get(var) is not None
            for key, var in _ENV_OVERRIDES.items()
        }

        self.risk_threshold = float(os.environ.get("SHIELD_RISK_THRESHOLD", "0.7"))
        self.log_dir = Path(os.environ.get("SHIELD_LOG_DIR", Path.home() / ".shield-mcp" / "logs"))
        self.log_file = self.log_dir / "shield.log"
        self.model_name = os.environ.get("SHIELD_MODEL_NAME", "protectai/deberta-v3-base-prompt-injection-v2")
        # Default to ~/.cache/huggingface/ — HF_HOME controls where models are cached
        self.model_cache_dir = Path(os.environ.get("HF_HOME", str(_HF_CACHE_DIR)))
        self.offline_mode = os.environ.get("SHIELD_OFFLINE_MODE", "false").lower() in ("true", "1", "yes")

        self._load_local_config()
        self._ensure_dirs()

    def _config_path(self) -> Path:
        """Locate shield_config.json.

        SHIELD_CONFIG_PATH points at an explicit file. Without it the lookup
        stays relative to the working directory, which is where a
        developer running the server from a project root expects it.
        """
        override = os.environ.get("SHIELD_CONFIG_PATH")
        if override:
            return Path(override).expanduser()
        return Path("shield_config.json")

    def _load_local_config(self):
        """Apply shield_config.json for settings not pinned by the environment."""
        config_path = self._config_path()
        if not config_path.exists():
            return
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            # Log to stderr, never stdout — stdout is the MCP stdio transport
            # and a stray print there corrupts the JSON-RPC stream.
            logger.warning("Could not read %s: %s", config_path, e)
            return

        try:
            if "risk_threshold" in data and not self._env_set["risk_threshold"]:
                self.risk_threshold = float(data["risk_threshold"])
            if "log_dir" in data and not self._env_set["log_dir"]:
                self.log_dir = Path(data["log_dir"])
                self.log_file = self.log_dir / "shield.log"
            if "model_name" in data and not self._env_set["model_name"]:
                self.model_name = data["model_name"]
            if "model_cache_dir" in data and not self._env_set["model_cache_dir"]:
                self.model_cache_dir = Path(data["model_cache_dir"])
            if "offline_mode" in data and not self._env_set["offline_mode"]:
                self.offline_mode = bool(data["offline_mode"])
        except (TypeError, ValueError) as e:
            logger.warning("Invalid value in %s: %s", config_path, e)

    def _ensure_dirs(self):
        self.log_dir.mkdir(parents=True, exist_ok=True)


# Global instance
config = Config()
