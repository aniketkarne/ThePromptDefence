import threading

import torch
from transformers import pipeline
from shield_mcp.utils.config import config
import logging

logger = logging.getLogger("shield-mcp")


class MLDetector:
    """Level-2 detection — DeBERTa prompt-injection classifier.

    The DeBERTa model is large (~400MB on first download) and slow to load. To
    keep MCP server startup instant and avoid forcing every user to pay the
    download cost on every connection, the model is loaded lazily on the first
    call to :meth:`check` instead of eagerly in ``__init__``. Concurrent first
    callers are de-duplicated via a class-level load lock so two simultaneous
    requests cannot trigger two parallel downloads.

    The ``SHIELD_OFFLINE_MODE`` / ``shield_config.json`` ``offline_mode`` flag
    is honored here: when set, the ML layer short-circuits at construction
    time so users who only want heuristic+structural detection pay nothing.
    """

    # Class-level lock so two simultaneous first-callers don't both download.
    # (Module-level on purpose — there is one model per process.)
    _load_lock = threading.Lock()

    def __init__(self):
        self.model_name = config.model_name
        self.cache_dir = config.model_cache_dir
        self.pipeline = None
        self.loaded = False
        self.disabled = False

        # If the user opted out of ML via offline_mode, skip the load entirely.
        # The check() method short-circuits when self.disabled is True.
        if config.offline_mode:
            logger.info(
                "SHIELD_OFFLINE_MODE=true — ML detector disabled, "
                "skipping DeBERTa load. Heuristic + Structural layers remain active."
            )
            self.disabled = True

    def _do_load(self) -> None:
        """Actually load the model. Must be called with ``_load_lock`` held."""
        try:
            logger.info(f"Loading ML model: {self.model_name}...")
            # Check if model exists locally or download it
            # We use the pipeline API for simplicity, specifying cache_dir
            # device=-1 ensures CPU usage
            self.pipeline = pipeline(
                "text-classification",
                model=self.model_name,
                tokenizer=self.model_name,
                device=-1,
                model_kwargs={"cache_dir": str(self.cache_dir)}
            )
            self.loaded = True
            logger.info("ML model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.loaded = False

    def _ensure_loaded(self) -> None:
        """Load the model on first call. Thread-safe via ``_load_lock``."""
        if self.loaded or self.disabled:
            return
        with self._load_lock:
            # Re-check under the lock — another thread may have loaded it
            # while we were waiting.
            if self.loaded or self.disabled:
                return
            self._do_load()

    def warm_up(self) -> None:
        """Eagerly load the model in the calling thread.

        Useful for the server entry point: lets the operator pay the load
        cost on a controlled schedule (e.g. a one-shot startup probe) without
        blocking the very first user request. Safe to call multiple times.
        """
        if self.disabled:
            return
        with self._load_lock:
            if not self.loaded:
                self._do_load()

    def check(self, prompt: str):
        """Returns: (is_injection, risk_score, category)"""
        if self.disabled:
            # Offline mode: never load, never run inference. The caller still
            # runs heuristic + structural layers in front of us.
            return False, 0.0, None

        if not self.loaded:
            # Lazy-load on first call. Concurrent first-callers serialize on
            # the class lock; subsequent calls short-circuit on self.loaded.
            self._ensure_loaded()

        if not self.loaded:
            # Load attempt failed (network error, OOM, etc.). Stay consistent
            # with the previous behavior: skip semantic analysis rather than
            # crash the request.
            logger.warning("ML model not loaded, skipping semantic analysis.")
            return False, 0.0, None

        try:
            # Result is a list of dicts: [{'label': 'INJECTION', 'score': 0.99}]
            result = self.pipeline(prompt, truncation=True, max_length=512)

            label = result[0]['label']
            score = result[0]['score']

            risk_score = score
            if label.upper() == 'SAFE':
                risk_score = 1.0 - score

            if label.upper() == 'INJECTION' and score > config.risk_threshold:
                return True, risk_score, "Semantic Injection"

            return False, risk_score, None

        except Exception as e:
            logger.error(f"Inference error: {e}")
            return False, 0.0, None
