# Changelog

All notable changes will be documented in this file.

## [Unreleased]

### Changed
- `MLDetector.__init__` no longer loads the DeBERTa model (~400MB, multi-second download).
  The load is deferred to the first `.check()` call so MCP server startup is instant.
  Concurrent first-callers are de-duplicated via a class-level load lock, so two
  simultaneous requests cannot trigger two parallel downloads. Operators that want
  to pay the load cost on a controlled schedule (e.g. a startup probe) can call
  `MLDetector().warm_up()` explicitly. The `Dockerfile` pre-cache step and the
  `demo/streamlit_app.py` detector loader now call `warm_up()` so behavior is
  preserved end-to-end.
- `MLDetector` now respects `SHIELD_OFFLINE_MODE=true` (and `shield_config.json` →
  `offline_mode: true`). When set, the ML layer short-circuits at construction time
  so users who only want heuristic + structural detection never download the model.
  Documented in the README env-var table and the Level-2 section.

### Tests
- `tests/test_ml_integration.py`: 6 new tests covering lazy load semantics, the
  class-level lock, `warm_up()`, `offline_mode` short-circuit (both via env and via
  patched config), and idempotent failure after a load error.

## [0.1.0] - 2026-04-13

### Added
- Initial release
- Tiered detection pipeline:
  - Level 1: Heuristic (regex) detection
  - Level 2: Semantic analysis via DeBERTa ML model
  - Level 3: Structural encoding/obfuscation checks
- MCP server integration (`analyze_prompt` tool)
- Configurable risk threshold via `shield_config.json`
- Docker support
- Test suite covering all detectors
