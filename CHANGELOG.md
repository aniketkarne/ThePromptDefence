# Changelog

All notable changes will be documented in this file.

## [Unreleased]

### Fixed
- **`pip install` was broken on a fresh environment.** `mcp` had no version pin in `pyproject.toml`, so a clean install on Sept 2026 resolves to `mcp 2.x`, where `mcp.server.fastmcp.FastMCP` no longer exists (renamed to `mcp.server.mcpserver.MCPServer`). The server crashed on import with `ModuleNotFoundError`. The CI's `tests/test_full_server.py` and `tests/test_server_logic.py` were silently broken by the same issue — collection errored, never reached the test bodies. Pinned `mcp<2`; migration to the v2 API is tracked as follow-up.
- **Structural detector false-positive flood on plain-English tokens.** Any whitespace-separated token >30 chars matching the base64/hex alphabet (MD5/SHA hashes, UUIDs, long URLs, common English words longer than 30 chars) was flagged as `Base64 Obfuscation` or `Hex Encoding` even when the decoded bytes were binary garbage. Tightened to require the decoded text be at least 8 chars and at least 50% alphabetic+space — real encoded payloads decode to >90% letters, plain English decodes to ~20%. The README's headline base64/hex TPs still fire. Added 6 FP regression cases + 2 TP regression cases.
- **Server wrote the first 50 chars of every prompt to its log file.** `server.py:46` did `logger.info(f"Analyzing prompt: {prompt[:50]}...")`, contradicting the README's "100% Local — No external API calls" promise. Replaced with `sha256(prompt)[:16] + length` so logs are forensically useful (you can dedupe prompt submissions, count uniques, prove a prompt was analyzed) without storing the prompt body. Added privacy regression test that fails if any substring of a secret prompt leaks to the log.

### Changed
- Dockerfile now uses `python:3.10-slim-bookworm` (was `python:3.10-slim`, which drifts) and `CMD ["ThePromptDefence"]` (was `python -m shield_mcp.server`), using the `[project.scripts]` entry point so the Dockerfile stays in sync with `pyproject.toml`.

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
