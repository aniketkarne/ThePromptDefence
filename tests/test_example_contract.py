"""Contract tests for the examples/ surface.

The example docs (examples/cursor/) show verdicts, config, and tool output
shapes. Every claim there is pinned against the real code so docs cannot
silently drift away from what the tool actually returns.
"""
import json
import re
from pathlib import Path

from shield_mcp.detectors.heuristics import HeuristicDetector
from shield_mcp.detectors.structural import StructuralDetector

REPO_ROOT = Path(__file__).resolve().parent.parent
CURSOR_DIR = REPO_ROOT / "examples" / "cursor"

# The exact output contract of analyze_prompt (see src/shield_mcp/server.py).
TOOL_OUTPUT_FIELDS = {"is_injection", "risk_score", "category"}
# Placeholders an agent-facing verdict template may reference.
ALLOWED_PLACEHOLDERS = {"<is_injection>", "<risk_score>", "<category>"}


def _documented_example_verdict():
    """Extract the JSON verdict block the example README documents."""
    readme = (CURSOR_DIR / "README.md").read_text()
    blocks = re.findall(r"```json\n(.*?)```", readme, re.DOTALL)
    for block in blocks:
        data = json.loads(block)
        if "is_injection" in data:
            return data
    raise AssertionError("examples/cursor/README.md has no documented verdict JSON block")


def test_poisoned_doc_verdict_matches_docs():
    """The demo's documented verdict must be what the detectors return."""
    doc = (CURSOR_DIR / "poisoned_doc.md").read_text()
    documented = _documented_example_verdict()

    is_inj, score, cat = HeuristicDetector().check(doc)
    assert is_inj is True
    assert (is_inj, score, cat) == (
        documented["is_injection"],
        documented["risk_score"],
        documented["category"],
    )


def test_documented_example_shape_is_tool_shape():
    """The documented verdict block must carry exactly the tool's fields."""
    assert set(_documented_example_verdict()) == TOOL_OUTPUT_FIELDS


def test_documented_category_is_a_real_category():
    """A category named in the docs must exist in the detector's category set."""
    documented = _documented_example_verdict()
    real_categories = {cat for _p, cat, _s in HeuristicDetector.PATTERNS_RAW}
    assert documented["category"] in real_categories


def test_benign_prompt_is_clean_with_zero_risk():
    """Clean input must come back False / 0.0 / None on every layer."""
    benign = "Please summarize this quarter's OKR document for my team."
    for detector in (HeuristicDetector(), StructuralDetector()):
        is_inj, score, cat = detector.check(benign)
        assert (is_inj, score, cat) == (False, 0.0, None)


def test_verdict_templates_only_reference_real_fields():
    """Agent-facing 'Blocked:' verdict templates may only use real output fields.

    Covers examples/cursor/README.md. The same contract applies to
    examples/cursor/.cursorrules (its verdict template still renders a
    <latency> placeholder that analyze_prompt never returns) — fixing that
    file is left to the maintainer, see the PR description.
    """
    text = (CURSOR_DIR / "README.md").read_text()
    for line in text.splitlines():
        if "Blocked:" in line:
            for placeholder in re.findall(r"<[^>]+>", line):
                assert placeholder in ALLOWED_PLACEHOLDERS, (
                    f"README.md verdict template references {placeholder}, "
                    "which analyze_prompt never returns"
                )
            assert "ms)" not in line, (
                "README.md renders a latency in the verdict, but "
                "analyze_prompt never returns one"
            )


def test_readme_config_block_matches_mcp_config():
    """The README's paste-in config must match the shipped mcp_config.json."""
    shipped = json.loads((CURSOR_DIR / "mcp_config.json").read_text())
    readme = (CURSOR_DIR / "README.md").read_text()
    blocks = re.findall(r"```json\n(.*?)```", readme, re.DOTALL)
    pasted = None
    for block in blocks:
        data = json.loads(block)
        if "mcpServers" in data:
            pasted = data
    assert pasted is not None, "examples/cursor/README.md has no mcpServers config block"
    assert pasted == shipped


def test_mcp_config_env_keys_are_consumed():
    """Every env var the example sets must actually be read by Config."""
    import os

    from shield_mcp.utils.config import Config

    mcp_config = json.loads((CURSOR_DIR / "mcp_config.json").read_text())
    env = mcp_config["mcpServers"]["ThePromptDefence"]["env"]

    os.environ["SHIELD_RISK_THRESHOLD"] = env["SHIELD_RISK_THRESHOLD"]
    os.environ["SHIELD_LOG_DIR"] = env["SHIELD_LOG_DIR"]
    try:
        cfg = Config()
        assert cfg.risk_threshold == float(env["SHIELD_RISK_THRESHOLD"])
        assert cfg.log_dir == Path(env["SHIELD_LOG_DIR"])
        assert cfg.log_file == Path(env["SHIELD_LOG_DIR"]) / "shield.log"
    finally:
        del os.environ["SHIELD_RISK_THRESHOLD"]
        del os.environ["SHIELD_LOG_DIR"]
