# Contributing to ThePromptDefence

Welcome! Thanks for considering contributing.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/aniketkarne/ThePromptDefence
cd ThePromptDefence

# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest
```

## Adding Detection Patterns

### Heuristic Rules (`src/shield_mcp/detectors/heuristics.py`)
Add regex patterns with a descriptive category name. Be specific — avoid patterns that could produce false positives on normal user input.

### The Corpus Is the Contract

Every pattern change is measured, not asserted. `benchmarks/efficacy.py` holds
the corpus — 66 attack prompts and 90 benign prompts — and replays it against a
fresh detector:

```bash
python benchmarks/efficacy.py    # prints the confusion matrix, exits non-zero on a regression
pytest tests/test_efficacy.py    # same thresholds, as a pytest contract
```

CI gates on precision ≥ 0.99, recall ≥ 0.99 and FPR ≤ 1%. So:

- **Adding a pattern** — add the attack phrasing it catches to `ATTACK_PROMPTS`.
  Without a case there, the pattern is unmeasured and the next person to change
  it can break it silently.
- **Changing a pattern** — add the benign prompts it now misreads to
  `BENIGN_PROMPTS`. Every false positive you find by hand belongs in the
  corpus, otherwise it comes back.

The corpus was written alongside the patterns, so it measures regression, not
accuracy on live traffic. Keep it honest: if you widen a pattern until it
covers more attack phrasings, add the ordinary English it now trips over.

### Structural Checks (`src/shield_mcp/detectors/structural.py`)
For encoding/obfuscation detection. Add checks for new encoding schemes if needed.

### ML Model (`src/shield_mcp/detectors/ml_models.py`)
Uses `protectai/deberta-v3-base-prompt-injection-v2`. Only change the model if the current one shows consistent false negatives on real attack patterns.

## Pull Request Guidelines

1. **Test your changes** — add tests in `tests/` for new patterns/features
2. **Keep it focused** — one feature or fix per PR
3. **Update docs** — if you add a config option or change behavior, update README.md
4. **Run the full suite** — `pytest` should pass before submitting
5. **Run the benchmark** — `python benchmarks/efficacy.py` must still report precision ≥ 0.99, recall ≥ 0.99 and FPR ≤ 1%

## Reporting Issues

Please include:
- The prompt that triggered a false positive/negative
- Your `shield_config.json` (if custom)
- Expected vs actual behavior

## Code Style

- Standard Python formatting (Black-compatible)
- Type hints appreciated but not required
- Docstrings on public methods
