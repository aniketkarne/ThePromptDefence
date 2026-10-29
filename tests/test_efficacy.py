"""Confusion-matrix contract for the heuristic detector.

Runs the same corpus as ``benchmarks/efficacy.py`` and asserts the thresholds
below. A detector change that trades recall for precision — or the reverse —
fails this test instead of shipping silently.

Thresholds are tight on purpose. The corpus is the one in
``benchmarks/efficacy.py``; extend it there when you add a pattern.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from efficacy import run_corpus  # noqa: E402


@pytest.fixture(scope="module")
def result():
    return run_corpus()


def test_precision(result):
    """Almost everything flagged must actually be an attack."""
    assert result["precision"] >= 0.99, (
        f"precision {result['precision']:.4f} below 0.99 — "
        f"{result['fp']} false positive(s): {result['false_positives']}"
    )


def test_recall(result):
    """Almost every attack must be caught."""
    assert result["recall"] >= 0.99, (
        f"recall {result['recall']:.4f} below 0.99 — "
        f"{result['fn']} false negative(s): {result['false_negatives']}"
    )


def test_false_positive_rate(result):
    """The false-positive rate must stay under 1% of benign traffic."""
    assert result["fpr"] <= 0.01, (
        f"FPR {result['fpr']:.4f} above 0.01 — "
        f"{result['fp']} false positive(s): {result['false_positives']}"
    )


def test_corpus_is_not_empty(result):
    """Guard against a shrunken corpus silently passing every threshold."""
    assert result["total"] >= 100
    assert result["tp"] >= 50
    assert result["tn"] >= 30
