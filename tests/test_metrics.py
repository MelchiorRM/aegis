import numpy as np
import pytest
from sklearn.metrics import average_precision_score

from aegis.evaluation.metrics import (
    bootstrap_ci,
    evaluate_scores,
    paired_comparison,
    precision_at_prevalence,
    prevalence_weights,
    threshold_at_fpr,
)


def test_threshold_flags_at_most_the_target_share():
    benign = np.arange(1000, dtype=float)
    threshold = threshold_at_fpr(benign, 0.01)
    assert (benign > threshold).mean() <= 0.01
    assert (benign > threshold).mean() > 0.005


def test_prevalence_weights_match_a_literally_resampled_test_set():
    rng = np.random.default_rng(0)
    y = np.array([1] * 100 + [0] * 100)
    scores = np.concatenate([rng.normal(1, 1, 100), rng.normal(0, 1, 100)])
    weighted = average_precision_score(y, scores, sample_weight=prevalence_weights(y, 0.1))
    # One copy of each attack and nine of each benign row gives 10% attacks.
    resampled_y = np.concatenate([y[:100], np.repeat(y[100:], 9)])
    resampled = np.concatenate([scores[:100], np.repeat(scores[100:], 9)])
    assert weighted == pytest.approx(average_precision_score(resampled_y, resampled))


def test_precision_at_prevalence():
    assert precision_at_prevalence(0.9, 0.01, 0.01) == pytest.approx(0.009 / (0.009 + 0.0099))
    assert np.isnan(precision_at_prevalence(0.0, 0.0, 0.01))


def test_evaluate_scores_uses_given_threshold_and_reports_drift():
    y = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    scores = np.array([10.0, 9.0, 4.0, 1.0, 5.0, 3.0, 2.0, 0.0])
    metrics = evaluate_scores(y, scores, threshold=3.5, target_fpr=0.25, attack_prevalences=[0.1])
    assert metrics["recall"] == 0.75
    assert metrics["realized_fpr"] == 0.25
    assert metrics["recall_at_oracle_fpr"] == 0.5
    assert 0 < metrics["pr_auc_prev_0.1"] <= 1
    assert metrics["precision_prev_0.1"] == pytest.approx(0.075 / (0.075 + 0.225))


def test_bootstrap_ci_contains_the_mean_and_ignores_nan():
    low, high = bootstrap_ci([0.1, 0.2, 0.3, float("nan")], samples=2000)
    assert low <= 0.2 <= high
    assert bootstrap_ci([float("nan")]) != bootstrap_ci([1.0])


def test_paired_comparison():
    result = paired_comparison([0.9, 0.8, 0.85, 0.95, 0.7], [0.5, 0.45, 0.6, 0.55, 0.4], samples=2000)
    assert result["n"] == 5
    assert result["mean_diff"] == pytest.approx(0.34)
    assert result["ci_low"] > 0
    assert result["p_wilcoxon"] == pytest.approx(0.0625)
    assert result["cohen_dz"] > 0


def test_paired_comparison_of_identical_values():
    result = paired_comparison([0.5, 0.5], [0.5, 0.5], samples=100)
    assert result["mean_diff"] == 0
    assert result["p_wilcoxon"] == 1.0
    assert np.isnan(result["cohen_dz"])
