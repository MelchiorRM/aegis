"""Detection metrics at fixed false-positive rates and realistic prevalence, plus statistics."""

from __future__ import annotations

from typing import Sequence

import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score


def threshold_at_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """Return a threshold that flags at most ``target_fpr`` of these benign scores."""
    return float(np.quantile(benign_scores, 1 - target_fpr, method="higher"))


def prevalence_weights(y: np.ndarray, attack_prevalence: float) -> np.ndarray:
    """Weight rows so the test set behaves as if attacks had this share of traffic."""
    n_attack = int((y == 1).sum())
    n_benign = int((y == 0).sum())
    if n_attack == 0 or n_benign == 0:
        raise ValueError("Prevalence weighting needs both benign and attack rows")
    return np.where(y == 1, attack_prevalence / n_attack, (1 - attack_prevalence) / n_benign)


def precision_at_prevalence(recall: float, fpr: float, attack_prevalence: float) -> float:
    """Precision implied by a recall and FPR at this attack share (NaN if nothing is flagged)."""
    flagged = attack_prevalence * recall + (1 - attack_prevalence) * fpr
    return float(attack_prevalence * recall / flagged) if flagged > 0 else float("nan")


def evaluate_scores(
    y: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    target_fpr: float,
    attack_prevalences: Sequence[float],
) -> dict[str, float]:
    """Score a test set using a threshold chosen earlier from validation benign traffic.

    ``recall_at_oracle_fpr`` picks its threshold on the test set. It cannot be deployed,
    but comparing it with ``recall`` separates ranking quality from threshold drift.
    """
    attack, benign = scores[y == 1], scores[y == 0]
    recall = float((attack > threshold).mean())
    fpr = float((benign > threshold).mean())
    oracle = threshold_at_fpr(benign, target_fpr)
    metrics = {
        "recall": recall,
        "realized_fpr": fpr,
        "recall_at_oracle_fpr": float((attack > oracle).mean()),
    }
    for prevalence in attack_prevalences:
        metrics[f"pr_auc_prev_{prevalence:g}"] = float(
            average_precision_score(y, scores, sample_weight=prevalence_weights(y, prevalence))
        )
        metrics[f"precision_prev_{prevalence:g}"] = precision_at_prevalence(recall, fpr, prevalence)
    return metrics


def bootstrap_ci(
    values: Sequence[float], samples: int = 10_000, level: float = 0.95, seed: int = 0
) -> tuple[float, float]:
    """Percentile bootstrap interval for the mean across seeds."""
    data = np.asarray(values, dtype=float)
    data = data[~np.isnan(data)]
    if data.size == 0:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    means = rng.choice(data, size=(samples, data.size), replace=True).mean(axis=1)
    tail = (1 - level) / 2
    return float(np.quantile(means, tail)), float(np.quantile(means, 1 - tail))


def paired_comparison(
    a: Sequence[float], b: Sequence[float], samples: int = 10_000, seed: int = 0
) -> dict[str, float]:
    """Compare paired per-seed results as a minus b.

    With n pairs the smallest possible two-sided Wilcoxon p-value is 2 / 2**n, or 0.0625
    at five seeds, so a five-seed run cannot reach p < 0.05. The configuration file allows
    up to the ten seeds v2 specifies; the interval and effect size also apply at five.
    """
    x, y = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if x.shape != y.shape:
        raise ValueError("Paired comparison needs one value per seed on each side")
    keep = ~(np.isnan(x) | np.isnan(y))
    diff = x[keep] - y[keep]
    if diff.size == 0:
        nan = float("nan")
        return {"n": 0, "mean_diff": nan, "ci_low": nan, "ci_high": nan, "p_wilcoxon": nan, "cohen_dz": nan}
    low, high = bootstrap_ci(diff, samples=samples, seed=seed)
    p_value = 1.0 if np.all(diff == 0) else float(stats.wilcoxon(diff).pvalue)
    spread = diff.std(ddof=1) if diff.size > 1 else 0.0
    return {
        "n": int(diff.size),
        "mean_diff": float(diff.mean()),
        "ci_low": low,
        "ci_high": high,
        "p_wilcoxon": p_value,
        "cohen_dz": float(diff.mean() / spread) if spread > 0 else float("nan"),
    }
