"""Config B analysis rules (section 9) and the determinism comparison (section 10). Fits nothing.

The tables follow these rules:
- B − B0 is primary, per held-out family, in the raw view at the primary target FPR.
- Two-family, single-family and neither-family folds are kept apart and never pooled.
- A contrast is classified positive, negative or inconclusive from its 95% interval alone, with no minimum
  effect size. The effect and its interval are always reported.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from aegis.config_b import protocol
from aegis.config_b.model import InvariantViolation
from aegis.evaluation.metrics import paired_comparison
from aegis.experiments.artifacts import rule_report, summarize_treatments

CONTRASTS = (("B", "B0"), ("B", "A"), ("B0", "A"))
METRICS = {"raw_recall": "raw", "overlap_excluded_recall": "overlap-excluded", "recall": "deduplicated"}
TIMING = ("fit_seconds",)
KEYS = ["dataset", "arm", "seed", "fold", "treatment", "family", "target_fpr"]

LIMITATIONS = [
    "Single-dataset result on improved CICIDS2017; not cross-dataset validation. UNSW-NB15: B = B0 = A by "
    "construction (no mapping qualified); no Config B fit was run there.",
    "B − B0 is the effect of the specified replay-composition policies (CAGE-derived split over the mapped seen "
    "families vs size-proportional replay over the seen attack pool), not an isolated causal effect of simulator "
    "information. In the bot fold B0 is about 92% dos replay.",
    "Single-family folds (brute_force, portscan) cannot establish a benefit from simulator-derived weighting: all of "
    "B's replay goes to the remaining mapped family.",
    "The weights barely vary across fold seeds (brute_force 0.371-0.378): in effect one fixed 37:63 composition.",
    "Mapped actions are 32,215 of 297,626 red actions (10.8%; 11.4% with the rejected SQLInjection); Impact and "
    "DegradeServices make up 61%. The scenario is CAGE 4 scripted red behaviour against a sleeping blue, not a "
    "representative real-world attacker population.",
    "Five seeds: the smallest attainable two-sided Wilcoxon p is 0.0625, so no test reaches 0.05. Effect sizes and "
    "intervals are read first; a bootstrap interval over five seeds is coarse.",
    "A positive or negative classification means only that the interval excludes zero; it is not a claim of "
    "practical importance.",
    "With min_samples_leaf=2, a record and its copy can form a leaf on their own.",
]


def classify(ci_low: float, ci_high: float) -> str:
    """Positive if the interval lies entirely above zero, negative if entirely below, otherwise inconclusive."""
    if np.isnan(ci_low) or np.isnan(ci_high):
        return "not estimable"
    if ci_low > 0:
        return "positive"
    if ci_high < 0:
        return "negative"
    return "inconclusive"


def _paired(left: pd.DataFrame, right: pd.DataFrame, value: str, samples: int) -> dict:
    merged = left.merge(right, on="seed", suffixes=("_l", "_r"))
    if len(merged) != len(left) or len(merged) != len(right):
        raise ValueError("a paired contrast needs the same seeds on both sides")
    for column in ("attack_rows_hash", "benign_rows_hash"):
        if column in left and (merged[f"{column}_l"] != merged[f"{column}_r"]).any():
            raise ValueError(f"a paired contrast was not evaluated on identical rows ({column})")
    merged = merged.sort_values("seed")
    return paired_comparison(merged[f"{value}_l"].to_numpy(), merged[f"{value}_r"].to_numpy(), samples=samples)


def contrasts(results: pd.DataFrame, samples: int, primary_fpr: float) -> pd.DataFrame:
    """B − B0, B − A and B0 − A, per held-out family, target FPR and view."""
    held = results[(results["fold"] == "holdout") & (results["treatment"] == protocol.REFERENCE)]
    out = []
    for (family, fpr), group in held.groupby(["family", "target_fpr"], sort=True):
        for left, right in CONTRASTS:
            a, b = group[group["arm"] == left], group[group["arm"] == right]
            if a.empty or b.empty:
                continue
            for metric, view in METRICS.items():
                stats = _paired(a, b, metric, samples)
                primary = (left, right) == ("B", "B0") and metric == "raw_recall" and np.isclose(fpr, primary_fpr)
                out.append({
                    "family": family, "fold_group": protocol.fold_group(family), "target_fpr": fpr,
                    "contrast": f"{left} - {right}", "view": view, "role": "primary" if primary else "secondary",
                    f"mean_{left}": float(a[metric].mean()), f"mean_{right}": float(b[metric].mean()),
                    **stats, "classification": classify(stats["ci_low"], stats["ci_high"]),
                    f"ratios_{left}": ",".join(f"{r:g}" for r in a.sort_values("seed")["ratio"]),
                    f"ratios_{right}": ",".join(f"{r:g}" for r in b.sort_values("seed")["ratio"]),
                })
    return pd.DataFrame(out)


def degradation(results: pd.DataFrame, samples: int) -> pd.DataFrame:
    """Seen minus held-out raw recall per arm and seed, and its difference per contrast (section 9.2)."""
    ref = results[results["treatment"] == protocol.REFERENCE]
    seen = ref[ref["fold"] == "seen"][["arm", "seed", "family", "target_fpr", "raw_recall"]]
    held = ref[ref["fold"] == "holdout"][["arm", "seed", "family", "target_fpr", "raw_recall"]]
    deg = seen.merge(held, on=["arm", "seed", "family", "target_fpr"], suffixes=("_seen", "_held"))
    deg["degradation"] = deg["raw_recall_seen"] - deg["raw_recall_held"]
    out = []
    for (family, fpr), group in deg.groupby(["family", "target_fpr"], sort=True):
        for left, right in CONTRASTS:
            a, b = group[group["arm"] == left], group[group["arm"] == right]
            if a.empty or b.empty:
                continue
            stats = _paired(a, b, "degradation", samples)
            out.append({"family": family, "fold_group": protocol.fold_group(family), "target_fpr": fpr,
                        "contrast": f"{left} - {right}", **stats,
                        "classification": classify(stats["ci_low"], stats["ci_high"])})
    return pd.DataFrame(out)


def shortcut_effects(results: pd.DataFrame, samples: int, primary_fpr: float) -> tuple[pd.DataFrame, dict]:
    """Config A's unchanged shortcut rule, applied separately to each arm's audit (section 9.3)."""
    tables, reports = [], {}
    held = results[results["fold"] == "holdout"]
    for arm in protocol.ARMS:
        part = held[held["arm"] == arm]
        if part["treatment"].nunique() < 2:
            continue
        effects = summarize_treatments(part.drop(columns=["arm"]), samples, primary_fpr)
        effects.insert(0, "arm", arm)
        tables.append(effects)
        reports[arm] = rule_report(effects, primary_fpr)
    return (pd.concat(tables, ignore_index=True) if tables else pd.DataFrame()), reports


def neither_family_control(inner: pd.DataFrame) -> dict:
    """Section 6.1: in neither-family inner folds, B = B0 = A, so inner recall must be identical everywhere.

    A difference stops the run as an invariant failure.
    """
    part = inner[inner["fold_group"] == "neither_family"]
    report = {"folds": sorted({f"({o}, {i})" for o, i in zip(part["outer_family"], part["inner_family"])}),
              "rows": int(len(part)), "identical": True}
    for keys, group in part.groupby(["seed", "outer_family", "inner_family", "target_fpr"]):
        for column in ("inner_recall", "inner_fpr"):
            if group[column].nunique(dropna=False) > 1:
                report["identical"] = False
                raise InvariantViolation(f"neither-family control {keys}: {column} differs across arms or ratios")
    if (part["replay_total"] != 0).any():
        raise InvariantViolation("neither-family control: a replay was added where no mapped family is in training")
    return report


def selection_tables(inner: pd.DataFrame, primary_fpr: float) -> pd.DataFrame:
    """Mean inner recall per arm, seed, outer family, fold group and candidate, at the primary target FPR."""
    part = inner[np.isclose(inner["target_fpr"], primary_fpr)]
    return (part.groupby(["arm", "seed", "outer_family", "fold_group", "candidate"], as_index=False)
            .agg(mean_inner_recall=("inner_recall", "mean"), inner_folds=("inner_family", "nunique"),
                 replay_total=("replay_total", "mean")))


def compare_exact(original: pd.DataFrame, rerun: pd.DataFrame) -> dict:
    """Section 10: every recorded column except timing must match exactly, NaN with NaN. No tolerance."""
    keys = [k for k in KEYS if k in original.columns]
    a = original.sort_values(keys).reset_index(drop=True)
    b = rerun.sort_values(keys).reset_index(drop=True)
    report = {"rows_original": int(len(a)), "rows_rerun": int(len(b)), "differences": []}
    if len(a) != len(b) or not a[keys].astype(str).equals(b[keys].astype(str)):
        report.update(passed=False, n_differences=-1, reason="the rerun does not have the same rows")
        return report
    columns = [c for c in a.columns if c not in TIMING]
    if set(columns) != {c for c in b.columns if c not in TIMING}:
        report.update(passed=False, n_differences=-1, reason="the rerun does not have the same columns")
        return report
    for column in columns:
        left, right = a[column], b[column]
        same = (left == right) | (left.isna() & right.isna())
        for i in np.flatnonzero(~same.to_numpy()):
            report["differences"].append({"column": column, **{k: a.loc[i, k] for k in keys},
                                          "original": a.loc[i, column], "rerun": b.loc[i, column]})
    report["n_differences"] = len(report["differences"])
    report["passed"] = report["n_differences"] == 0
    return report


def report_tables(results: pd.DataFrame, inner: pd.DataFrame, samples: int, primary_fpr: float) -> dict:
    effects, rules = shortcut_effects(results, samples, primary_fpr)
    table = contrasts(results, samples, primary_fpr)
    primary = table[table["role"] == "primary"] if len(table) else table
    return {
        "contrasts": table,
        "degradation": degradation(results, samples),
        "shortcut_effects": effects,
        "selection_inner": selection_tables(inner, primary_fpr),
        "shortcut_rules": rules,
        "neither_family_control": neither_family_control(inner),
        "primary_by_fold_group": {
            group: primary[primary["fold_group"] == group][["family", "mean_diff", "ci_low", "ci_high", "cohen_dz",
                                                            "p_wilcoxon", "classification"]].to_dict("records")
            for group in ("two_family", "single_family")
        },
        "pooled_estimate": "none: held-out families are never pooled (section 9.1)",
    }
