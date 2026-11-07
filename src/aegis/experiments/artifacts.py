"""Artifact-resistance and sensitivity audit: does held-out recall survive removing dataset shortcuts?

    python -m aegis.experiments.artifacts --config configs/baseline.yaml --out results/config_a_artifacts

This audits a baseline that was selected using these same test results, so it is not an unbiased
estimate of generalization. Every treatment refits the Random Forest baseline on the same folds as
the reference, so differences are paired by seed and family on identical held-out rows. Recall on
raw published rows is primary, and deduplicated recall is a secondary sensitivity analysis. No label
is ever changed. Results go to their own folder, and a finished fold is kept, so an interrupted run
continues where it stopped.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from aegis.config import BaselineConfig, load_config
from aegis.data.dataset import BENIGN, Dataset, remove_duplicates
from aegis.data.loaders import load_dataset
from aegis.data.suspect_benign import suspect_benign_mask
from aegis.data.splits import Fold, eligible_families, holdout_fold, make_partition
from aegis.evaluation.metrics import evaluate_scores, paired_comparison, threshold_at_fpr
from aegis.experiments.baseline import FoldStore, Progress, _write_manifest
from aegis.models.baseline import RandomForestBaseline
from aegis.provenance import source_hash

EVALUATION_ROLE = "artifact-resistance and sensitivity audit; not an unbiased generalization estimate"
REFERENCE = "reference"
ROW_KEYS = ["dataset", "seed", "treatment", "family", "target_fpr"]

# Columns left out when comparing flows, so two flows match if only their timing differs.
CICIDS_TIMING = re.compile(r"Duration|IAT|/s|Active|Idle|Bulk Rate")
UNSW_TIMING = ("dur", "rate", "sload", "dload", "sinpkt", "dinpkt", "sjit", "djit", "tcprtt", "synack", "ackdat")
# TCP base sequence numbers are random per flow, so they would hide otherwise identical flows.
UNSW_SEQUENCE = ("stcpb", "dtcpb")

# TCP window sizes reflect the sending host's network stack as well as its behavior.
TCP_WINDOW = ("Init_Win_bytes_forward", "Init_Win_bytes_backward", "swin", "dwin")
# -1 in these columns means no value was observed.
NUMERIC_MARKER = -1
NUMERIC_MARKER_COLUMNS = ("Init_Win_bytes_forward", "Init_Win_bytes_backward")
# The publisher defines "-" as "not much used service": a catch-all category, not missing data.
# It still separates families strongly, so the treatments test what the model takes from it.
CATEGORICAL_MARKER = "-"
CATEGORICAL_MARKER_COLUMNS = ("service",)

# A treatment shows shortcut dependence if the mean of its paired per-seed recall drops is at least
# this large and the 95% interval of that mean lies entirely above zero. Set before the run.
SHORTCUT_MIN_DROP = 0.10
RULE_TREATMENTS = (
    "remove_matching_signatures", "no_tcp_window", "neutralize_missing_markers", "no_context_counts", "all_controls",
)
LABEL_SENSITIVITY = "exclude_suspect_benign"


@dataclass(frozen=True)
class Treatment:
    name: str
    drop: tuple[str, ...] = ()
    neutralize: tuple[str, ...] = ()  # Numeric marker becomes NaN, then the training median.
    remove_signatures: bool = False
    missingness_only: bool = False
    marker_only: tuple[str, ...] = ()  # The category is replaced by one flag for its marker value.
    exclude_suspect: bool = False


def signature_columns(ds: Dataset) -> list[str]:
    """Columns that define a flow's signature: everything except timing and random values."""
    if ds.name == "cicids2017":
        return [c for c in ds.X.columns if not CICIDS_TIMING.search(c)]
    excluded = {*UNSW_TIMING, *UNSW_SEQUENCE}
    return [c for c in ds.X.columns if c not in excluded]


def signatures(ds: Dataset) -> np.ndarray:
    return pd.util.hash_pandas_object(ds.X[signature_columns(ds)], index=False).to_numpy()


def missingness_frame(ds: Dataset) -> pd.DataFrame:
    """One indicator per missing-value marker, and nothing else about the flow."""
    indicators = {}
    for column in ds.numeric:
        values = ds.X[column]
        if values.isna().any():
            indicators[f"{column}_missing"] = values.isna()
        if column in NUMERIC_MARKER_COLUMNS:
            indicators[f"{column}_marker"] = values == NUMERIC_MARKER
    for column in CATEGORICAL_MARKER_COLUMNS:
        if column in ds.categorical:
            indicators[f"{column}_marker"] = ds.X[column] == CATEGORICAL_MARKER
    return pd.DataFrame(indicators, index=ds.X.index).astype(np.float32)


def treatments_for(ds: Dataset, has_suspect_benign: bool = False) -> list[Treatment]:
    """The treatments that apply to this dataset's columns."""
    columns = set(ds.X.columns)
    window = tuple(c for c in TCP_WINDOW if c in columns)
    numeric_markers = tuple(c for c in NUMERIC_MARKER_COLUMNS if c in columns)
    category_markers = tuple(
        c for c in CATEGORICAL_MARKER_COLUMNS
        if c in ds.categorical and (ds.X[c] == CATEGORICAL_MARKER).any()
    )
    context = tuple(c for c in ds.X.columns if c.startswith("ct_"))

    plan = [Treatment(REFERENCE), Treatment("remove_matching_signatures", remove_signatures=True)]
    if window:
        plan.append(Treatment("no_tcp_window", drop=window))
    if numeric_markers or category_markers:
        plan.append(Treatment("neutralize_missing_markers", drop=category_markers, neutralize=numeric_markers))
    if missingness_frame(ds).shape[1]:
        plan.append(Treatment("missingness_only", missingness_only=True))
    if context:
        plan.append(Treatment("no_context_counts", drop=context))
    if category_markers:
        # With the reference (marker kept as a category) and neutralize_missing_markers (column
        # removed), this completes the service comparison. Adding a flag beside the full category
        # would give a forest the same information as the reference, so the names are removed.
        plan.append(Treatment("service_marker_only", marker_only=category_markers))
    if has_suspect_benign:
        plan.append(Treatment(LABEL_SENSITIVITY, exclude_suspect=True))
    plan.append(
        Treatment(
            "all_controls",
            drop=(*window, *category_markers),
            neutralize=tuple(c for c in numeric_markers if c not in window),
            remove_signatures=True,
        )
    )
    return plan


def treat_frame(frame: pd.DataFrame, treatment: Treatment, indicators: pd.DataFrame) -> pd.DataFrame:
    """Apply a treatment to these rows; ``indicators`` holds the same rows' marker columns."""
    if treatment.missingness_only:
        return indicators
    if treatment.neutralize:
        frame = frame.assign(**{c: frame[c].where(frame[c] != NUMERIC_MARKER) for c in treatment.neutralize})
    if treatment.marker_only:
        flags = {f"{c}_marker": (frame[c] == CATEGORICAL_MARKER).astype(np.float32) for c in treatment.marker_only}
        frame = frame.assign(**flags).drop(columns=list(treatment.marker_only))
    return frame.drop(columns=list(treatment.drop))


def treated_features(ds: Dataset, treatment: Treatment, rows: np.ndarray, indicators: pd.DataFrame) -> pd.DataFrame:
    return treat_frame(ds.X.iloc[rows], treatment, indicators.iloc[rows])


def training_rows(fold: Fold, ds: Dataset, treatment: Treatment, flow_signatures: np.ndarray) -> np.ndarray:
    """Remove training attack rows that match the held-out family apart from timing.

    Benign rows stay, because they cannot teach the model to flag the family. Removal follows
    the training cap, so every other training row is the same as in the reference fold.
    """
    if not treatment.remove_signatures:
        return fold.train
    held_out = flow_signatures[ds.family.astype(str) == fold.held_out]
    is_attack = ds.family[fold.train].astype(str) != BENIGN
    return fold.train[~(is_attack & np.isin(flow_signatures[fold.train], held_out))]


@dataclass
class RawRows:
    """Rows as published, before cleaning: one entry per distinct flow and family, with its count."""

    X: pd.DataFrame
    family: np.ndarray
    flow: np.ndarray
    count: np.ndarray
    conflicting: np.ndarray
    indicators: pd.DataFrame | None = None
    suspect: np.ndarray | None = None


def build_raw_rows(raw: Dataset) -> RawRows:
    keys = pd.DataFrame(
        {"flow": pd.util.hash_pandas_object(raw.X, index=False).to_numpy(), "family": raw.family.astype(str)}
    )
    groups = keys.reset_index().groupby(["flow", "family"], sort=False)["index"].agg(["first", "size"]).reset_index()
    conflicting = groups.groupby("flow")["family"].transform("nunique").to_numpy() > 1
    return RawRows(
        raw.X.iloc[groups["first"].to_numpy()].reset_index(drop=True),
        groups["family"].to_numpy(dtype=object),
        groups["flow"].to_numpy(),
        groups["size"].to_numpy(),
        conflicting,
    )


def evaluate_raw(
    model: RandomForestBaseline,
    rows: RawRows,
    target_fpr: float,
    attack_scores: np.ndarray,
    benign_scores: np.ndarray,
    attack: np.ndarray,
    benign: np.ndarray,
) -> dict[str, float]:
    """Score traffic with its repeats restored, using the threshold from cleaned validation rows.

    Every row of the held-out family is unseen. Benign rows are copies of cleaned test rows,
    plus rows that cleaning removed for matching another family, which no model trained on.
    """
    threshold = threshold_at_fpr(model.val_benign_scores, target_fpr)
    attack_count, benign_count = rows.count[attack], rows.count[benign]
    oracle = threshold_at_fpr(np.repeat(benign_scores, benign_count), target_fpr)
    conflict = rows.conflicting[attack]
    caught = attack_scores > threshold
    return {
        "raw_recall": float(attack_count[caught].sum() / attack_count.sum()),
        "raw_fpr": float(benign_count[benign_scores > threshold].sum() / benign_count.sum()),
        "raw_recall_at_oracle_fpr": float(attack_count[attack_scores > oracle].sum() / attack_count.sum()),
        "raw_distinct_recall": float(caught.mean()),
        "raw_attack_rows": int(attack_count.sum()),
        "raw_benign_rows": int(benign_count.sum()),
        "raw_conflicting_share": float(attack_count[conflict].sum() / attack_count.sum()),
    }


def without_suspect_benign(fold: Fold, suspect: np.ndarray) -> Fold:
    """Remove the suspect rows from every part of a fold. Attack rows are unaffected."""
    return Fold(
        fold.name, fold.train[~suspect[fold.train]], fold.val[~suspect[fold.val]],
        fold.test[~suspect[fold.test]], fold.held_out,
    )


def _rows_hash(*parts: np.ndarray) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(np.asarray(part, dtype=np.int64).tobytes())
    return digest.hexdigest()[:16]


def _fold_rows(
    ds: Dataset,
    treatment: Treatment,
    fold: Fold,
    seed: int,
    config: BaselineConfig,
    flow_signatures: np.ndarray,
    indicators: pd.DataFrame,
    raw_rows: RawRows,
    flows: np.ndarray,
    suspect: np.ndarray | None = None,
) -> list[dict]:
    full_train_rows = len(fold.train)
    if treatment.exclude_suspect:
        fold = without_suspect_benign(fold, suspect)
    train = training_rows(fold, ds, treatment, flow_signatures)
    val_benign = fold.val[ds.family[fold.val].astype(str) == BENIGN]
    train_frame = treated_features(ds, treatment, train, indicators)
    categorical = [c for c in ds.categorical if c in train_frame.columns] if not treatment.missingness_only else []
    numeric = [c for c in train_frame.columns if c not in categorical]
    start = time.perf_counter()
    model = RandomForestBaseline(config.rf, seed).fit(
        train_frame, ds.y[train], treated_features(ds, treatment, val_benign, indicators), numeric, categorical
    )
    fit_seconds = time.perf_counter() - start

    scores = model.scores(treated_features(ds, treatment, fold.test, indicators))
    y = (ds.family[fold.test].astype(str) != BENIGN).astype(np.int8)
    attack_rows = fold.test[y == 1]
    attack_rows_train = train[ds.family[train].astype(str) != BENIGN]
    matched = np.isin(flow_signatures[attack_rows], flow_signatures[attack_rows_train])

    attack = raw_rows.family.astype(str) == fold.held_out
    test_benign = flows[fold.test[y == 0]]
    benign = (raw_rows.family.astype(str) == BENIGN) & (raw_rows.conflicting | np.isin(raw_rows.flow, test_benign))
    if treatment.exclude_suspect:
        benign &= ~raw_rows.suspect
    attack_scores = model.scores(treat_frame(raw_rows.X[attack], treatment, raw_rows.indicators[attack]))
    benign_scores = model.scores(treat_frame(raw_rows.X[benign], treatment, raw_rows.indicators[benign]))
    rows_tested = {
        "attack_rows_hash": _rows_hash(attack_rows, np.flatnonzero(attack)),
        "benign_rows_hash": _rows_hash(fold.test[y == 0], np.flatnonzero(benign)),
    }

    rows = []
    for target_fpr in config.target_fprs:
        threshold = threshold_at_fpr(model.val_benign_scores, target_fpr)
        caught = scores[y == 1] > threshold
        row = {
            "dataset": ds.name,
            "seed": seed,
            "treatment": treatment.name,
            "family": fold.held_out,
            "target_fpr": target_fpr,
            "train_rows": len(train),
            "train_rows_removed": full_train_rows - len(train),
            "n_attack": int(y.sum()),
            "n_benign": int((y == 0).sum()),
            "fit_seconds": fit_seconds,
            "auc": float(roc_auc_score(y, scores)),
            "signature_matched_rows": int(matched.sum()),
            "recall_signature_matched": float(caught[matched].mean()) if matched.any() else float("nan"),
            "recall_signature_unmatched": float(caught[~matched].mean()) if (~matched).any() else float("nan"),
            **evaluate_scores(y, scores, threshold, target_fpr, config.attack_prevalences),
            **evaluate_raw(model, raw_rows, target_fpr, attack_scores, benign_scores, attack, benign),
            **rows_tested,
        }
        rows.append(row)
    return rows


def meets_shortcut_rule(mean_drop: float, ci_low: float) -> bool:
    """Recall fell by at least the minimum, and the interval excludes zero on the side of a decrease."""
    return bool(mean_drop >= SHORTCUT_MIN_DROP and ci_low > 0)


def _treatment_role(treatment: str) -> str:
    if treatment in RULE_TREATMENTS:
        return "rule"
    return "label_sensitivity" if treatment == LABEL_SENSITIVITY else "diagnostic"


def _check_identical_rows(merged: pd.DataFrame, treatment: str) -> None:
    """Refuse a comparison made on different rows. Only the label sensitivity run changes benign rows."""
    columns = ["attack_rows_hash"] if treatment == LABEL_SENSITIVITY else ["attack_rows_hash", "benign_rows_hash"]
    for column in columns:
        if (merged[f"{column}_reference"] != merged[f"{column}_treated"]).any():
            raise ValueError(f"{treatment} was not evaluated on the reference rows ({column})")


def summarize_treatments(results: pd.DataFrame, samples: int, primary_fpr: float) -> pd.DataFrame:
    """Compare each treatment with the reference on the same seeds, families and held-out rows.

    ``mean_diff`` is the mean per-seed drop in raw-row recall (reference minus treated), so a
    positive value is recall lost, and ``ci_low`` and ``ci_high`` are its 95% interval. The
    ``dedup_`` columns repeat this on deduplicated rows, as a secondary sensitivity analysis.
    The rule cannot fire where reference recall is under the minimum drop, so
    ``rule_testable`` separates those families from ones that passed.
    """
    keys = ["dataset", "family", "target_fpr"]
    reference = results[results["treatment"] == REFERENCE]
    summary = []
    for treatment, part in results[results["treatment"] != REFERENCE].groupby("treatment"):
        merged = reference.merge(part, on=[*keys, "seed"], suffixes=("_reference", "_treated"))
        _check_identical_rows(merged, treatment)
        role = _treatment_role(treatment)
        for key, group in merged.groupby(keys, sort=True):
            row = {**dict(zip(keys, key)), "treatment": treatment, "role": role}
            for metric in ("raw_recall", "recall", "auc"):
                row[f"{metric}_reference"] = float(group[f"{metric}_reference"].mean())
                row[f"{metric}_treated"] = float(group[f"{metric}_treated"].mean())
            row.update(
                paired_comparison(
                    group["raw_recall_reference"].to_numpy(), group["raw_recall_treated"].to_numpy(), samples=samples
                )
            )
            secondary = paired_comparison(
                group["recall_reference"].to_numpy(), group["recall_treated"].to_numpy(), samples=samples
            )
            row.update({f"dedup_{name}": secondary[name] for name in ("mean_diff", "ci_low", "ci_high")})
            applies = role == "rule" and bool(np.isclose(key[2], primary_fpr))
            row["rule_testable"] = row["raw_recall_reference"] >= SHORTCUT_MIN_DROP
            row["shortcut_dependent"] = applies and meets_shortcut_rule(row["mean_diff"], row["ci_low"])
            row["dedup_shortcut_dependent"] = applies and meets_shortcut_rule(
                row["dedup_mean_diff"], row["dedup_ci_low"]
            )
            summary.append(row)
    return pd.DataFrame(summary)


def rule_report(effects: pd.DataFrame, primary_fpr: float) -> dict:
    """State the rule and disclose how many comparisons it was applied to."""
    primary = effects[np.isclose(effects["target_fpr"], primary_fpr)]
    rule = primary[primary["role"] == "rule"]
    return {
        "evaluation_role": EVALUATION_ROLE,
        "primary_metric": "raw_recall",
        "secondary_metric": "recall on deduplicated rows",
        "primary_target_fpr": primary_fpr,
        "min_recall_drop": SHORTCUT_MIN_DROP,
        "interval": "95% percentile bootstrap of the mean paired per-seed drop; lower bound above zero",
        "multiple_comparison_correction": "none",
        "n_comparisons": int(len(rule)),
        "n_comparisons_by_dataset": {str(k): int(v) for k, v in rule["dataset"].value_counts().sort_index().items()},
        "n_comparisons_by_treatment": {str(k): int(v) for k, v in rule["treatment"].value_counts().sort_index().items()},
        "n_not_testable": int((~rule["rule_testable"]).sum()),
        "n_shortcut_dependent": int(rule["shortcut_dependent"].sum()),
        "n_shortcut_dependent_dedup": int(rule["dedup_shortcut_dependent"].sum()),
        "treatments_outside_the_rule": sorted(set(primary["treatment"]) - set(rule["treatment"])),
    }


def run(
    config: BaselineConfig,
    out: str | Path,
    extra_manifest: dict | None = None,
    log: Callable[[str], None] = print,
) -> pd.DataFrame:
    """Run or continue the artifact experiments, then write the combined result files."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    prepared = []
    suspects: dict[str, np.ndarray | None] = {}
    suspect_counts = {}
    for dataset_config in config.datasets:
        raw = load_dataset(dataset_config)
        raw_rows = build_raw_rows(raw)
        clean, stats = remove_duplicates(raw)
        del raw
        gc.collect()
        raw_rows.indicators = missingness_frame(
            Dataset(clean.name, raw_rows.X, raw_rows.family, clean.categorical)
        ).reindex(columns=missingness_frame(clean).columns, fill_value=0.0)
        suspect = suspect_benign_mask(clean)
        suspects[clean.name] = suspect
        if suspect is not None:
            flows = pd.util.hash_pandas_object(clean.X, index=False).to_numpy()
            raw_rows.suspect = (raw_rows.family.astype(str) == BENIGN) & np.isin(raw_rows.flow, flows[suspect])
            suspect_counts[clean.name] = {
                "cleaned_rows": int(suspect.sum()), "raw_rows": int(raw_rows.count[raw_rows.suspect].sum()),
            }
            del flows
        prepared.append((clean, stats, raw_rows))

    datasets = [p[0] for p in prepared]
    plans = {ds.name: treatments_for(ds, suspects[ds.name] is not None) for ds in datasets}
    extra = {
        "experiment": "artifact_resistance",
        "evaluation_role": EVALUATION_ROLE,
        "suspect_benign_excluded_in_sensitivity_only": suspect_counts,
        "treatments": {name: [t.name for t in plan] for name, plan in plans.items()},
        **(extra_manifest or {}),
    }
    _write_manifest(out, config, datasets, {p[0].name: p[1] for p in prepared}, extra, log)
    store = FoldStore(out / "folds")
    total = sum(
        len(plans[ds.name]) * len(eligible_families(ds.family, config.min_family_count)) for ds in datasets
    ) * len(config.seeds)
    progress = Progress(total, log)

    for seed in config.seeds:
        for ds, _, raw_rows in prepared:
            flow_signatures = signatures(ds)
            flows = pd.util.hash_pandas_object(ds.X, index=False).to_numpy()
            indicators = missingness_frame(ds)
            partition = make_partition(ds.family, seed, config.val_fraction, config.test_fraction)
            for family in eligible_families(ds.family, config.min_family_count):
                fold = holdout_fold(partition, ds.family, family, config.max_train_per_family, seed)
                for treatment in plans[ds.name]:
                    label = f"{treatment.name}:{family}"
                    if store.done(ds.name, seed, label):
                        progress.skip()
                        continue
                    started = time.perf_counter()
                    rows = _fold_rows(ds, treatment, fold, seed, config, flow_signatures, indicators, raw_rows, flows, suspects[ds.name])
                    store.save(ds.name, seed, label, rows)
                    progress.update(f"seed {seed} {ds.name} {label}", time.perf_counter() - started)
                    gc.collect()

    results = store.load_all()
    results = results[results["seed"].isin(config.seeds)].sort_values(ROW_KEYS).reset_index(drop=True)
    results.to_csv(out / "results.csv", index=False)
    primary_fpr = config.target_fprs[0]
    effects = summarize_treatments(results, config.bootstrap_samples, primary_fpr)
    effects.to_csv(out / "treatment_effects.csv", index=False)
    (out / "shortcut_rule.json").write_text(json.dumps(rule_report(effects, primary_fpr), indent=2), encoding="utf-8")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    run(load_config(args.config), args.out)
    print(f"Results written to {args.out}")


if __name__ == "__main__":
    main()
