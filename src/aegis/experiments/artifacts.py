"""Artifact-resistant evaluation: does held-out recall survive the removal of dataset shortcuts?

    python -m aegis.experiments.artifacts --config configs/baseline.yaml --out results/config_a_artifacts

Every treatment refits the Random Forest baseline on the same folds as the reference, so
differences are paired by seed and family. No label is ever changed. Results go to their own
folder, and a finished fold is kept, so an interrupted run continues where it stopped.
"""

from __future__ import annotations

import argparse
import gc
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
from aegis.data.splits import Fold, eligible_families, holdout_fold, make_partition
from aegis.evaluation.metrics import evaluate_scores, paired_comparison, threshold_at_fpr
from aegis.experiments.baseline import FoldStore, Progress, _write_manifest
from aegis.models.baseline import RandomForestBaseline
from aegis.provenance import source_hash

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
# "-" here means no application protocol was identified. Imputing a category would invent
# one, so the column is removed.
CATEGORICAL_MARKER = "-"
CATEGORICAL_MARKER_COLUMNS = ("service",)


@dataclass(frozen=True)
class Treatment:
    name: str
    drop: tuple[str, ...] = ()
    neutralize: tuple[str, ...] = ()  # Numeric marker becomes NaN, then the training median.
    remove_signatures: bool = False
    missingness_only: bool = False


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
    return pd.DataFrame(indicators).astype(np.float32)


def treatments_for(ds: Dataset) -> list[Treatment]:
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
    plan.append(
        Treatment(
            "all_controls",
            drop=(*window, *category_markers),
            neutralize=tuple(c for c in numeric_markers if c not in window),
            remove_signatures=True,
        )
    )
    return plan


def treated_features(ds: Dataset, treatment: Treatment, rows: np.ndarray, indicators: pd.DataFrame) -> pd.DataFrame:
    if treatment.missingness_only:
        return indicators.iloc[rows]
    frame = ds.X.iloc[rows]
    if treatment.neutralize:
        frame = frame.assign(**{c: frame[c].where(frame[c] != NUMERIC_MARKER) for c in treatment.neutralize})
    return frame.drop(columns=list(treatment.drop))


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
) -> list[dict]:
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

    raw_scores = None
    if treatment.name == REFERENCE:
        attack = raw_rows.family.astype(str) == fold.held_out
        test_benign = flows[fold.test[y == 0]]
        benign = (raw_rows.family.astype(str) == BENIGN) & (raw_rows.conflicting | np.isin(raw_rows.flow, test_benign))
        raw_scores = (attack, benign, model.scores(raw_rows.X[attack]), model.scores(raw_rows.X[benign]))

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
            "train_rows_removed": len(fold.train) - len(train),
            "n_attack": int(y.sum()),
            "n_benign": int((y == 0).sum()),
            "fit_seconds": fit_seconds,
            "auc": float(roc_auc_score(y, scores)),
            "signature_matched_rows": int(matched.sum()),
            "recall_signature_matched": float(caught[matched].mean()) if matched.any() else float("nan"),
            "recall_signature_unmatched": float(caught[~matched].mean()) if (~matched).any() else float("nan"),
            **evaluate_scores(y, scores, threshold, target_fpr, config.attack_prevalences),
        }
        if raw_scores is not None:
            attack, benign, attack_scores, benign_scores = raw_scores
            row.update(
                evaluate_raw(model, raw_rows, target_fpr, attack_scores, benign_scores, attack, benign)
            )
        rows.append(row)
    return rows


def summarize_treatments(results: pd.DataFrame, samples: int) -> pd.DataFrame:
    """Compare each treatment with the reference on the same seeds and families.

    ``mean_diff`` is reference minus treated recall, so a positive value is recall lost.
    """
    metrics = ("recall", "auc")
    keys = ["dataset", "family", "target_fpr"]
    reference = results[results["treatment"] == REFERENCE]
    summary = []
    for treatment, part in results[results["treatment"] != REFERENCE].groupby("treatment"):
        merged = reference.merge(part, on=[*keys, "seed"], suffixes=("_reference", "_treated"))
        for key, group in merged.groupby(keys, sort=True):
            row = {**dict(zip(keys, key)), "treatment": treatment}
            for metric in metrics:
                row[f"{metric}_reference"] = float(group[f"{metric}_reference"].mean())
                row[f"{metric}_treated"] = float(group[f"{metric}_treated"].mean())
            row.update(
                paired_comparison(
                    group["recall_reference"].to_numpy(), group["recall_treated"].to_numpy(), samples=samples
                )
            )
            summary.append(row)
    return pd.DataFrame(summary)


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
    for dataset_config in config.datasets:
        raw = load_dataset(dataset_config)
        raw_rows = build_raw_rows(raw)
        clean, stats = remove_duplicates(raw)
        del raw
        gc.collect()
        prepared.append((clean, stats, raw_rows))

    datasets = [p[0] for p in prepared]
    plans = {ds.name: treatments_for(ds) for ds in datasets}
    extra = {
        "experiment": "artifact_resistance",
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
                    rows = _fold_rows(ds, treatment, fold, seed, config, flow_signatures, indicators, raw_rows, flows)
                    store.save(ds.name, seed, label, rows)
                    progress.update(f"seed {seed} {ds.name} {label}", time.perf_counter() - started)
                    gc.collect()

    results = store.load_all()
    results = results[results["seed"].isin(config.seeds)].sort_values(ROW_KEYS).reset_index(drop=True)
    results.to_csv(out / "results.csv", index=False)
    summarize_treatments(results, config.bootstrap_samples).to_csv(out / "treatment_effects.csv", index=False)
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
