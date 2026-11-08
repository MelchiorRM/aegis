"""Nested selection: choose among candidate scores without access to the outer test rows.

    python -m aegis.experiments.selection --config configs/baseline.yaml --out results/selection_check

For an outer held-out family F, candidates are compared on inner folds built only from the
partition's training and validation rows. Each inner fold also holds out a second eligible family G:
it trains on training rows outside F and G, sets thresholds on one half of the validation benign
rows, and measures recall on G's validation rows against the other half. The outer test rows are
never passed in. The inner fold for (F, G) trains on the same rows as (G, F), so each unordered pair
is fitted once and scored for both directions.

The selection rule is fixed in advance, at the primary target FPR. The first listed candidate is the
default. A challenger replaces it only if its mean inner recall is higher and it has strictly higher
recall than the default on a strict majority of inner families; ties on a family count as no win.
Among challengers that pass, the highest mean wins, ties going to the one listed first. The majority
requirement was added on 2026-11-08 after the Config A re-check, where single large inner wins carried
challengers that then scored lower on test.
"""

from __future__ import annotations

import argparse
import itertools
import time
from pathlib import Path
from typing import Callable, Sequence

import numpy as np
import pandas as pd

from aegis.config import BaselineConfig, load_config
from aegis.data.dataset import BENIGN, Dataset
from aegis.data.splits import cap_per_family, eligible_families, make_partition
from aegis.evaluation.metrics import threshold_at_fpr
from aegis.experiments.baseline import FoldStore, Progress, _write_manifest, prepare_datasets
from aegis.models.baseline import RandomForestBaseline, RFAEBaseline

CONFIG_A_CANDIDATES = ("rf", "ae", "fused")

# Fits candidates on the given training rows and returns a function that scores rows by
# candidate, plus each candidate's scores on the threshold benign rows.
Fitter = Callable[[Dataset, np.ndarray, np.ndarray, BaselineConfig, int], tuple[Callable, dict]]


def fit_config_a(ds: Dataset, train: np.ndarray, threshold_benign: np.ndarray, config: BaselineConfig, seed: int):
    model = RFAEBaseline(config.rf, config.autoencoder, seed).fit(
        ds.X.iloc[train], ds.y[train], ds.X.iloc[threshold_benign], np.zeros(len(threshold_benign), dtype=np.int8),
        list(ds.numeric), list(ds.categorical),
    )
    return (lambda rows: model.scores(ds.X.iloc[rows])), model.val_benign_scores


def fit_rf_only(ds: Dataset, train: np.ndarray, threshold_benign: np.ndarray, config: BaselineConfig, seed: int):
    model = RandomForestBaseline(config.rf, seed).fit(
        ds.X.iloc[train], ds.y[train], ds.X.iloc[threshold_benign], list(ds.numeric), list(ds.categorical)
    )
    return (lambda rows: {"rf": model.scores(ds.X.iloc[rows])}), {"rf": model.val_benign_scores}


def benign_halves(val: np.ndarray, family: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Split validation benign rows into a threshold half and an evaluation half."""
    benign = val[family[val].astype(str) == BENIGN]
    shuffled = np.random.default_rng(seed).permutation(benign)
    half = len(shuffled) // 2
    return np.sort(shuffled[:half]), np.sort(shuffled[half:])


def pair_rows(
    pair: tuple[str, str],
    train: np.ndarray,
    val: np.ndarray,
    ds: Dataset,
    config: BaselineConfig,
    seed: int,
    fit: Fitter,
    candidates: Sequence[str],
) -> list[dict]:
    """Fit once without both families, then score each as the other's inner held-out family."""
    labels = ds.family.astype(str)
    kept = train[~np.isin(labels[train], pair)]
    kept = cap_per_family(kept, ds.family, config.max_train_per_family, seed)
    threshold_benign, eval_benign = benign_halves(val, ds.family, seed)
    if not (labels[kept] != BENIGN).any():
        # No attack family is left to train on, so this pair gives no evidence either way.
        return [{
            "dataset": ds.name, "seed": seed, "outer_family": outer, "inner_family": inner, "candidate": candidate,
            "target_fpr": target_fpr, "inner_recall": np.nan, "inner_fpr": np.nan, "n_inner_attack": 0,
            "train_rows": int(len(kept)), "skipped": "no attack rows left in training",
        } for outer, inner in (pair, pair[::-1]) for candidate in candidates for target_fpr in config.target_fprs]
    score, benign_scores = fit(ds, kept, threshold_benign, config, seed)
    eval_scores = score(eval_benign)
    rows = []
    for outer, inner in (pair, pair[::-1]):
        inner_rows = val[labels[val] == inner]
        inner_scores = score(inner_rows)
        for candidate in candidates:
            for target_fpr in config.target_fprs:
                threshold = threshold_at_fpr(benign_scores[candidate], target_fpr)
                rows.append({
                    "dataset": ds.name, "seed": seed, "outer_family": outer, "inner_family": inner,
                    "candidate": candidate, "target_fpr": target_fpr,
                    "inner_recall": float((inner_scores[candidate] > threshold).mean()) if len(inner_rows) else np.nan,
                    "inner_fpr": float((eval_scores[candidate] > threshold).mean()),
                    "n_inner_attack": int(len(inner_rows)), "train_rows": int(len(kept)), "skipped": "",
                })
    return rows


def select(rows: pd.DataFrame, primary_fpr: float, candidates: Sequence[str]) -> pd.DataFrame:
    """Apply the fixed rule per dataset, seed and outer family."""
    primary = rows[np.isclose(rows["target_fpr"], primary_fpr)].dropna(subset=["inner_recall"])
    keys = ["dataset", "seed", "outer_family"]
    every = rows[np.isclose(rows["target_fpr"], primary_fpr)].groupby(keys).size().index
    recall = primary.pivot_table(index=keys + ["inner_family"], columns="candidate", values="inner_recall")
    present = [c for c in candidates if c in recall.columns]
    recall = recall.reindex(columns=present)
    means = recall.groupby(level=keys).mean().reindex(every)
    default, challengers = candidates[0], [c for c in present if c != candidates[0]]
    wins, families = {}, {}
    for c in challengers:
        both = recall[[default, c]].dropna() if default in present else recall[[c]].iloc[0:0]
        wins[c] = (both[c] > both[default]).groupby(level=keys).sum().reindex(every, fill_value=0)
        families[c] = both.groupby(level=keys).size().reindex(every, fill_value=0)
    selected = []
    for key in every:
        if means.loc[key].isna().all():
            selected.append("none")  # No inner result at all: nothing is selected, not the default.
            continue
        base = means.loc[key].get(default, np.nan)
        passing = [c for c in challengers if base == base and means.loc[key, c] > base
                   and wins[c][key] * 2 > families[c][key]]
        selected.append(max(passing, key=lambda c: (means.loc[key, c], -challengers.index(c))) if passing else default)
    out = means.add_prefix("mean_inner_recall_").reset_index()
    out.columns.name = None
    for c in challengers:
        out[f"inner_wins_{c}"] = wins[c].to_numpy()
    out["selected"] = selected
    out["n_inner_families"] = primary.groupby(keys)["inner_family"].nunique().reindex(every, fill_value=0).to_numpy()
    return out


def nested_rows(
    ds: Dataset,
    train: np.ndarray,
    val: np.ndarray,
    config: BaselineConfig,
    seed: int,
    fit: Fitter = fit_config_a,
    candidates: Sequence[str] = CONFIG_A_CANDIDATES,
    store: FoldStore | None = None,
    progress: Progress | None = None,
) -> list[dict]:
    """All inner results for one partition. Only training and validation rows are accepted."""
    families = eligible_families(ds.family, config.min_family_count)
    rows = []
    for pair in itertools.combinations(families, 2):
        label = f"pair:{pair[0]}+{pair[1]}"
        if store is not None and store.done(ds.name, seed, label):
            if progress:
                progress.skip()
            continue
        started = time.perf_counter()
        found = pair_rows(pair, train, val, ds, config, seed, fit, candidates)
        if store is not None:
            store.save(ds.name, seed, label, found)
        if progress:
            progress.update(f"seed {seed} {ds.name} {label}", time.perf_counter() - started)
        rows.extend(found)
    return rows


def run(
    config: BaselineConfig,
    out: str | Path,
    fit: Fitter = fit_config_a,
    candidates: Sequence[str] = CONFIG_A_CANDIDATES,
    extra_manifest: dict | None = None,
    log: Callable[[str], None] = print,
) -> pd.DataFrame:
    """Run or continue nested selection, then write the inner results and the selections."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    datasets, cleaning = prepare_datasets(config)
    extra = {"experiment": "nested_selection", "candidates": list(candidates), **(extra_manifest or {})}
    _write_manifest(out, config, datasets, cleaning, extra, log)
    store = FoldStore(out / "folds")
    pairs = sum(len(list(itertools.combinations(eligible_families(d.family, config.min_family_count), 2))) for d in datasets)
    progress = Progress(pairs * len(config.seeds), log)
    for seed in config.seeds:
        for ds in datasets:
            partition = make_partition(ds.family, seed, config.val_fraction, config.test_fraction)
            # The test rows stay here; nested_rows never receives them.
            nested_rows(ds, partition.train, partition.val, config, seed, fit, candidates, store, progress)
    rows = store.load_all()
    rows = rows[rows["seed"].isin(config.seeds)].reset_index(drop=True)
    rows.to_csv(out / "inner_results.csv", index=False)
    selected = select(rows, config.target_fprs[0], candidates)
    selected.to_csv(out / "selections.csv", index=False)
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    selected = run(load_config(args.config), args.out)
    print(selected["selected"].value_counts().to_string())


if __name__ == "__main__":
    main()
