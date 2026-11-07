"""Train/validation/test partitions and the folds built from them.

Each seed makes one partition. The seen fold and every held-out fold reuse its test
rows, so the seen-versus-unseen recall of a family is compared on identical flows.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from aegis.data.dataset import BENIGN


@dataclass(frozen=True)
class Partition:
    train: np.ndarray
    val: np.ndarray
    test: np.ndarray


@dataclass(frozen=True)
class Fold:
    name: str
    train: np.ndarray
    val: np.ndarray
    test: np.ndarray
    held_out: str | None = None


def make_partition(
    family: np.ndarray, seed: int, val_fraction: float = 0.2, test_fraction: float = 0.2
) -> Partition:
    """Split within each family so that every family keeps its share of each part."""
    if val_fraction <= 0 or test_fraction <= 0 or val_fraction + test_fraction >= 1:
        raise ValueError("val_fraction and test_fraction must be positive and sum to less than 1")
    rng = np.random.default_rng(seed)
    labels = family.astype(str)
    train, val, test = [], [], []
    for name in np.unique(labels):
        rows = rng.permutation(np.flatnonzero(labels == name))
        n_test = int(round(len(rows) * test_fraction))
        n_val = int(round(len(rows) * val_fraction))
        test.append(rows[:n_test])
        val.append(rows[n_test : n_test + n_val])
        train.append(rows[n_test + n_val :])
    return Partition(*(np.sort(np.concatenate(part)) for part in (train, val, test)))


def eligible_families(family: np.ndarray, min_count: int) -> list[str]:
    """Attack families with enough rows for a held-out result to mean something."""
    names, counts = np.unique(family.astype(str), return_counts=True)
    return [str(n) for n, c in zip(names, counts) if n != BENIGN and c >= min_count]


def cap_per_family(
    rows: np.ndarray, family: np.ndarray, cap: int | None, seed: int
) -> np.ndarray:
    """Limit each family's rows to keep training within memory. Applied to training rows only."""
    if cap is None:
        return rows
    rng = np.random.default_rng(seed)
    labels = family[rows].astype(str)
    kept = []
    for name in np.unique(labels):
        members = rows[labels == name]
        kept.append(rng.choice(members, size=cap, replace=False) if len(members) > cap else members)
    return np.sort(np.concatenate(kept))


def seen_fold(
    partition: Partition, family: np.ndarray, cap: int | None, seed: int
) -> Fold:
    """Train on every family, which gives each family's recall when it is known."""
    train = cap_per_family(partition.train, family, cap, seed)
    return Fold("seen", train, partition.val, partition.test)


def holdout_fold(
    partition: Partition, family: np.ndarray, held_out: str, cap: int | None, seed: int
) -> Fold:
    """Remove one family from training and validation; test on it and benign traffic."""
    labels = family.astype(str)
    train = partition.train[labels[partition.train] != held_out]
    val = partition.val[labels[partition.val] != held_out]
    tested = np.isin(labels[partition.test], [BENIGN, held_out])
    return Fold(
        f"holdout:{held_out}",
        cap_per_family(train, family, cap, seed),
        val,
        partition.test[tested],
        held_out,
    )
