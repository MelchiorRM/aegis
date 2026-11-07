"""The dataset form every loader produces, plus duplicate removal."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

BENIGN = "benign"


@dataclass
class Dataset:
    """Flow features with one attack-family name per row (``BENIGN`` for normal traffic)."""

    name: str
    X: pd.DataFrame
    family: np.ndarray
    categorical: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.X = self.X.reset_index(drop=True)
        self.family = np.asarray(self.family, dtype=object)
        if len(self.X) != len(self.family):
            raise ValueError(f"{self.name}: {len(self.X)} rows but {len(self.family)} labels")

    @property
    def y(self) -> np.ndarray:
        return (self.family != BENIGN).astype(np.int8)

    @property
    def numeric(self) -> tuple[str, ...]:
        return tuple(c for c in self.X.columns if c not in self.categorical)

    def family_counts(self) -> dict[str, int]:
        names, counts = np.unique(self.family.astype(str), return_counts=True)
        return {str(n): int(c) for n, c in zip(names, counts)}


def column_report(ds: Dataset) -> pd.DataFrame:
    """Show per-column data problems, for checking a new download before training."""
    rows = []
    for column in ds.X.columns:
        values = ds.X[column]
        numeric = column not in ds.categorical
        rows.append(
            {
                "column": column,
                "missing_share": float(values.isna().mean()),
                "negative_share": float((values < 0).mean()) if numeric else 0.0,
                "constant": values.nunique(dropna=True) <= 1,
            }
        )
    return pd.DataFrame(rows)


def remove_duplicates(ds: Dataset) -> tuple[Dataset, dict[str, int]]:
    """Drop repeated rows and rows whose features appear under more than one family.

    Without this, a copy of a test flow can sit in the training set, and a flow from
    a held-out family can reach training under another label. It runs before any split
    and fits no statistics, so it cannot leak test information into a model.
    """
    keys = pd.DataFrame(
        {
            "hash": pd.util.hash_pandas_object(ds.X, index=False).to_numpy(),
            "family": ds.family.astype(str),
        }
    )
    conflicting = keys.groupby("hash")["family"].transform("nunique").to_numpy() > 1
    repeated = keys.duplicated("hash").to_numpy()
    keep = ~conflicting & ~repeated
    stats = {
        "rows_before": int(len(keys)),
        "rows_conflicting_labels": int(conflicting.sum()),
        "rows_after": int(keep.sum()),
    }
    cleaned = Dataset(ds.name, ds.X.loc[keep], ds.family[keep], ds.categorical)
    return cleaned, stats
