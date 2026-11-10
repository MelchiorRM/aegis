"""The Config B fit wrapper and the same-records invariant checks (section 7).

The wrapper fits Config A's preprocessor once, on the distinct training rows, with Config A's own
``build_preprocessor``. It then appends replays as integer copies of preprocessed rows, and fits the forest with
Config A's ``fit_forest``. So ``class_weight="balanced_subsample"`` and every other setting are unchanged, and no
``sample_weight`` is passed. Scores use Config A's fixed-order ``forest_log_odds``. Config A's code is imported,
never modified.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Sequence

import numpy as np
import pandas as pd

from aegis.config import RandomForestConfig
from aegis.data.dataset import BENIGN
from aegis.frozen import FROZEN
from aegis.models.baseline import RandomForestBaseline, build_preprocessor, fit_forest, forest_log_odds


class InvariantViolation(RuntimeError):
    """A pre-fit invariant failed. The run stops, with no correction, retry or fallback (section 7)."""


class ReplayForest:
    """Config A's Random Forest, fitted on distinct rows plus integer copies."""

    def __init__(self, rf: RandomForestConfig, seed: int) -> None:
        self.rf_config = rf
        self.seed = seed
        self.val_benign_scores = np.empty(0)

    def fit(
        self,
        X_distinct: pd.DataFrame,
        y_distinct: np.ndarray,
        copy_positions: np.ndarray,
        X_val_benign: pd.DataFrame,
        numeric: Sequence[str],
        categorical: Sequence[str] = (),
    ) -> "ReplayForest":
        """``copy_positions`` index rows of ``X_distinct``; each entry adds one copy of that row."""
        return self.preprocess(X_distinct, numeric, categorical).fit_forest(y_distinct, copy_positions, X_val_benign)

    def preprocess(self, X_distinct: pd.DataFrame, numeric: Sequence[str], categorical: Sequence[str] = ()) -> "ReplayForest":
        """Fit Config A's preprocessor on the distinct rows only, and transform them. Copies never refit it."""
        self.preprocessor = build_preprocessor(numeric, categorical).fit(X_distinct)
        self.distinct = self.preprocessor.transform(X_distinct).astype(np.float32)
        return self

    def fit_forest(self, y_distinct: np.ndarray, copy_positions: np.ndarray, X_val_benign: pd.DataFrame) -> "ReplayForest":
        if len(np.unique(y_distinct)) != 2:
            raise ValueError("Training data must contain both benign and attack rows")
        positions = np.asarray(copy_positions, dtype=np.int64)
        if len(positions):
            X = np.concatenate([self.distinct, self.distinct[positions]])
            y = np.concatenate([y_distinct, y_distinct[positions]])
        else:
            X, y = self.distinct, y_distinct
        self.n_fit_rows = len(X)
        self.forest = fit_forest(self.rf_config, self.seed, X, y)
        self.val_benign_scores = self.scores(X_val_benign)
        return self

    def scores(self, X: pd.DataFrame) -> np.ndarray:
        return forest_log_odds(self.forest, self.preprocessor.transform(X).astype(np.float32), self.rf_config.n_jobs)


def preprocessing_fingerprint(preprocessor, distinct: np.ndarray) -> str:
    """A hash of the fitted preprocessing parameters and the transformed distinct rows (invariant 3)."""
    digest = hashlib.sha256()
    digest.update(np.ascontiguousarray(distinct).tobytes())
    digest.update(str(distinct.shape).encode())
    for name, transformer, _ in preprocessor.transformers_:
        if name == "numeric":
            digest.update(np.asarray(transformer.named_steps["impute"].statistics_, dtype=np.float64).tobytes())
            digest.update(np.asarray(transformer.named_steps["scale"].mean_, dtype=np.float64).tobytes())
            digest.update(np.asarray(transformer.named_steps["scale"].scale_, dtype=np.float64).tobytes())
        elif name == "categorical":
            digest.update(repr([list(map(str, c)) for c in transformer.categories_]).encode())
            infrequent = transformer.infrequent_categories_
            digest.update(repr([None if c is None else list(map(str, c)) for c in infrequent]).encode())
    return digest.hexdigest()


class FingerprintRegistry:
    """Invariant 3 across arms and stages: one preprocessing fingerprint per training context.

    The first arm to fit a context records it. Every later arm must match it.
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.known: dict[str, str] = {}
        if path is not None and path.exists():
            self.known = json.loads(path.read_text(encoding="utf-8"))

    def check(self, context: str, fingerprint: str) -> None:
        recorded = self.known.get(context)
        if recorded is None:
            self.known[context] = fingerprint
            if self.path is not None:
                temporary = self.path.with_suffix(".tmp")
                temporary.write_text(json.dumps(self.known, indent=1, sort_keys=True), encoding="utf-8")
                temporary.replace(self.path)
        elif recorded != fingerprint:
            raise InvariantViolation(f"invariant 3: preprocessing for {context} differs between arms")


def check_replay_rows(
    *,
    arm: str,
    train: np.ndarray,
    config_a_train: np.ndarray,
    copies: np.ndarray,
    expected_total: int,
    excluded: dict[str, np.ndarray],
    flows: np.ndarray | None = None,
    test: np.ndarray | None = None,
    family: np.ndarray | None = None,
    held_out: str | None = None,
) -> np.ndarray:
    """Invariants 1, 2 and 4 for one fit. Returns the copies' positions within ``train``.

    - ``config_a_train``: the training rows Config A's own procedure yields for this fold and treatment.
    - ``excluded``: named row sets no replay may touch, for example validation, test and rows the cap left out.
    """
    train, config_a_train, copies = (np.asarray(a, dtype=np.int64) for a in (train, config_a_train, copies))
    # 1. Distinct records: identical to Config A's rows, and every replay is one of them.
    if not np.array_equal(train, config_a_train):
        raise InvariantViolation(f"invariant 1: {arm}'s distinct training rows differ from Config A's")
    if len(copies) and not np.isin(copies, train).all():
        raise InvariantViolation(f"invariant 1: {arm} replays a row outside Config A's training rows")
    # 2. Excluded rows.
    for name, rows in excluded.items():
        if len(copies) and np.isin(copies, rows).any():
            raise InvariantViolation(f"invariant 2: {arm} replays a {name} row")
    if held_out is not None and family is not None and len(copies):
        if (family[copies].astype(str) == held_out).any():
            raise InvariantViolation(f"invariant 2: {arm} replays a row of the held-out family {held_out}")
    if flows is not None and test is not None and len(copies):
        if np.isin(flows[copies], flows[np.asarray(test, dtype=np.int64)]).any():
            raise InvariantViolation(f"invariant 2: a feature vector {arm} replays appears in the test rows")
    # 4. Multiplicities.
    if arm == "A" and len(copies):
        raise InvariantViolation("invariant 4: arm A must not replay any row")
    if len(copies) != expected_total:
        raise InvariantViolation(f"invariant 4: {arm} adds {len(copies)} copies, expected {expected_total}")
    if not np.all(np.diff(train) > 0):
        raise InvariantViolation("invariant 1: training rows must be sorted and distinct")
    positions = np.searchsorted(train, copies)
    if len(copies) and not np.array_equal(train[positions], copies):
        raise InvariantViolation(f"invariant 4: {arm}'s copies do not map onto training rows")
    return positions


def check_settings(rf: RandomForestConfig, seed: int, fold_seed: int) -> None:
    """Invariant 5: the forest settings are Config A's frozen ones, and the forest seed is the fold seed."""
    frozen = FROZEN["settings"]["rf"]
    current = {k: v for k, v in dataclasses.asdict(rf).items() if k != "n_jobs"}
    if current != frozen:
        raise InvariantViolation(f"invariant 5: forest settings {current} are not Config A's {frozen}")
    if seed != fold_seed:
        raise InvariantViolation(f"invariant 5: forest seed {seed} is not the fold seed {fold_seed}")


def preprocessing_gate(
    model: ReplayForest, X_distinct: pd.DataFrame, y_distinct: np.ndarray, X_val_benign: pd.DataFrame,
    numeric: Sequence[str], categorical: Sequence[str],
) -> None:
    """Invariant 6: the wrapper's preprocessing equals Config A's ``RandomForestBaseline.fit`` path, bit for bit.

    Config A's real fit path runs on the same rows. Its forest is reduced to one shallow tree, because only its
    preprocessor is compared. That forest is never used for any score.
    """
    probe = RandomForestConfig(n_estimators=1, max_depth=1, min_samples_leaf=1, n_jobs=1)
    reference = RandomForestBaseline(probe, model.seed).fit(
        X_distinct, y_distinct, X_val_benign.iloc[:1], numeric, categorical
    )
    expected = reference.preprocessor.transform(X_distinct).astype(np.float32)
    if expected.shape != model.distinct.shape or expected.tobytes() != model.distinct.tobytes():
        raise InvariantViolation("invariant 6: preprocessing differs from Config A's RandomForestBaseline.fit path")


def attack_and_benign(family: np.ndarray, rows: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    labels = family[rows].astype(str)
    return rows[labels != BENIGN], rows[labels == BENIGN]
