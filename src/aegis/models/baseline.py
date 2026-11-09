"""Config A defender: a static Random Forest plus autoencoder.

Inspired by Agrawal et al. (2026), not a replication: the paper does not release its
preprocessing or model settings. The fusion rule below is an Aegis design choice.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np
import pandas as pd
from joblib import Parallel, delayed, effective_n_jobs
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from aegis.config import AutoencoderConfig, RandomForestConfig
from aegis.models.autoencoder import AutoencoderScorer

SCORERS = ("rf", "ae", "fused")


def signed_log1p(values: np.ndarray) -> np.ndarray:
    """Compress heavy-tailed flow counts while keeping the sign of negative values."""
    return np.sign(values) * np.log1p(np.abs(values))


def build_preprocessor(
    numeric: Sequence[str], categorical: Sequence[str]
) -> ColumnTransformer:
    numeric_steps = Pipeline(
        [
            ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("log", FunctionTransformer(signed_log1p)),
            ("scale", StandardScaler()),
        ]
    )
    categorical_steps = OneHotEncoder(
        handle_unknown="infrequent_if_exist",
        min_frequency=20,
        sparse_output=False,
        dtype=np.float32,
    )
    transformers = [("numeric", numeric_steps, list(numeric))]
    if categorical:
        transformers.append(("categorical", categorical_steps, list(categorical)))
    return ColumnTransformer(transformers, sparse_threshold=0.0)


class TailCalibrator:
    """Express a score as how rare it is among validation benign traffic.

    The result is -log10 of the share of benign scores at or above the value, so two
    scorers with very different distributions become comparable. Standardizing is not
    enough: one scorer's long benign tail can set the fused threshold above everything
    the other scorer finds. Scores beyond the benign maximum keep their order through a
    term that grows with the distance past that maximum.
    """

    def __init__(self, benign_scores: np.ndarray) -> None:
        self.sorted = np.sort(benign_scores)
        self.spread = max(float(benign_scores.std()), 1e-6)

    def __call__(self, scores: np.ndarray) -> np.ndarray:
        n = len(self.sorted)
        at_or_above = n - np.searchsorted(self.sorted, scores, side="left")
        rarity = -np.log10((at_or_above + 1) / (n + 1))
        beyond = np.maximum(scores - self.sorted[-1], 0.0) / self.spread
        return rarity + beyond


def fit_forest(config: RandomForestConfig, seed: int, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=config.n_estimators,
        max_depth=config.max_depth,
        min_samples_leaf=config.min_samples_leaf,
        n_jobs=config.n_jobs,
        class_weight="balanced_subsample",  # Used instead of SMOTE.
        random_state=seed,
    ).fit(X, y)


def forest_probability(forest: RandomForestClassifier, X: np.ndarray, n_jobs: int = 1) -> np.ndarray:
    """Attack probability, with the trees added in a fixed order so the result never depends on threads.

    ``RandomForestClassifier.predict_proba`` adds the trees' outputs from several threads in whatever
    order they finish. With more than one worker its last digits vary from call to call, and a tie
    between two scores can then break either way. Here each thread takes a block of rows and adds every
    tree in order, so the result is the same for any ``n_jobs`` and equal, bit for bit, to
    ``predict_proba`` with ``n_jobs=1``.
    """
    column = list(forest.classes_).index(1)
    X = np.ascontiguousarray(X, dtype=np.float32)  # What the trees expect, so each call skips the check.
    bounds = np.linspace(0, len(X), min(len(X), effective_n_jobs(n_jobs)) + 1).astype(int)

    def block(start: int, stop: int) -> np.ndarray:
        total = np.zeros((stop - start, forest.n_classes_))
        for tree in forest.estimators_:
            total += tree.predict_proba(X[start:stop], check_input=False)
        total /= len(forest.estimators_)
        return total[:, column]

    if len(X) == 0:
        return np.empty(0)
    parts = Parallel(n_jobs=n_jobs, prefer="threads")(
        delayed(block)(start, stop) for start, stop in zip(bounds[:-1], bounds[1:])
    )
    return np.concatenate(parts)


def forest_log_odds(forest: RandomForestClassifier, X: np.ndarray, n_jobs: int = 1) -> np.ndarray:
    probability = forest_probability(forest, X, n_jobs)
    clipped = np.clip(probability, 1e-6, 1 - 1e-6)
    return np.log(clipped / (1 - clipped))


class RandomForestBaseline:
    """The Config A baseline score: the forest alone, with no autoencoder to fit."""

    def __init__(self, rf: RandomForestConfig, seed: int) -> None:
        self.rf_config = rf
        self.seed = seed
        self.val_benign_scores = np.empty(0)

    def fit(
        self,
        X_train: pd.DataFrame,
        y_train: np.ndarray,
        X_val_benign: pd.DataFrame,
        numeric: Sequence[str],
        categorical: Sequence[str] = (),
    ) -> "RandomForestBaseline":
        if len(np.unique(y_train)) != 2:
            raise ValueError("Training data must contain both benign and attack rows")
        self.preprocessor = build_preprocessor(numeric, categorical).fit(X_train)
        train = self.preprocessor.transform(X_train).astype(np.float32)
        self.forest = fit_forest(self.rf_config, self.seed, train, y_train)
        self.val_benign_scores = self.scores(X_val_benign)
        return self

    def scores(self, X: pd.DataFrame) -> np.ndarray:
        return forest_log_odds(self.forest, self.preprocessor.transform(X).astype(np.float32), self.rf_config.n_jobs)


class RFAEBaseline:
    """Combine a supervised score with an anomaly score.

    The RF score is a log-odds value and the AE score a log error. The fused score is
    the larger of their calibrated values, so a flow can be flagged for looking like a
    known attack or for looking unusual.
    """

    def __init__(
        self, rf: RandomForestConfig, autoencoder: AutoencoderConfig, seed: int
    ) -> None:
        self.rf_config = rf
        self.ae_config = autoencoder
        self.seed = seed
        self.val_benign_scores: dict[str, np.ndarray] = {}

    def fit(
        self,
        X_train: pd.DataFrame,
        y_train: np.ndarray,
        X_val: pd.DataFrame,
        y_val: np.ndarray,
        numeric: Sequence[str],
        categorical: Sequence[str] = (),
    ) -> "RFAEBaseline":
        if len(np.unique(y_train)) != 2:
            raise ValueError("Training data must contain both benign and attack rows")

        # Every fitted statistic comes from the training rows.
        self.preprocessor = build_preprocessor(numeric, categorical).fit(X_train)
        train = self.preprocessor.transform(X_train).astype(np.float32)
        val = self.preprocessor.transform(X_val).astype(np.float32)

        self.forest = fit_forest(self.rf_config, self.seed, train, y_train)

        val_benign = val[y_val == 0]
        self.autoencoder = AutoencoderScorer(self.ae_config, self.seed).fit(
            train[y_train == 0], val_benign
        )

        rf_raw, ae_raw = self._raw_scores(val_benign)
        self._rf_calibrator = TailCalibrator(rf_raw)
        self._ae_calibrator = TailCalibrator(ae_raw)
        self.val_benign_scores = self._combine(rf_raw, ae_raw)
        return self

    def _raw_scores(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        rf = forest_log_odds(self.forest, X, self.rf_config.n_jobs)
        ae = np.log(self.autoencoder.reconstruction_error(X) + 1e-12)
        return rf, ae

    def _combine(self, rf: np.ndarray, ae: np.ndarray) -> dict[str, np.ndarray]:
        fused = np.maximum(self._rf_calibrator(rf), self._ae_calibrator(ae))
        return {"rf": rf, "ae": ae, "fused": fused}

    def scores(self, X: pd.DataFrame) -> dict[str, np.ndarray]:
        transformed = self.preprocessor.transform(X).astype(np.float32)
        return self._combine(*self._raw_scores(transformed))
