"""Experiment configuration. Unknown YAML keys raise an error instead of being ignored."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class DatasetConfig:
    kind: str  # cicids2017, unsw_nb15 or synthetic
    path: str | None = None
    name: str | None = None
    seed: int = 0
    drop_columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class RandomForestConfig:
    n_estimators: int = 100
    max_depth: int | None = 20
    min_samples_leaf: int = 2
    n_jobs: int = 4


@dataclass(frozen=True)
class AutoencoderConfig:
    hidden: tuple[int, ...] = (64, 32)
    latent: int = 16
    epochs: int = 30
    batch_size: int = 1024
    learning_rate: float = 1e-3
    patience: int = 4
    device: str = "cpu"


@dataclass(frozen=True)
class BaselineConfig:
    datasets: tuple[DatasetConfig, ...]
    seeds: tuple[int, ...] = (0, 1, 2, 3, 4)
    cross_dataset: bool = True
    val_fraction: float = 0.2
    test_fraction: float = 0.2
    max_train_per_family: int | None = 100_000
    min_family_count: int = 200
    target_fprs: tuple[float, ...] = (0.01, 0.001)
    attack_prevalences: tuple[float, ...] = (0.01, 0.001)
    bootstrap_samples: int = 10_000
    rf: RandomForestConfig = field(default_factory=RandomForestConfig)
    autoencoder: AutoencoderConfig = field(default_factory=AutoencoderConfig)


def load_config(path: str | Path) -> BaselineConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    datasets = tuple(
        DatasetConfig(**{**d, "drop_columns": tuple(d.get("drop_columns", ()))})
        for d in raw.pop("datasets")
    )
    rf = RandomForestConfig(**raw.pop("rf", {}))
    ae_raw = raw.pop("autoencoder", {})
    if "hidden" in ae_raw:
        ae_raw["hidden"] = tuple(ae_raw["hidden"])
    autoencoder = AutoencoderConfig(**ae_raw)
    for key in ("seeds", "target_fprs", "attack_prevalences"):
        if key in raw:
            raw[key] = tuple(raw[key])
    return BaselineConfig(datasets=datasets, rf=rf, autoencoder=autoencoder, **raw)
