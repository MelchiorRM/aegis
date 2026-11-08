"""Loader for the improved CICIDS2017 release (Liu, Engelen et al., IEEE CNS 2022).

The release re-extracts the CICIDS2017 PCAPs with a fixed CICFlowMeter and relabels the flows. It
ships one CSV per day (``monday.csv`` to ``friday.csv``) with a ``Label`` column and an
``Attempted Category`` column: -1 for flows that are not "Attempted", 0-6 for the reason an attack
flow carried no malicious behaviour. Schema and labels follow the published labelling code
(github.com/GintsEngelen/CNS2022_Code, ``CICIDS2017_labelling_fixed_CICFlowMeter.ipynb``); they have
not yet been checked against the downloaded files.

"Attempted" flows are excluded, before duplicate removal and splitting, so they are never trained on
and are absent from the primary metrics. That is the primary handling decided for Aegis on
2026-11-08, following the authors' advice never to treat them as a class of their own. The
secondary handling counts them as benign test traffic: ``load_with_attempted`` returns them apart,
with the same feature columns, and the Config A runner scores them in every fold.

Unknown labels, an inconsistent ``Attempted Category`` or differing columns between files raise an
error, so a different release cannot be misread.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from aegis.data.dataset import BENIGN, Dataset

NAME = "cicids2017_improved"
DAY_FILES = ("monday.csv", "tuesday.csv", "wednesday.csv", "thursday.csv", "friday.csv")
ATTEMPTED_SUFFIX = " - attempted"
ATTEMPTED_COLUMN = "Attempted Category"

# As in the original release, DDoS is grouped with DoS so that holding out "dos" removes both.
# "Infiltration - Portscan" is the NMAP scan run from the infected victim. It is grouped with portscan,
# for the same reason: if it stayed in training, a held-out portscan family would not be unseen.
FAMILIES = {
    "benign": BENIGN,
    "botnet": "bot",
    "ddos": "dos",
    "dos goldeneye": "dos",
    "dos hulk": "dos",
    "dos slowhttptest": "dos",
    "dos slowloris": "dos",
    "ftp-patator": "brute_force",
    "ssh-patator": "brute_force",
    "heartbleed": "heartbleed",
    "infiltration": "infiltration",
    "infiltration - portscan": "portscan",
    "portscan": "portscan",
    "web attack - brute force": "web_attack",
    "web attack - sql injection": "web_attack",
    "web attack - xss": "web_attack",
}
# Columns that identify a host, a time or a row rather than behavior. ``id`` appears only if the
# labelling script was run with its row-number option.
IDENTIFIERS = ("id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp")


def day_files(directory: str | Path) -> list[Path]:
    directory = Path(directory)
    missing = [name for name in DAY_FILES if not (directory / name).exists()]
    if missing:
        raise FileNotFoundError(f"{directory} is missing improved CICIDS2017 files {missing}. See README.md.")
    return [directory / name for name in DAY_FILES]


def parse_labels(label: pd.Series, category: pd.Series, source: str = "") -> tuple[np.ndarray, np.ndarray]:
    """Return each row's family and whether it is an "Attempted" flow; raise on anything unexpected."""
    text = label.astype(str).str.strip().str.lower()
    attempted = text.str.endswith(ATTEMPTED_SUFFIX).to_numpy()
    base = text.str.removesuffix(ATTEMPTED_SUFFIX)
    unknown = sorted(set(base) - set(FAMILIES))
    if unknown:
        raise ValueError(f"Unknown improved CICIDS2017 labels in {source}: {unknown}")
    code = pd.to_numeric(category, errors="coerce").to_numpy()
    if np.isnan(code).any():
        raise ValueError(f"{source}: unparseable {ATTEMPTED_COLUMN} values")
    if np.any(attempted & ~np.isin(code, np.arange(7))) or np.any(~attempted & (code != -1)):
        raise ValueError(f"{source}: {ATTEMPTED_COLUMN} disagrees with the Attempted labels")
    if np.any(attempted & (base == "benign").to_numpy()):
        raise ValueError(f"{source}: a benign flow is marked Attempted")
    return base.map(FAMILIES).to_numpy(dtype=object), attempted


def _read(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, encoding="latin-1", low_memory=False)
    frame.columns = frame.columns.str.strip()
    missing = {"Label", ATTEMPTED_COLUMN} - set(frame.columns)
    if missing:
        raise ValueError(f"{path} is missing columns {sorted(missing)}; is this the improved release?")
    return frame.dropna(subset=["Label"])


def label_counts(directory: str | Path) -> pd.DataFrame:
    """Rows per file, label and Attempted Category, before anything is excluded. For the data check."""
    counts = []
    for path in day_files(directory):
        frame = _read(path)
        parse_labels(frame["Label"], frame[ATTEMPTED_COLUMN], path.name)
        grouped = frame.groupby(["Label", ATTEMPTED_COLUMN]).size().rename("rows").reset_index()
        counts.append(grouped.assign(file=path.name))
    return pd.concat(counts, ignore_index=True)[["file", "Label", ATTEMPTED_COLUMN, "rows"]]


@dataclass
class AttemptedRows:
    """The "Attempted" flows, kept apart: features as in the primary Dataset, their Attempted
    Category (0-6) and the family their label names. They are benign in the secondary metric."""

    X: pd.DataFrame
    category: np.ndarray
    family: np.ndarray

    def __post_init__(self) -> None:
        self.X = self.X.reset_index(drop=True)
        self.category = np.asarray(self.category, dtype=np.int8)
        self.family = np.asarray(self.family, dtype=object)
        if not len(self.X) == len(self.category) == len(self.family):
            raise ValueError("Attempted rows: features, categories and families differ in length")

    def __len__(self) -> int:
        return len(self.X)


@dataclass
class DatasetWithAttempted(Dataset):
    """A Dataset carrying its excluded "Attempted" flows, for the secondary metric only."""

    attempted: AttemptedRows | None = None


def load_with_attempted(directory: str | Path, drop_columns: Iterable[str] = ()) -> tuple[Dataset, AttemptedRows]:
    """Read the five day files once; return the primary Dataset and, apart, the "Attempted" flows.

    Both get the same parsing and column drops, so the model can score either.
    """
    from aegis.data.loaders import _to_float32  # The same numeric parsing as the original release.

    drop = set(IDENTIFIERS) | set(drop_columns)
    features, families, attempted_features, attempted_families, categories = [], [], [], [], []
    for path in day_files(directory):
        frame = _read(path)
        absent = sorted(set(drop_columns) - set(frame.columns))
        if absent:  # A misspelt drop would silently keep a feature.
            raise ValueError(f"{path.name} has no columns {absent} to drop")
        family, attempted = parse_labels(frame["Label"], frame[ATTEMPTED_COLUMN], path.name)
        code = pd.to_numeric(frame[ATTEMPTED_COLUMN]).to_numpy()
        parsed = _to_float32(frame.drop(columns=["Label", ATTEMPTED_COLUMN, *(drop & set(frame.columns))]))
        del frame
        features.append(parsed.loc[~attempted])
        families.append(family[~attempted])
        attempted_features.append(parsed.loc[attempted])
        attempted_families.append(family[attempted])
        categories.append(code[attempted])
    if any(list(f.columns) != list(features[0].columns) for f in features):
        raise ValueError("Improved CICIDS2017 files do not share the same columns")
    primary = Dataset(NAME, pd.concat(features, ignore_index=True), np.concatenate(families))
    del features
    rows = AttemptedRows(
        pd.concat(attempted_features, ignore_index=True),
        np.concatenate(categories),
        np.concatenate(attempted_families),
    )
    return primary, rows


def load_cicids2017_improved(directory: str | Path, drop_columns: Iterable[str] = ()) -> Dataset:
    """Load the five day files, excluding "Attempted" flows."""
    return load_with_attempted(directory, drop_columns)[0]


def load_attempted(directory: str | Path, drop_columns: Iterable[str] = ()) -> AttemptedRows:
    """Only the "Attempted" flows, parsed exactly as ``load_cicids2017_improved`` parses the rest."""
    return load_with_attempted(directory, drop_columns)[1]


def remove_repeated_attempted(rows: AttemptedRows) -> tuple[AttemptedRows, dict[str, int]]:
    """Count each attempted feature vector once, as ``remove_duplicates`` does for the primary rows.

    Repeats with differing categories or families are dropped too (the first is kept): all are
    benign in the secondary metric, so no label conflict arises among them. Attempted rows that
    copy a training row are kept and counted per fold by the runner instead.
    """
    keep = ~pd.util.hash_pandas_object(rows.X, index=False).duplicated().to_numpy()
    stats = {"attempted_rows_before": int(len(rows)), "attempted_rows_after": int(keep.sum())}
    return AttemptedRows(rows.X.loc[keep], rows.category[keep], rows.family[keep]), stats
