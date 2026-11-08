"""Loaders for CICIDS2017, UNSW-NB15 and (in ``improved``) the improved CICIDS2017, a shared feature view,
and generated data.

The real loaders expect the published CSV files and raise an error on labels or
columns they do not recognize, so a different dataset release cannot be misread.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from aegis.config import DatasetConfig
from aegis.data.dataset import BENIGN, Dataset

# DDoS is grouped with DoS, so holding out "dos" removes both. If DDoS stayed in training,
# DoS would not be an unseen family.
CICIDS_FAMILIES = {
    "benign": BENIGN,
    "bot": "bot",
    "ddos": "dos",
    "dos goldeneye": "dos",
    "dos hulk": "dos",
    "dos slowhttptest": "dos",
    "dos slowloris": "dos",
    "ftp-patator": "brute_force",
    "ssh-patator": "brute_force",
    "heartbleed": "heartbleed",
    "infiltration": "infiltration",
    "portscan": "portscan",
}
# Columns that identify a host, a time or a repeated field rather than behavior.
CICIDS_IDENTIFIERS = (
    "Flow ID", "Source IP", "Src IP", "Source Port", "Src Port",
    "Destination IP", "Dst IP", "Timestamp", "Fwd Header Length.1",
)

UNSW_FAMILIES = {
    "normal": BENIGN,
    "analysis": "analysis",
    "backdoor": "backdoor",
    "backdoors": "backdoor",
    "dos": "dos",
    "exploits": "exploits",
    "fuzzers": "fuzzers",
    "generic": "generic",
    "reconnaissance": "reconnaissance",
    "shellcode": "shellcode",
    "worms": "worms",
}
UNSW_CATEGORICAL = ("proto", "service", "state")
UNSW_IDENTIFIERS = ("id", "srcip", "sport", "dstip", "dsport", "stime", "ltime")

# Shared name -> (source column, multiplier into the shared unit).
# Sizes are similar rather than identical: CICFlowMeter and Argus/Bro do not count
# packet bytes the same way, so cross-dataset results carry that caveat.
SHARED_FEATURES = {
    "cicids2017": {
        "duration_s": ("Flow Duration", 1e-6),
        "src_packets": ("Total Fwd Packets", 1.0),
        "dst_packets": ("Total Backward Packets", 1.0),
        "src_bytes": ("Total Length of Fwd Packets", 1.0),
        "dst_bytes": ("Total Length of Bwd Packets", 1.0),
        "src_packet_mean": ("Fwd Packet Length Mean", 1.0),
        "dst_packet_mean": ("Bwd Packet Length Mean", 1.0),
        "src_interarrival_ms": ("Fwd IAT Mean", 1e-3),
        "dst_interarrival_ms": ("Bwd IAT Mean", 1e-3),
    },
    # Names from the improved release's labelling code; the means are unverified until first load.
    "cicids2017_improved": {
        "duration_s": ("Flow Duration", 1e-6),
        "src_packets": ("Total Fwd Packet", 1.0),
        "dst_packets": ("Total Bwd packets", 1.0),
        "src_bytes": ("Total Length of Fwd Packet", 1.0),
        "dst_bytes": ("Total Length of Bwd Packet", 1.0),
        "src_packet_mean": ("Fwd Packet Length Mean", 1.0),
        "dst_packet_mean": ("Bwd Packet Length Mean", 1.0),
        "src_interarrival_ms": ("Fwd IAT Mean", 1e-3),
        "dst_interarrival_ms": ("Bwd IAT Mean", 1e-3),
    },
    "unsw_nb15": {
        "duration_s": ("dur", 1.0),
        "src_packets": ("spkts", 1.0),
        "dst_packets": ("dpkts", 1.0),
        "src_bytes": ("sbytes", 1.0),
        "dst_bytes": ("dbytes", 1.0),
        "src_packet_mean": ("smean", 1.0),
        "dst_packet_mean": ("dmean", 1.0),
        "src_interarrival_ms": ("sinpkt", 1.0),
        "dst_interarrival_ms": ("dinpkt", 1.0),
    },
}


SOURCE_PATTERNS = {"cicids2017": "*.csv", "unsw_nb15": "UNSW_NB15_*-set.csv", "cicids2017_improved": "*day.csv"}


def _csv_files(directory: str | Path, pattern: str = "*.csv") -> list[Path]:
    files = sorted(Path(directory).glob(pattern))
    if not files:
        raise FileNotFoundError(f"No files matching {pattern} in {directory}. See README.md.")
    return files


def _to_float32(frame: pd.DataFrame) -> pd.DataFrame:
    """Parse numbers compactly; infinities and unparseable values become NaN for imputation."""
    out = {}
    for column in frame.columns:
        values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=np.float64, copy=True)
        values[~np.isfinite(values)] = np.nan
        out[column] = np.clip(values, -1e30, 1e30).astype(np.float32)
    return pd.DataFrame(out)


def dataset_files(config: DatasetConfig) -> list[Path]:
    """Return the source files a real dataset loads from; generated data has none."""
    if config.kind == "synthetic":
        return []
    if config.path is None:
        raise ValueError(f"Dataset {config.kind} needs a path")
    if config.kind not in SOURCE_PATTERNS:
        raise ValueError(f"Unknown dataset kind: {config.kind}")
    return _csv_files(config.path, SOURCE_PATTERNS[config.kind])


def _cicids_family(raw_label: str) -> str:
    label = str(raw_label).strip().lower()
    # Web attack labels contain a dash that some releases garble, so match the prefix.
    if label.startswith("web attack"):
        return "web_attack"
    if label not in CICIDS_FAMILIES:
        raise ValueError(f"Unknown CICIDS2017 label: {raw_label!r}")
    return CICIDS_FAMILIES[label]


def load_cicids2017(directory: str | Path, drop_columns: Iterable[str] = ()) -> Dataset:
    """Load the CICIDS2017 ``MachineLearningCVE`` CSV files."""
    drop = set(CICIDS_IDENTIFIERS) | set(drop_columns)
    features, families = [], []
    for path in _csv_files(directory, SOURCE_PATTERNS["cicids2017"]):
        frame = pd.read_csv(path, encoding="latin-1", low_memory=False)
        frame.columns = frame.columns.str.strip()
        if "Label" not in frame.columns:
            raise ValueError(f"{path} has no Label column")
        frame = frame.dropna(subset=["Label"])
        families.append(frame["Label"].map(_cicids_family).to_numpy(dtype=object))
        features.append(_to_float32(frame.drop(columns=["Label", *(drop & set(frame.columns))])))
    if any(list(f.columns) != list(features[0].columns) for f in features):
        raise ValueError("CICIDS2017 files do not share the same columns")
    return Dataset("cicids2017", pd.concat(features, ignore_index=True), np.concatenate(families))


def load_unsw_nb15(directory: str | Path, drop_columns: Iterable[str] = ()) -> Dataset:
    """Load both published partition files; Aegis makes its own splits from the combined rows."""
    drop = set(UNSW_IDENTIFIERS) | set(drop_columns)
    frame = pd.concat(
        [pd.read_csv(p, low_memory=False) for p in _csv_files(directory, SOURCE_PATTERNS["unsw_nb15"])],
        ignore_index=True,
    )
    frame.columns = frame.columns.str.strip().str.lower()
    missing = {"attack_cat", "label"} - set(frame.columns)
    if missing:
        raise ValueError(f"UNSW-NB15 files are missing columns: {sorted(missing)}")

    category = frame["attack_cat"].fillna("normal").astype(str).str.strip().str.lower()
    unknown = sorted(set(category) - set(UNSW_FAMILIES))
    if unknown:
        raise ValueError(f"Unknown UNSW-NB15 attack categories: {unknown}")
    family = category.map(UNSW_FAMILIES).to_numpy(dtype=object)
    if np.any((family != BENIGN) != (frame["label"].to_numpy() == 1)):
        raise ValueError("UNSW-NB15 attack_cat and label columns disagree")

    frame = frame.drop(columns=["attack_cat", "label", *(drop & set(frame.columns))])
    categorical = tuple(c for c in UNSW_CATEGORICAL if c in frame.columns)
    numeric = _to_float32(frame.drop(columns=list(categorical)))
    text = frame[list(categorical)].fillna("missing").astype(str)
    return Dataset("unsw_nb15", pd.concat([numeric, text], axis=1), family, categorical)


def generate_synthetic(name: str = "synthetic", seed: int = 0, n_benign: int = 6000) -> Dataset:
    """Generate separable clusters for tests and smoke runs. Not a model of real traffic."""
    rng = np.random.default_rng(seed)
    n_features = 12
    # Fixed across seeds, so generated datasets share a family structure and can test transfer.
    profiles = {
        "scan": (0, 1, 2),
        "flood": (3, 4, 5),
        "exfil": (6, 7, 8),
        "beacon": (9, 10, 11),
    }
    rows = [rng.lognormal(0.0, 0.4, size=(n_benign, n_features))]
    families = [np.full(n_benign, BENIGN, dtype=object)]
    for family, dims in profiles.items():
        count = n_benign // 6
        block = rng.lognormal(0.0, 0.4, size=(count, n_features))
        block[:, list(dims)] *= 30.0
        rows.append(block)
        families.append(np.full(count, family, dtype=object))
    X = pd.DataFrame(np.vstack(rows).astype(np.float32),
                     columns=[f"feature_{i}" for i in range(n_features)])
    family = np.concatenate(families)
    order = rng.permutation(len(X))
    return Dataset(name, X.iloc[order], family[order])


def locate_data(root: str | Path) -> dict[str, Path]:
    """Find each dataset's folder under ``root``, and reject incomplete copies.

    Copies of CICIDS2017 often also include ``TrafficLabelling``, whose files have the
    same names but different columns, so a ``MachineLearning`` folder is preferred.
    """
    root = Path(root)
    found: dict[str, Path] = {}

    cicids = {p.parent for p in root.rglob("*.pcap_ISCX.csv")}
    preferred = {d for d in cicids if "machinelearning" in str(d).lower()}
    candidates = preferred or cicids
    if len(candidates) > 1:
        raise ValueError(f"Several CICIDS2017 folders under {root}: {sorted(map(str, candidates))}")
    if candidates:
        folder = next(iter(candidates))
        count = len(list(folder.glob("*.pcap_ISCX.csv")))
        if count != 8:
            raise ValueError(f"{folder} has {count} CICIDS2017 CSV files; expected 8")
        found["cicids2017"] = folder

    unsw = {p.parent for p in root.rglob("UNSW_NB15_*-set.csv")}
    if len(unsw) > 1:
        raise ValueError(f"Several UNSW-NB15 folders under {root}: {sorted(map(str, unsw))}")
    if unsw:
        folder = next(iter(unsw))
        for name in ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"):
            if not (folder / name).exists():
                raise ValueError(f"{folder} is missing {name}")
        found["unsw_nb15"] = folder

    from aegis.data.improved import DAY_FILES  # Improved CICIDS2017: five day files, all required.
    improved = {p.parent for p in root.rglob("monday.csv")}
    if len(improved) > 1:
        raise ValueError(f"Several improved CICIDS2017 folders under {root}: {sorted(map(str, improved))}")
    if improved:
        folder = next(iter(improved))
        absent = [name for name in DAY_FILES if not (folder / name).exists()]
        if absent:
            raise ValueError(f"{folder} is missing {absent}")
        found["cicids2017_improved"] = folder
    return found


def load_dataset(config: DatasetConfig) -> Dataset:
    if config.kind == "cse_cic_ids2018":
        raise PermissionError("External test sets load only through aegis.data.external.guarded_load")
    if config.kind == "synthetic":
        return generate_synthetic(config.name or "synthetic", config.seed)
    if config.path is None:
        raise ValueError(f"Dataset {config.kind} needs a path")
    if config.kind == "cicids2017":
        return load_cicids2017(config.path, config.drop_columns)
    if config.kind == "unsw_nb15":
        return load_unsw_nb15(config.path, config.drop_columns)
    if config.kind == "cicids2017_improved":
        from aegis.data.improved import load_cicids2017_improved
        return load_cicids2017_improved(config.path, config.drop_columns)
    raise ValueError(f"Unknown dataset kind: {config.kind}")


def project_to_shared(ds: Dataset) -> Dataset:
    """Return the features two datasets have in common, in shared names and units."""
    if ds.name.startswith("synthetic"):
        return ds  # Generated datasets already share one schema.
    mapping = SHARED_FEATURES[ds.name]
    missing = [column for column, _ in mapping.values() if column not in ds.X.columns]
    if missing:
        raise ValueError(f"{ds.name} is missing shared-feature columns: {missing}")
    shared = pd.DataFrame(
        {new: (ds.X[column] * scale).astype(np.float32) for new, (column, scale) in mapping.items()}
    )
    return Dataset(ds.name, shared, ds.family)
