"""The improved CICIDS2017 loader, on small files shaped like the published release."""

import pandas as pd
import pytest

from aegis.config import DatasetConfig
from aegis.data.dataset import BENIGN
from aegis.data.improved import DAY_FILES, label_counts, load_cicids2017_improved
from aegis.data.loaders import load_dataset, locate_data, project_to_shared

FEATURES = ["Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
            "Total Length of Bwd Packet", "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Fwd IAT Mean",
            "Bwd IAT Mean", "FWD Init Win Bytes"]
ROWS = {
    "monday.csv": [("BENIGN", -1)] * 3,
    "tuesday.csv": [("BENIGN", -1), ("FTP-Patator", -1), ("FTP-Patator - Attempted", 0), ("SSH-Patator", -1)],
    "wednesday.csv": [("BENIGN", -1), ("DoS Hulk", -1), ("DoS Slowloris - Attempted", 6), ("Heartbleed", -1)],
    "thursday.csv": [("BENIGN", -1), ("Web Attack - XSS", -1), ("Web Attack - Brute Force - Attempted", 2),
                     ("Infiltration", -1), ("Infiltration - Portscan", -1)],
    "friday.csv": [("BENIGN", -1), ("Portscan", -1), ("Botnet", -1), ("Botnet - Attempted", 1), ("DDoS", -1)],
}


def write_release(folder, rows=ROWS, extra_index=False):
    folder.mkdir(parents=True, exist_ok=True)
    for name, labels in rows.items():
        frame = pd.DataFrame({
            "Flow ID": [f"10.0.0.{i}-10.0.0.9-1-80-6" for i in range(len(labels))],
            "Src IP": "10.0.0.1", "Src Port": 40000, "Dst IP": "10.0.0.9", "Dst Port": 80, "Protocol": 6,
            "Timestamp": "2017-07-04 10:00:00.000000",
            **{f: [float(i + 1) for i in range(len(labels))] for f in FEATURES},
            "Label": [label for label, _ in labels],
            "Attempted Category": [code for _, code in labels],
        })
        if extra_index:
            frame.insert(0, "id", range(1, len(frame) + 1))
        frame.to_csv(folder / name, index=False)
    return folder


def test_loads_maps_families_and_excludes_attempted_flows(tmp_path):
    ds = load_cicids2017_improved(write_release(tmp_path / "improved", extra_index=True), ("Dst Port",))
    assert ds.name == "cicids2017_improved"
    assert ds.family_counts() == {BENIGN: 7, "bot": 1, "brute_force": 2, "dos": 2, "heartbleed": 1,
                                  "infiltration": 1, "portscan": 2, "web_attack": 1}
    assert list(ds.X.columns) == ["Protocol", *FEATURES]  # Identifiers, the row id and Dst Port are gone.


def test_label_counts_report_attempted_rows_before_exclusion(tmp_path):
    counts = label_counts(write_release(tmp_path / "improved"))
    assert counts["rows"].sum() == sum(len(v) for v in ROWS.values())
    attempted = counts[counts["Attempted Category"] >= 0]
    assert set(attempted["Label"]) == {"FTP-Patator - Attempted", "DoS Slowloris - Attempted",
                                       "Web Attack - Brute Force - Attempted", "Botnet - Attempted"}


@pytest.mark.parametrize("label, code, message", [
    ("DoS Slowhttptest - (Category 2 - Attack Startup/Teardown Artefact)", 2, "Unknown"),  # Documented variant.
    ("PortScan - Attempted", -1, "disagrees"),
    ("DoS Hulk", 3, "disagrees"),
    ("DoS Hulk - Attempted", 9, "disagrees"),
    ("BENIGN - Attempted", 0, "benign flow"),
])
def test_unexpected_labels_or_categories_are_refused(tmp_path, label, code, message):
    rows = {**ROWS, "friday.csv": ROWS["friday.csv"] + [(label, code)]}
    with pytest.raises(ValueError, match=message):
        load_cicids2017_improved(write_release(tmp_path / "improved", rows))


def test_a_misspelt_drop_column_is_refused(tmp_path):
    with pytest.raises(ValueError, match="Destination Port"):
        load_cicids2017_improved(write_release(tmp_path / "improved"), ("Destination Port",))


def test_the_original_release_is_not_mistaken_for_the_improved_one(tmp_path):
    folder = write_release(tmp_path / "improved")
    frame = pd.read_csv(folder / "monday.csv").drop(columns=["Attempted Category"])
    frame.to_csv(folder / "monday.csv", index=False)
    with pytest.raises(ValueError, match="improved release"):
        load_cicids2017_improved(folder)


def test_located_and_dispatched_like_the_other_datasets(tmp_path):
    folder = write_release(tmp_path / "data" / "CNS2022" / "CICIDS2017")
    assert locate_data(tmp_path / "data") == {"cicids2017_improved": folder}
    ds = load_dataset(DatasetConfig(kind="cicids2017_improved", path=str(folder), drop_columns=("Dst Port",)))
    assert len(project_to_shared(ds).X.columns) == 9
    (folder / DAY_FILES[2]).unlink()
    with pytest.raises(ValueError, match="wednesday.csv"):
        locate_data(tmp_path / "data")
