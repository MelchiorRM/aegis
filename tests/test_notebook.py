import importlib.util
import json
import zipfile
from pathlib import Path

import nbformat
import numpy as np
import pandas as pd
from nbclient import NotebookClient

from aegis.config import load_config
from aegis.experiments.baseline import _experiment_settings

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "config_a_baseline.ipynb"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_notebook", ROOT / "notebooks" / "build_notebook.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cicids_fixture(folder: Path, rng: np.random.Generator) -> None:
    """Five day files shaped like the improved CICIDS2017 release, including some "Attempted" flows."""
    folder.mkdir(parents=True)
    columns = [
        "Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
        "Total Length of Bwd Packet", "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Bytes/s",
        "Fwd IAT Mean", "Bwd IAT Mean",
    ]
    labels = (["BENIGN"] * 1200 + ["DoS Hulk"] * 300 + ["Portscan"] * 300 + ["Heartbleed"] * 11
              + ["DoS Hulk - Attempted"] * 40)
    names = np.array(labels)
    values = rng.lognormal(3.0, 0.5, size=(len(labels), len(columns)))
    values[names == "DoS Hulk", 0:3] *= 40
    values[names == "Portscan", 3:6] *= 40
    frame = pd.DataFrame(values, columns=columns)
    frame["Flow Bytes/s"] = frame["Flow Bytes/s"].astype(object)
    frame.loc[0, "Flow Bytes/s"] = "Infinity"
    frame.insert(0, "Timestamp", "2017-07-05 10:00:00.000000")
    frame.insert(0, "Protocol", 6)
    frame.insert(0, "Dst Port", rng.choice([80, 443, 22], len(frame)))
    frame.insert(0, "Dst IP", "192.168.10.50")
    frame.insert(0, "Src Port", rng.integers(1024, 65535, len(frame)))
    frame.insert(0, "Src IP", "172.16.0.1")
    frame.insert(0, "Flow ID", [f"flow-{i}" for i in range(len(frame))])
    frame["Label"] = labels
    frame["Attempted Category"] = np.where(np.char.endswith(names.astype(str), " - Attempted"), 0, -1)
    frame = frame.sample(frac=1.0, random_state=0).reset_index(drop=True)
    days = ("monday", "tuesday", "wednesday", "thursday", "friday")
    for day, part in zip(days, np.array_split(np.arange(len(frame)), len(days))):
        frame.iloc[part].to_csv(folder / f"{day}.csv", index=False)


def unsw_fixture(folder: Path, rng: np.random.Generator) -> None:
    folder.mkdir(parents=True)
    numeric = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "smean", "dmean", "sinpkt", "dinpkt"]
    categories = ["Normal"] * 1200 + ["Exploits"] * 300 + ["Generic"] * 300
    values = rng.lognormal(2.0, 0.5, size=(len(categories), len(numeric)))
    names = np.array(categories)
    values[names == "Exploits", :3] *= 40
    values[names == "Generic", 3:6] *= 40
    frame = pd.DataFrame(values, columns=numeric)
    frame.insert(0, "id", range(len(frame)))
    frame["proto"] = rng.choice(["tcp", "udp"], len(frame))
    frame["service"] = rng.choice(["-", "dns"], len(frame))
    frame["state"] = rng.choice(["FIN", "CON"], len(frame))
    frame["attack_cat"] = categories
    frame["label"] = (names != "Normal").astype(int)
    frame = frame.sample(frac=1.0, random_state=0).reset_index(drop=True)
    half = len(frame) // 2
    frame.iloc[:half].to_csv(folder / "UNSW_NB15_training-set.csv", index=False)
    frame.iloc[half:].to_csv(folder / "UNSW_NB15_testing-set.csv", index=False)


def test_notebook_embeds_the_current_source():
    # If this fails, run: .venv/bin/python notebooks/build_notebook.py
    source = NOTEBOOK.read_text(encoding="utf-8")
    assert f"SOURCE_VERSION = '{load_builder().source_hash()}'" in json.loads(json.dumps(source))


def test_notebook_has_no_saved_outputs():
    notebook = nbformat.read(NOTEBOOK, as_version=4)
    assert all(not cell.get("outputs") for cell in notebook.cells if cell.cell_type == "code")


def test_notebook_runs_top_to_bottom_on_small_csv_files(tmp_path, monkeypatch):
    rng = np.random.default_rng(0)
    cicids_fixture(tmp_path / "data" / "CNS2022" / "CICIDS2017", rng)
    unsw_fixture(tmp_path / "data" / "UNSW", rng)
    output = tmp_path / "output"
    monkeypatch.setenv("AEGIS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(output))
    monkeypatch.setenv("AEGIS_SEEDS", "0,1")
    monkeypatch.setenv("AEGIS_CROSS", "1")

    notebook = nbformat.read(NOTEBOOK, as_version=4)
    NotebookClient(
        notebook, timeout=900, kernel_name="python3", resources={"metadata": {"path": str(tmp_path)}}
    ).execute()

    text = "\n".join(
        str(out.get("text", ""))
        for cell in notebook.cells
        if cell.cell_type == "code"
        for out in cell.outputs
    )
    assert "Pipeline check passed" in text
    assert "PHASE 1 GATE: MET" in text

    with zipfile.ZipFile(output / "aegis_config_a_results.zip") as bundle:
        assert set(bundle.namelist()) == {
            "manifest.json", "results.csv", "summary.csv", "degradation.csv", "seen_vs_heldout_recall.png",
        }
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["identity"]["extra"]["source_version"] == load_builder().source_hash()
    # The embedded copy fingerprints to the same value as the source it came from.
    assert manifest["identity"]["source_version"] == load_builder().source_hash()
    assert manifest["held_out_families"] == {
        "cicids2017_improved": ["dos", "portscan"],
        "unsw_nb15": ["exploits", "generic"],
    }
    assert "cannot fall below 0.05" in text
    assert "not corrected for testing many families" in text
    assert "Features to review:" in text
    assert set(manifest["identity"]["data"]["source_sha256"]) == {"cicids2017_improved", "unsw_nb15"}
    assert len(manifest["identity"]["data"]["source_sha256"]["cicids2017_improved"]) == 5

    # Seeds and the cross-dataset switch are set by the environment in this test.
    reference = load_config(ROOT / "configs" / "baseline.yaml")
    assert manifest["identity"]["settings"] == json.loads(json.dumps(_experiment_settings(reference)))
    settings_cell = load_builder().SETTINGS
    assert f"'AEGIS_SEEDS', '{','.join(map(str, reference.seeds))}'" in settings_cell
    assert f"'AEGIS_CROSS', '{int(reference.cross_dataset)}'" in settings_cell

    results = pd.read_csv(output / "results.csv")
    assert (results["fold"] == "cross:cicids2017_improved->unsw_nb15").any()
    assert "Dst Port" not in json.dumps(manifest["family_counts"])
