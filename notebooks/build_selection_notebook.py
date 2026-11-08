"""Generate selection_check.ipynb with the package source embedded.

Run this after changing anything in src/; a test checks that the notebook is current.

    .venv/bin/python notebooks/build_selection_notebook.py
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import nbformat
from nbformat.v4 import new_code_cell, new_markdown_cell, new_notebook

OUTPUT = Path(__file__).with_name("selection_check.ipynb")

_spec = importlib.util.spec_from_file_location("build_notebook", Path(__file__).with_name("build_notebook.py"))
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

INTRO = """\\
# Aegis v2: nested selection check of the Config A baseline

Config A uses the `rf` score, chosen after seeing held-out test results. This notebook repeats that
choice the way later configurations must make it: for each outer held-out family, `rf`, `ae` and
`fused` are compared by inner leave-one-family-out on training and validation rows only. The outer
test rows are never read. The rule is fixed in advance, at 1% FPR: a challenger replaces `rf` only if
its mean inner recall is higher and it beats `rf` on a strict majority of inner families. The result
is reported whichever score it selects.

**Before you start:** use the same data folder as the Config A run. Results go to a new folder.

**If the session stops:** run everything again with the same `OUTPUT_DIR`. Finished pairs are kept.

**Sending results back:** return this notebook with its outputs, plus `aegis_selection_results.zip`
from the last cell. Neither contains any traffic rows.
"""

_folder = "results/config_a"
if base.SETTINGS.count(_folder) != 4:
    raise ValueError("The base settings cell changed; review the output folder replacement")
SETTINGS = base.SETTINGS.replace(_folder, "results/selection_check")

CHECK = """\\
import tempfile
from aegis.config import AutoencoderConfig, BaselineConfig, DatasetConfig, RandomForestConfig
from aegis.experiments.selection import run as run_selection
from aegis.frozen import verify_config_a

check_config = BaselineConfig(
    datasets=(DatasetConfig(kind='synthetic', name='synthetic_a', seed=11),),
    seeds=(0,), max_train_per_family=3000, min_family_count=100,
    target_fprs=TARGET_FPRS, attack_prevalences=ATTACK_PREVALENCES, bootstrap_samples=200,
    rf=RandomForestConfig(n_estimators=20, max_depth=10, n_jobs=cpus),
    autoencoder=AutoencoderConfig(epochs=3, device=AE_DEVICE),
)
with tempfile.TemporaryDirectory() as folder:
    assert len(run_selection(check_config, folder, log=lambda message: None)), 'The pipeline check produced no rows'
print('Pipeline check passed on generated data. These numbers say nothing about real traffic.')
"""

RUN = """\\
import time

if all(d.kind != 'synthetic' for d in config.datasets):
    verify_config_a(config)  # Refuses unless these settings and this code are the frozen Config A.
    print('Settings and code match the frozen Config A')
started = time.time()
selected = run_selection(config, OUTPUT_DIR, extra_manifest={'source_version': SOURCE_VERSION})
print(f'Finished in {(time.time() - started) / 3600:.2f} h this session; {len(selected)} outer folds')
"""

TABLES = """\\
import pandas as pd

pd.set_option('display.max_rows', 300, 'display.width', 200)
display(selected.round(3))
counts = selected.groupby('dataset')['selected'].value_counts().unstack(fill_value=0)
display(counts)
share = (selected['selected'] == 'rf').mean()
print(f'Nested selection chose rf in {share:.1%} of {len(selected)} outer folds (dataset x seed x held-out family).')
print('This is reported either way. A majority for another score means the rf choice relied on test results.')
"""

PACKAGE = """\\
import zipfile

archive = f'{OUTPUT_DIR}/aegis_selection_results.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name in ('manifest.json', 'inner_results.csv', 'selections.csv'):
        bundle.write(f'{OUTPUT_DIR}/{name}', name)
print('Return this file with the executed notebook:', archive)
"""


def build() -> nbformat.NotebookNode:
    return new_notebook(
        cells=[
            new_markdown_cell(INTRO),
            new_markdown_cell("## 1. Settings"),
            new_code_cell(SETTINGS),
            new_markdown_cell("## 2. Setup"),
            new_code_cell(base.DEPENDENCIES),
            base.embedded_source_cell(),
            new_code_cell(base.ENVIRONMENT),
            new_markdown_cell("## 3. Check the pipeline on generated data"),
            new_code_cell(CHECK),
            new_markdown_cell("## 4. Find the real data"),
            new_code_cell(base.LOCATE),
            new_markdown_cell("## 5. Run nested selection\\nThis is the long step. A progress line appears after each family pair."),
            new_code_cell(RUN),
            new_markdown_cell("## 6. Results"),
            new_code_cell(TABLES),
            new_markdown_cell("## 7. Package the results"),
            new_code_cell(PACKAGE),
        ],
        metadata={
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
    )


def main() -> None:
    nbformat.write(build(), OUTPUT)
    print(f"Wrote {OUTPUT} (source version {base.source_hash()})")


if __name__ == "__main__":
    main()
