"""Generate artifact_resistance.ipynb with the package source embedded.

Run this after changing anything in src/; a test checks that the notebook is current.

    .venv/bin/python notebooks/build_artifact_notebook.py
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import nbformat
from nbformat.v4 import new_code_cell, new_markdown_cell, new_notebook

OUTPUT = Path(__file__).with_name("artifact_resistance.ipynb")

_spec = importlib.util.spec_from_file_location("build_notebook", Path(__file__).with_name("build_notebook.py"))
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

INTRO = """\
# Aegis v2: artifact-resistant evaluation

Tests whether Random Forest recall on held-out attack families survives the removal of dataset
shortcuts. Every treatment refits the baseline on the same folds. No label is changed.

| Treatment | Question |
| --- | --- |
| `remove_matching_signatures` | Does the model rely on near-duplicates of the held-out family? |
| Raw versus deduplicated, on `reference` | How sensitive is recall to duplicate handling? |
| `no_tcp_window` | Does the model rely on host-specific TCP fingerprints? |
| `neutralize_missing_markers`, `missingness_only` | Is missingness itself a shortcut? |
| `no_context_counts` | How much does UNSW-NB15 depend on its `ct_*` counts? |
| `all_controls` | What remains with signatures, TCP windows and markers all controlled? |

**Before you start:** use the same data folder as the Config A run. Results go to a new folder,
and this notebook only reads the earlier Config A folder.

**If the session stops:** run everything again with the same `OUTPUT_DIR`. Finished folds are kept.

**Sending results back:** return this notebook with its outputs, plus
`aegis_artifact_results.zip` from the last cell. Neither contains any traffic rows.
"""

_folder = "results/config_a"
if base.SETTINGS.count(_folder) != 4:
    raise ValueError("The base settings cell changed; review the output folder replacement")
SETTINGS = base.SETTINGS.replace(_folder, "results/config_a_artifacts") + """
# Config A results stay untouched. They are read once, to compare the data and reference scores.
PREVIOUS_DIR = os.environ.get('AEGIS_PREVIOUS_DIR', OUTPUT_DIR.replace('config_a_artifacts', 'config_a'))
if os.path.realpath(OUTPUT_DIR) == os.path.realpath(PREVIOUS_DIR):
    raise ValueError('OUTPUT_DIR must be a new folder, separate from the Config A results')
print('PREVIOUS   ', PREVIOUS_DIR)
"""

CHECK = """\
import tempfile
from aegis.config import AutoencoderConfig, BaselineConfig, DatasetConfig, RandomForestConfig
from aegis.experiments.artifacts import run as run_artifacts

check_config = BaselineConfig(
    datasets=(DatasetConfig(kind='synthetic', name='synthetic_a', seed=11),),
    seeds=(0,), max_train_per_family=5000, min_family_count=100,
    target_fprs=TARGET_FPRS, attack_prevalences=ATTACK_PREVALENCES, bootstrap_samples=200,
    rf=RandomForestConfig(n_estimators=20, max_depth=10, n_jobs=cpus),
)
with tempfile.TemporaryDirectory() as folder:
    assert len(run_artifacts(check_config, folder, log=lambda message: None)), 'The pipeline check produced no rows'
print('Pipeline check passed on generated data. These numbers say nothing about real traffic.')
"""

RUN = """\
import time

started = time.time()
results = run_artifacts(config, OUTPUT_DIR, extra_manifest={'source_version': SOURCE_VERSION})
print(f'Finished in {(time.time() - started) / 3600:.2f} h this session; {len(results)} result rows')
"""

COMPARE = """\
import json
import pandas as pd

previous_manifest = os.path.join(PREVIOUS_DIR, 'manifest.json')
previous_results = os.path.join(PREVIOUS_DIR, 'results.csv')
if os.path.exists(previous_manifest) and os.path.exists(previous_results):
    with open(previous_manifest, encoding='utf-8') as handle:
        earlier = json.load(handle)
    with open(os.path.join(OUTPUT_DIR, 'manifest.json'), encoding='utf-8') as handle:
        current = json.load(handle)
    same = earlier['identity']['data']['source_sha256'] == current['identity']['data']['source_sha256']
    print('Same source data as Config A:', same)
    old = pd.read_csv(previous_results)
    old = old[(old['scorer'] == 'rf') & old['fold'].str.startswith('holdout:')]
    new = results[results['treatment'] == 'reference']
    paired = new.merge(old, left_on=['dataset', 'family', 'seed', 'target_fpr'],
                       right_on=['dataset', 'eval_family', 'seed', 'target_fpr'], suffixes=('', '_config_a'))
    gap = (paired['recall'] - paired['recall_config_a']).abs()
    print(f'Reference recall vs Config A RF: mean gap {gap.mean():.4f}, largest {gap.max():.4f}, {len(paired)} pairs.')
    print('A gap means the library versions or machine differ. Compare treatments within this run only.')
else:
    print('No Config A results found in', PREVIOUS_DIR, 'so this comparison was skipped.')
"""

TABLES = """\
pd.set_option('display.max_rows', 300, 'display.width', 200, 'display.max_columns', 40)
primary_fpr = config.target_fprs[0]
main = results[results['target_fpr'] == primary_fpr]
effects = pd.read_csv(f'{OUTPUT_DIR}/treatment_effects.csv')
order = ['reference', 'remove_matching_signatures', 'no_tcp_window', 'neutralize_missing_markers',
         'no_context_counts', 'all_controls', 'missingness_only']

for metric in ('recall', 'auc'):
    table = main.pivot_table(index=['dataset', 'family'], columns='treatment', values=metric)
    display(table[[c for c in order if c in table.columns]].round(3))

print('Raw versus deduplicated evaluation, reference treatment')
raw = main[main['treatment'] == 'reference'].groupby(['dataset', 'family'])[
    ['recall', 'raw_recall', 'raw_recall_at_oracle_fpr', 'raw_fpr', 'raw_distinct_recall',
     'raw_conflicting_share', 'raw_attack_rows']].mean()
display(raw.round(3))

print('Recall by whether a test flow matches a training attack apart from timing, reference treatment')
display(main[main['treatment'] == 'reference'].groupby(['dataset', 'family'])[
    ['signature_matched_rows', 'n_attack', 'recall_signature_matched', 'recall_signature_unmatched']].mean().round(3))

# The rule set in the v2 specification before this run.
flagged = effects[(effects['target_fpr'] == primary_fpr) & (effects['treatment'] != 'missingness_only')
                  & (effects['mean_diff'] >= 0.10) & (effects['ci_low'] > 0)]
print('Shortcut-dependent results: recall falls by at least 0.10 and the paired interval excludes zero')
display(flagged[['dataset', 'family', 'treatment', 'recall_reference', 'recall_treated', 'mean_diff',
                 'ci_low', 'ci_high', 'cohen_dz']].round(3))
print('With five seeds the paired test cannot reach p < 0.05, and values are not corrected for '
      'testing many families and treatments. Read the intervals and effect sizes.')
"""

PACKAGE = """\
import zipfile

archive = f'{OUTPUT_DIR}/aegis_artifact_results.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name in ('manifest.json', 'results.csv', 'treatment_effects.csv'):
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
            new_markdown_cell("## 5. Run the experiments\nThis is the long step. A progress line appears after each fold."),
            new_code_cell(RUN),
            new_markdown_cell("## 6. Compare with Config A"),
            new_code_cell(COMPARE),
            new_markdown_cell("## 7. Results"),
            new_code_cell(TABLES),
            new_markdown_cell("## 8. Package the results"),
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
