"""Generate config_a_baseline.ipynb with the package source embedded.

Embedding the source lets the notebook run elsewhere without a clone. Run this after
changing anything in src/ to keep the notebook in step; a test checks that.

    .venv/bin/python notebooks/build_notebook.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import nbformat
from nbformat.v4 import new_code_cell, new_markdown_cell, new_notebook

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
OUTPUT = Path(__file__).with_name("config_a_baseline.ipynb")

sys.path.insert(0, str(SOURCE))
from aegis import provenance  # noqa: E402  (this repository's copy, installed or not)


def source_files() -> dict[str, str]:
    return provenance.source_files(SOURCE)


def source_hash() -> str:
    return provenance.source_hash(SOURCE)


def embedded_source_cell():
    entries = []
    for name, text in source_files().items():
        if "'''" in text:
            raise ValueError(f"{name} contains ''' and cannot be embedded")
        entries.append(f"    {name!r}: r'''{text}''',\n")
    code = (
        "#@title Aegis source (generated from src/; do not edit here)\n"
        "import sys, tempfile\n"
        "from pathlib import Path\n\n"
        f"SOURCE_VERSION = {source_hash()!r}\n"
        "FILES = {\n" + "".join(entries) + "}\n\n"
        "source_root = Path(tempfile.mkdtemp(prefix='aegis_source_'))\n"
        "for name, text in FILES.items():\n"
        "    path = source_root / name\n"
        "    path.parent.mkdir(parents=True, exist_ok=True)\n"
        "    path.write_text(text, encoding='utf-8')\n"
        "sys.path.insert(0, str(source_root))\n"
        "print('Aegis source version', SOURCE_VERSION)\n"
    )
    return new_code_cell(code, metadata={"cellView": "form", "jupyter": {"source_hidden": True}})


INTRO = """\
# Aegis v2, Phase 1: Config A baseline

This notebook measures the static Random Forest + autoencoder defender on held-out attack
families. Phase 1 closes when that measurement exists for every eligible family, whatever
the score is. A weak or null result still counts.

**Before you start**
1. Put the datasets in the folder set by `DATA_ROOT` in the next cell:
   - CICIDS2017: the 8 `MachineLearningCVE` CSV files
   - UNSW-NB15: `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`
2. Choose a machine with more than 12 GB of RAM. A GPU is optional and has little effect,
   because most of the time goes to the Random Forest, which runs on CPU.

**Running it:** use *Run all*. The notebook stops early with a clear message if the data is
missing or incomplete.

**If the session stops:** run everything again with the same `OUTPUT_DIR`. Finished folds are
kept and only the missing ones run. On Colab, results go to Google Drive so they survive a
disconnect. On Kaggle, `/kaggle/working` is lost when a session ends unless you use
*Save Version*, so use that for a full run.

**Sending results back:** return this notebook with its outputs, plus
`aegis_config_a_results.zip` from the last cell. Neither contains any traffic rows.
"""

SETTINGS = """\
import os, sys

IN_COLAB = 'google.colab' in sys.modules
IN_KAGGLE = os.path.isdir('/kaggle/working')

if IN_COLAB:
    from google.colab import drive
    drive.mount('/content/drive')
    default_data = '/content/drive/MyDrive/aegis/data'
    default_output = '/content/drive/MyDrive/aegis/results/config_a'
elif IN_KAGGLE:
    default_data = '/kaggle/input'
    default_output = '/kaggle/working/results/config_a'
else:
    default_data = '../data' if os.path.basename(os.getcwd()) == 'notebooks' else 'data'
    default_output = '../results/config_a' if os.path.basename(os.getcwd()) == 'notebooks' else 'results/config_a'

# Edit these if your folders differ. The AEGIS_ variables are used by the automated test.
DATA_ROOT = os.environ.get('AEGIS_DATA_ROOT', default_data)
OUTPUT_DIR = os.environ.get('AEGIS_OUTPUT_DIR', default_output)

# v2 asks for 5-10 seeds. To add seeds later, extend this list and run again with the same
# OUTPUT_DIR. Five seeds cannot reach p < 0.05 in the paired test; six is the minimum.
SEEDS = [int(s) for s in os.environ.get('AEGIS_SEEDS', '0,1,2,3,4').split(',')]

# The first value of each list is the primary operating point.
TARGET_FPRS = (0.01, 0.001)
ATTACK_PREVALENCES = (0.01, 0.001)  # Assumed attack share of traffic, not a measurement.

MAX_TRAIN_PER_FAMILY = 100_000
MIN_FAMILY_COUNT = 200

# The roadmap places cross-dataset tests in phase 5, so they are off for this gate.
RUN_CROSS_DATASET = os.environ.get('AEGIS_CROSS', '0') == '1'

print('DATA_ROOT  ', DATA_ROOT)
print('OUTPUT_DIR ', OUTPUT_DIR)
print('SEEDS      ', SEEDS)
"""

DEPENDENCIES = """\
import importlib.util, subprocess

REQUIRED = {'numpy': 'numpy', 'pandas': 'pandas', 'yaml': 'pyyaml', 'sklearn': 'scikit-learn',
            'scipy': 'scipy', 'torch': 'torch', 'matplotlib': 'matplotlib'}
missing = [package for module, package in REQUIRED.items() if importlib.util.find_spec(module) is None]
if missing:
    print('Installing', missing)
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', *missing])
else:
    print('All dependencies are present')
"""

ENVIRONMENT = """\
import multiprocessing, platform
import numpy, pandas, scipy, sklearn, torch

try:
    ram_gb = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 1024**3
except (AttributeError, ValueError, OSError):
    ram_gb = float('nan')
cpus = multiprocessing.cpu_count()
AE_DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'

print(f'platform     {platform.platform()}')
print(f'python       {platform.python_version()}')
print(f'numpy        {numpy.__version__}')
print(f'pandas       {pandas.__version__}')
print(f'scipy        {scipy.__version__}')
print(f'scikit-learn {sklearn.__version__}')
print(f'torch        {torch.__version__}')
print(f'cpus         {cpus}')
print(f'ram_gb       {ram_gb:.1f}')
print(f'ae_device    {AE_DEVICE}')
if ram_gb < 12:
    print('WARNING: under 12 GB of RAM. If the run crashes, lower MAX_TRAIN_PER_FAMILY '
          'and use a new OUTPUT_DIR.')
"""

CONFIG = """\
import tempfile
from aegis.config import AutoencoderConfig, BaselineConfig, DatasetConfig, RandomForestConfig
from aegis.experiments.baseline import phase1_gate, prepare_datasets, run

check_config = BaselineConfig(
    datasets=(DatasetConfig(kind='synthetic', name='synthetic_a', seed=11),),
    seeds=(0,), cross_dataset=False, max_train_per_family=5000, min_family_count=100,
    target_fprs=TARGET_FPRS, attack_prevalences=ATTACK_PREVALENCES,
    bootstrap_samples=200,
    rf=RandomForestConfig(n_estimators=20, max_depth=10, n_jobs=cpus),
    autoencoder=AutoencoderConfig(hidden=(32,), latent=8, epochs=5, batch_size=256, device=AE_DEVICE),
)
with tempfile.TemporaryDirectory() as folder:
    prepared_check = prepare_datasets(check_config)
    check_results = run(check_config, folder, prepared=prepared_check)
    check_gate = phase1_gate(check_results, prepared_check[0], check_config)
assert check_gate['complete'].all(), 'The pipeline check did not measure every family'
print('Pipeline check passed on generated data. These numbers say nothing about real traffic.')
"""

LOCATE = """\
from aegis.data.loaders import locate_data

located = locate_data(DATA_ROOT) if os.path.isdir(DATA_ROOT) else {}
for name, folder in located.items():
    print(f'{name}: {folder}')
if len(located) < 2:
    absent = sorted({'cicids2017', 'unsw_nb15'} - set(located))
    raise FileNotFoundError(
        f'Could not find {absent} under {DATA_ROOT}. See the first cell for the expected files.'
    )

config = BaselineConfig(
    datasets=(
        # A port identifies the service, so it can stand in for the attack family.
        DatasetConfig(kind='cicids2017', path=str(located['cicids2017']),
                      drop_columns=('Destination Port',)),
        DatasetConfig(kind='unsw_nb15', path=str(located['unsw_nb15'])),
    ),
    seeds=tuple(SEEDS),
    cross_dataset=RUN_CROSS_DATASET,
    max_train_per_family=MAX_TRAIN_PER_FAMILY,
    min_family_count=MIN_FAMILY_COUNT,
    target_fprs=TARGET_FPRS,
    attack_prevalences=ATTACK_PREVALENCES,
    rf=RandomForestConfig(n_estimators=100, max_depth=20, min_samples_leaf=2, n_jobs=cpus),
    autoencoder=AutoencoderConfig(device=AE_DEVICE),
)
"""

DATA_CHECK = """\
import pandas as pd
from aegis.data.dataset import column_report
from aegis.data.splits import eligible_families

pd.set_option('display.max_rows', 200, 'display.width', 180, 'display.max_columns', 40)

prepared = prepare_datasets(config)
datasets, cleaning = prepared
for ds in datasets:
    stats = cleaning[ds.name]
    print(f'=== {ds.name} ===')
    print(f"rows {stats['rows_before']:,} -> {stats['rows_after']:,} after cleaning; "
          f"{stats['rows_conflicting_labels']:,} rows had conflicting labels")
    print(f'{ds.X.shape[1]} feature columns; categorical: {list(ds.categorical) or None}')
    held = eligible_families(ds.family, config.min_family_count)
    counts = pd.Series(ds.family_counts(), name='rows').sort_values(ascending=False).to_frame()
    counts['held_out'] = [name in held for name in counts.index]
    display(counts)
    report = column_report(ds)
    flagged = report[(report['missing_share'] > 0) | (report['negative_share'] > 0) | report['constant']]
    print('Columns with missing values, negative values or a single value:')
    display(flagged.round(4))
"""

UNITS = """\
# Compare typical benign values to catch a wrong unit conversion. The datasets differ, but
# a gap of around 1000x on a time feature would point to a unit error rather than traffic.
# 'review' marks gaps over 100x and undefined ratios for a closer look. It is not a verdict.
from aegis.data.dataset import BENIGN
from aegis.data.loaders import project_to_shared

units = pd.DataFrame({
    shared.name: shared.X[shared.family == BENIGN].median()
    for shared in map(project_to_shared, datasets)
})
units['ratio'] = units.iloc[:, 0] / units.iloc[:, 1]
units['review'] = ~units['ratio'].between(0.01, 100)
display(units.round(4))
print('Features to review:', list(units.index[units['review']]) or 'none')
"""

RUN = """\
import time

started = time.time()
results = run(config, OUTPUT_DIR, prepared=prepared, extra_manifest={'source_version': SOURCE_VERSION})
print(f'Finished in {(time.time() - started) / 3600:.2f} h this session; {len(results):,} result rows')
"""

GATE = """\
gate = phase1_gate(results, datasets, config)
display(gate)
print('PHASE 1 GATE:', 'MET' if gate['complete'].all() else 'NOT MET: some families are missing seeds')
print('The gate requires the measurement to exist. It says nothing about how good the scores are.')
"""

TABLES = """\
seed_count = len(config.seeds)
if seed_count < 6:
    print(f'NOTE: with {seed_count} seeds the smallest possible two-sided Wilcoxon p-value is '
          f'{2 / 2**seed_count:.4f}, so p_wilcoxon cannot fall below 0.05. Read the intervals and '
          'effect sizes, or add seeds to SEEDS and run again with the same OUTPUT_DIR.')
print('These p-values are not corrected for testing many families, scorers and FPRs, so one '
      'value below 0.05 is not by itself a claim.')

primary_fpr = config.target_fprs[0]
degradation = pd.read_csv(f'{OUTPUT_DIR}/degradation.csv')
summary = pd.read_csv(f'{OUTPUT_DIR}/summary.csv')

test_rows = (results[results['fold'].str.startswith('holdout:')]
             .groupby(['dataset', 'eval_family'])['n_attack'].first().rename('test_attack_rows'))

for scorer in ('fused', 'rf', 'ae'):
    table = degradation[(degradation['scorer'] == scorer) & (degradation['target_fpr'] == primary_fpr)]
    table = table.join(test_rows, on=['dataset', 'eval_family'])
    print(f'Recall on the same test flows, seen vs held out: {scorer} scorer, target FPR {primary_fpr:g}')
    display(table[['dataset', 'eval_family', 'test_attack_rows', 'recall_seen_mean', 'recall_heldout_mean',
                   'mean_diff', 'ci_low', 'ci_high', 'p_wilcoxon', 'cohen_dz', 'n']].round(3))
"""

CHART = """\
import matplotlib.pyplot as plt

SEEN, HELD_OUT = '#2a78d6', '#eb6834'  # Validated categorical slots 1 and 2.
SURFACE, INK, MUTED, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#e4e3df'

view = degradation[(degradation['scorer'] == 'fused') & (degradation['target_fpr'] == primary_fpr)]
intervals = summary[(summary['scorer'] == 'fused') & (summary['target_fpr'] == primary_fpr)
                    & summary['fold'].str.startswith('holdout:')]
names = list(view['dataset'].unique())
fig, axes = plt.subplots(len(names), 1, squeeze=False, facecolor=SURFACE,
                         figsize=(8.5, 1.4 + sum(0.45 * (view['dataset'] == n).sum() for n in names)),
                         gridspec_kw={'height_ratios': [max((view['dataset'] == n).sum(), 1) for n in names]})

for axis, name in zip(axes[:, 0], names):
    part = view[view['dataset'] == name].sort_values('recall_heldout_mean')
    limits = intervals[intervals['dataset'] == name].set_index('eval_family')
    axis.set_facecolor(SURFACE)
    for y, row in enumerate(part.itertuples()):
        axis.plot([row.recall_seen_mean, row.recall_heldout_mean], [y, y], color=GRID, lw=2, zorder=1)
        low, high = limits.loc[row.eval_family, ['recall_ci_low', 'recall_ci_high']]
        axis.plot([low, high], [y, y], color=HELD_OUT, lw=2, alpha=0.45, zorder=2)
    y = range(len(part))
    # Seen is an open ring around a smaller dot, so equal values still show both marks.
    axis.scatter(part['recall_heldout_mean'], y, s=40, color=HELD_OUT, zorder=3, label='Family held out (95% CI across seeds)')
    axis.scatter(part['recall_seen_mean'], y, s=120, facecolors='none', edgecolors=SEEN, lw=2, zorder=4, label='Family seen in training')
    axis.set_yticks(list(y), part['eval_family'], color=INK)
    axis.set_xlim(-0.02, 1.02)
    axis.set_ylim(-0.6, len(part) - 0.4)
    axis.set_title(name, loc='left', color=INK, fontsize=11, fontweight='bold')
    axis.grid(axis='x', color=GRID, lw=0.8)
    axis.set_axisbelow(True)
    axis.tick_params(length=0, colors=MUTED)
    for side in axis.spines.values():
        side.set_visible(False)

axes[-1, 0].set_xlabel(f'Recall on the same test flows, fused score, target FPR {primary_fpr:g}', color=MUTED)
axes[0, 0].legend(loc='lower center', bbox_to_anchor=(0.5, 1.12), ncols=2, frameon=False, labelcolor=INK)
fig.tight_layout()
fig.savefig(f'{OUTPUT_DIR}/seen_vs_heldout_recall.png', dpi=160, facecolor=SURFACE, bbox_inches='tight')
plt.show()
"""

CALIBRATION = """\
# Recall only means something at the false-positive rate actually reached. A realized FPR far
# from the target means the threshold drifted, and recall_at_oracle_fpr shows the ranking alone.
holdout = summary[summary['fold'].str.startswith('holdout:') & (summary['scorer'] == 'fused')]
columns = ['dataset', 'eval_family', 'target_fpr', 'realized_fpr_mean', 'recall_mean', 'recall_at_oracle_fpr_mean']
columns += [c for c in holdout.columns if c.startswith(('pr_auc_prev_', 'precision_prev_')) and c.endswith('_mean')]
display(holdout[columns].round(4))

cost = results.groupby(['dataset', 'fold'])['fit_seconds'].first().groupby('dataset').describe()
print('Seconds per fit:')
display(cost[['count', 'mean', 'max']].round(0))

if RUN_CROSS_DATASET:
    display(summary[summary['fold'].str.startswith('cross:')].round(4))
"""

PACKAGE = """\
import zipfile

archive = f'{OUTPUT_DIR}/aegis_config_a_results.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name in ('manifest.json', 'results.csv', 'summary.csv', 'degradation.csv', 'seen_vs_heldout_recall.png'):
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
            new_code_cell(DEPENDENCIES),
            embedded_source_cell(),
            new_code_cell(ENVIRONMENT),
            new_markdown_cell("## 3. Check the pipeline on generated data\nTakes about a minute, so a broken setup fails before the long run."),
            new_code_cell(CONFIG),
            new_markdown_cell("## 4. Find and check the real data\nThe loaders were only tested on small hand-written files, so these outputs are the first check against the real downloads."),
            new_code_cell(LOCATE),
            new_code_cell(DATA_CHECK),
            new_code_cell(UNITS),
            new_markdown_cell("## 5. Run Config A\nThis is the long step. A progress line appears after each fold, with an estimate of the time left."),
            new_code_cell(RUN),
            new_markdown_cell("## 6. Phase 1 gate"),
            new_code_cell(GATE),
            new_markdown_cell("## 7. Results"),
            new_code_cell(TABLES),
            new_code_cell(CHART),
            new_code_cell(CALIBRATION),
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
    print(f"Wrote {OUTPUT} (source version {source_hash()})")


if __name__ == "__main__":
    main()
