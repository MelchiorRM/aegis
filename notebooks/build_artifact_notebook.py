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
# Aegis v2: artifact-resistance and sensitivity audit

This run audits the Random Forest baseline. **It is not an unbiased estimate of final
generalization:** the baseline was chosen using these same test results, and no untouched evaluation
set is involved. Phase 1 stays open until this audit is reported.

Every treatment refits the baseline on the same folds and is scored on identical held-out rows. Raw
published rows give the primary recall. Two secondary views follow: raw rows without feature vectors
that carry several attack families, and deduplicated rows. No label is changed.

| Treatment | Question |
| --- | --- |
| `remove_matching_signatures` | Does the model rely on near-duplicates of the held-out family? |
| `no_tcp_window` | Does the model rely on host-specific TCP fingerprints? |
| `neutralize_missing_markers`, `missingness_only` | Is a missing-value marker itself a shortcut? |
| `service_marker_only` | With the reference and column removal, what does UNSW-NB15 take from `service`? |
| `no_context_counts` | How much does UNSW-NB15 depend on its `ct_*` counts? |
| `all_controls` | What remains with signatures, TCP windows and markers all controlled? |
| `exclude_suspect_benign` | Do the possibly mislabeled benign rows of the original CICIDS2017 release change the result? (Not run on the improved release.) |
| `no_extractor_features` | **Exploratory** (pre-registration section 6.2): with the TCP window and seven columns the fixed CICFlowMeter adds or redefines removed, how much held-out recall remains? Improved release only; reported apart from every rule count. |

**Two modes** (`MODE` in the settings cell):
- `exploratory` (default): the pre-registered development run of `no_extractor_features`. Improved CICIDS2017
  only, seeds 0–4, treatments `reference`, `no_tcp_window` and `no_extractor_features`. The reference and
  `no_tcp_window` rows must reproduce the recorded audit (`RECORDED_DIR`) exactly, or the notebook stops. The five
  recorded shortcut verdicts are not re-evaluated.
- `full`: every treatment on both datasets, as in the recorded audit.

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

# 'exploratory': the pre-registered development run of no_extractor_features (section 6.2). 'full': every treatment.
MODE = os.environ.get('AEGIS_MODE', 'exploratory')
if MODE not in ('exploratory', 'full'):
    raise ValueError(f'MODE must be exploratory or full, not {MODE!r}')
EXPLORATORY_TREATMENTS = ('no_tcp_window', 'no_extractor_features')
# The recorded improved-release audit the exploratory run must reproduce.
RECORDED_DIR = os.environ.get('AEGIS_RECORDED_DIR', OUTPUT_DIR)
if MODE == 'exploratory':
    OUTPUT_DIR = os.environ.get('AEGIS_EXPLORATORY_DIR', OUTPUT_DIR.replace('config_a_artifacts', 'config_a_exploratory'))
    if os.path.realpath(OUTPUT_DIR) == os.path.realpath(RECORDED_DIR):
        raise ValueError('OUTPUT_DIR must be a new folder, separate from the recorded audit')
    print('MODE        exploratory: improved CICIDS2017, treatments', EXPLORATORY_TREATMENTS)
    print('RECORDED   ', RECORDED_DIR)
    print('OUTPUT_DIR ', OUTPUT_DIR)
else:
    print('MODE        full')
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

RESTRICT = """\
from dataclasses import replace

if MODE == 'exploratory':
    config = replace(config, datasets=tuple(d for d in config.datasets if d.kind == 'cicids2017_improved'))
    recorded_results = os.path.join(RECORDED_DIR, 'results.csv')
    if not os.path.exists(recorded_results):
        raise FileNotFoundError(f'The exploratory run must reproduce the recorded audit; put its results.csv in {RECORDED_DIR}')
    if list(config.seeds) != [0, 1, 2, 3, 4]:
        print('NOTE: the pre-registered development run uses seeds 0-4; these seeds are for testing only:', config.seeds)
print('Datasets:', [d.kind for d in config.datasets], 'seeds:', list(config.seeds))
"""

RUN = """\
import time

started = time.time()
results = run_artifacts(config, OUTPUT_DIR, extra_manifest={'source_version': SOURCE_VERSION, 'mode': MODE},
                        treatments=EXPLORATORY_TREATMENTS if MODE == 'exploratory' else None)
print(f'Finished in {(time.time() - started) / 3600:.2f} h this session; {len(results)} result rows')
"""

REPRODUCE = """\
import pandas as pd
from aegis.experiments.artifacts import check_matches_recorded

if MODE == 'exploratory':
    compared = check_matches_recorded(results, pd.read_csv(os.path.join(RECORDED_DIR, 'results.csv')),
                                      ('reference', 'no_tcp_window'))
    print(f'Reproduced the recorded audit exactly: {compared} reference and no_tcp_window rows.')
else:
    print('Full mode: no recorded run to reproduce.')
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
if MODE == 'full':
    pd.set_option('display.max_rows', 300, 'display.width', 200, 'display.max_columns', 40)
    primary_fpr = config.target_fprs[0]
    main = results[results['target_fpr'] == primary_fpr]
    reference = main[main['treatment'] == 'reference']
    effects = pd.read_csv(f'{OUTPUT_DIR}/treatment_effects.csv')
    effects = effects[effects['target_fpr'] == primary_fpr]
    with open(f'{OUTPUT_DIR}/shortcut_rule.json', encoding='utf-8') as handle:
        rule = json.load(handle)
    EFFECT_COLUMNS = ['dataset', 'family', 'treatment', 'raw_recall_reference', 'raw_recall_treated', 'mean_diff',
                      'ci_low', 'ci_high', 'rule_testable', 'shortcut_dependent']


    def show_effects(title, treatments, family=None):
        # mean_diff is reference minus treated raw recall, so a negative value is recall gained.
        print(title)
        table = effects[effects['treatment'].isin(treatments)]
        if family is not None:
            table = table[table['family'] == family]
        display(table[EFFECT_COLUMNS].round(3))


    print('This is a sensitivity audit, not an unbiased generalization estimate.')
    show_effects('1. Web attack recall after signature removal', ['remove_matching_signatures'], 'web_attack')

    print('2. PortScan on raw published rows, reference treatment')
    display(reference[reference['family'] == 'portscan'].groupby('dataset')[
        ['raw_recall', 'recall', 'raw_recall_at_oracle_fpr', 'raw_fpr', 'raw_distinct_recall',
         'raw_conflicting_share', 'raw_attack_rows']].mean().round(3))

    show_effects('3. Sensitivity to TCP window features', ['no_tcp_window'])
    show_effects('4. Signal through markers (missingness_only sees nothing else)',
                 ['neutralize_missing_markers', 'missingness_only'])
    print('4b. UNSW-NB15 service: kept with its catch-all value, removed, or reduced to one flag')
    service = main[(main['dataset'] == 'unsw_nb15')
                   & main['treatment'].isin(['reference', 'neutralize_missing_markers', 'service_marker_only'])]
    display(service.pivot_table(index='family', columns='treatment', values='raw_recall').round(3))
    show_effects('5. Removing ct_* context counts', ['no_context_counts'])
    show_effects('6. all_controls across unseen attack families', ['all_controls'])

    print('7. Possibly mislabeled benign rows: original labels are primary, and this run excludes them')
    print('Attack rows are identical to the reference. Benign rows differ by design, so raw_fpr is shown too.')
    suspect = effects[effects['treatment'] == 'exclude_suspect_benign']
    display(suspect[['dataset', 'family', 'raw_recall_reference', 'raw_recall_treated', 'mean_diff', 'ci_low', 'ci_high']].round(3))
    # The suspect rows are listed for the original CICIDS2017 release only, so other datasets have no such run.
    if suspect.empty:
        print('No dataset in this run has a suspect benign list, so this check was skipped.')
    else:
        display(main[main['treatment'].isin(['reference', 'exclude_suspect_benign'])
                     & main['dataset'].isin(suspect['dataset'].unique())].pivot_table(
            index=['dataset', 'family'], columns='treatment', values=['raw_fpr', 'raw_benign_rows']).round(4))

    print('8. Three evaluation views, reference treatment: raw rows (primary), without attack-label overlaps, deduplicated')
    display(reference.groupby(['dataset', 'family'])[
        ['raw_recall', 'overlap_excluded_recall', 'recall', 'raw_attack_overlap_share', 'raw_attack_rows',
         'overlap_excluded_attack_rows', 'raw_fpr', 'overlap_excluded_fpr', 'raw_conflicting_share']
    ].mean().round(3))
    print('Recall by whether a test flow matches a training attack apart from timing, reference treatment')
    display(reference.groupby(['dataset', 'family'])[
        ['signature_matched_rows', 'n_attack', 'recall_signature_matched', 'recall_signature_unmatched']].mean().round(3))

    print('Shortcut-dependent results: mean paired raw-recall drop of at least 0.10, with the 95% interval above zero')
    display(effects[effects['shortcut_dependent']][EFFECT_COLUMNS].round(3))
    print(f"Comparisons under the rule: {rule['n_comparisons']} {rule['n_comparisons_by_dataset']}, with no "
          f"multiple-comparison correction. {rule['n_shortcut_dependent']} flagged.")
    print(f"{rule['n_not_testable']} comparisons cannot trigger the rule, because reference recall is already under 0.10:")
    display(effects[(effects['role'] == 'rule') & ~effects['rule_testable']][['dataset', 'family', 'treatment', 'raw_recall_reference']].round(3))
    print('Flagged without attack-label overlaps (secondary):')
    display(effects[effects['overlap_shortcut_dependent']][
        ['dataset', 'family', 'treatment', 'overlap_excluded_recall_reference', 'overlap_excluded_recall_treated',
         'overlap_mean_diff', 'overlap_ci_low', 'overlap_ci_high']].round(3))
    print('Flagged on deduplicated rows instead (secondary):')
    display(effects[effects['dedup_shortcut_dependent']][
        ['dataset', 'family', 'treatment', 'recall_reference', 'recall_treated', 'dedup_mean_diff', 'dedup_ci_low', 'dedup_ci_high']].round(3))
    print('With five seeds the paired test cannot reach p < 0.05. Read the intervals and effect sizes.')
"""

EXPLORATORY_TABLES = """\
import json
pd.set_option('display.max_rows', 300, 'display.width', 200, 'display.max_columns', 40)
path = f'{OUTPUT_DIR}/exploratory_effects.csv'
if os.path.exists(path):
    print('EXPLORATORY (pre-registration 6.2). Not part of any shortcut count or verdict.')
    print('A drop means dependence on extractor-specific features, not proof of an artifact.')
    explore = pd.read_csv(path)
    explore = explore[explore['target_fpr'] == config.target_fprs[0]]
    columns = ['dataset', 'family', 'comparison', 'raw_recall_reference', 'raw_recall_treated', 'mean_diff', 'ci_low',
               'ci_high', 'exploratory_rule_met', 'dedup_mean_diff', 'dedup_ci_low', 'dedup_ci_high']
    print('Against the reference (same rule thresholds, no verdict):')
    display(explore[explore['comparison'] == 'reference'][columns].round(3))
    print('Against no_tcp_window (descriptive: the seven extractor columns once the window is gone):')
    display(explore[explore['comparison'] == 'no_tcp_window'][columns[:8] + columns[9:]].round(3))
    with open(f'{OUTPUT_DIR}/shortcut_rule.json', encoding='utf-8') as handle:
        rule = json.load(handle)
    print('Rule comparisons in this run:', rule['n_comparisons'], '| exploratory treatments not counted:',
          rule['exploratory_treatments_not_counted'])
else:
    print('No exploratory treatment ran on these datasets.')
"""

PACKAGE = """\
import zipfile

archive = f'{OUTPUT_DIR}/aegis_artifact_results.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name in ('manifest.json', 'results.csv', 'treatment_effects.csv', 'shortcut_rule.json', 'exploratory_effects.csv'):
        if os.path.exists(f'{OUTPUT_DIR}/{name}'):
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
            new_code_cell(RESTRICT),
            new_markdown_cell("## 5. Run the experiments\nThis is the long step. A progress line appears after each fold."),
            new_code_cell(RUN),
            new_markdown_cell("## 6. Reproduce the recorded audit and compare with Config A"),
            new_code_cell(REPRODUCE),
            new_code_cell(COMPARE),
            new_markdown_cell("## 7. Results"),
            new_code_cell(TABLES),
            new_markdown_cell("## 8. Exploratory treatment"),
            new_code_cell(EXPLORATORY_TABLES),
            new_markdown_cell("## 9. Package the results"),
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
