# Aegis

Aegis is a research project on adaptive cyber defense. It asks one question: does
co-training a defender against adaptive attackers, combined with opponent modeling, help
it detect attack families it has never seen?

> **Status: early-stage research.** The baseline defender (Config A) has been measured on
> CICIDS2017 and UNSW-NB15 held-out families and audited for shortcuts. The audit found five distinct
> shortcut dependencies in those scores, so this repository makes no performance claims. Config A is
> now being re-measured on the improved CICIDS2017 release, which corrects known label and
> feature-extraction errors, and is frozen on that data before any result exists.

## Research foundation

1. **Leakage-free evaluation:** attack families are excluded from training and validation.
2. **Artifact-resistant evaluation:** investigate duplicates, host fingerprints, feature shortcuts
   and mislabeled traffic, to establish whether apparent generalization is genuine.
3. **Robust baseline:** a reliable Random Forest baseline with controlled preprocessing.
4. **Adaptive adversarial training:** does co-training help on genuinely unfamiliar attacks?
5. **Opponent modeling:** does predicting an adaptive opponent add to historical opponent pools?

## Research questions

| ID | Question |
| --- | --- |
| RQ1 | Does training against adaptive attackers reduce performance loss on unseen attack families, compared with a static supervised defender? |
| RQ2 | Does opponent modeling improve defense beyond adversarial training against a league of past opponents? |
| RQ3 | Do any gains carry over across datasets and environments, at realistic benign prevalence and response costs? |

These are hypotheses to test, and a rigorous null result is still worth reporting. The full
design is in the [v2 specification](Aegis%20v2%20Adaptive%20Cyber%20Defense%20Through%20Adversarial%20Learning%20and%20Opponent%20Modeli.md),
which replaced the broader [v1 vision](Aegis%20v1%20An%20Adaptive%20AI%20Cybersecurity%20Research%20System.md).

## Experimental design

Five configurations separate the effect of each component:

| Config | Defender | Attacker training | Opponent modeling | Isolates |
| --- | --- | --- | --- | --- |
| A | Static Random Forest | None | No | Baseline |
| B | Static Random Forest | Fixed adversarial scenarios | No | Adversarial data alone |
| C | Adaptive | RL + historical league | No | Co-training |
| D | Adaptive | RL + historical league | Yes | Opponent modeling |
| E | Adaptive | RL, no historical league | Yes | Opponent modeling without the league |

Config A takes its model design from Agrawal et al. (*Scientific Reports* 16:11673, 2026).
It is not a replication, because that paper does not release its preprocessing or model
settings. The autoencoder and fused scores are still measured for comparison, but the Random
Forest score is the baseline: it was the strongest of the three on held-out families. That
choice was made after seeing test results, so it was re-checked with the nested protocol later
configurations must use, which never reads test rows. The fixed rule picked the Random Forest in 49 of
65 outer folds and the fused score in the other 16, usually by small margins. It never picked the
autoencoder. Config A is now frozen: its settings and the code that implements it are fingerprinted,
and any change counts as a new baseline.

## Roadmap

Each phase closes on a measurement, not a date.

- [ ] **Phase 1, foundation and baseline:** Config A measured, audited and re-checked by nested selection on the original CICIDS2017; re-freezing on the improved release; open until Config A, the audit and the selection check are rerun on it and the external test set's pre-registration is written
- [ ] **Phase 2, fixed adversarial scenarios:** traffic realization layer, scripted attacker, Config B
- [ ] **Phase 3, co-training:** RL attacker, historical league, Config C
- [ ] **Phase 4, opponent modeling:** prediction models, Configs D and E
- [ ] **Phase 5, evaluation and write-up:** cross-dataset tests, sensitivity analysis, statistics

## How Config A is evaluated

- **No leakage:** duplicates are removed and the data is split before the imputer, scaler
  and encoder are fit on training rows only. Class weights replace SMOTE.
- **Unseen families:** each eligible attack family is removed from training and validation,
  then its recall is compared with a model that saw it, on the same test flows.
- **Dataset shortcuts:** a sensitivity audit of the selected baseline, not an unbiased estimate of
  generalization. Each treatment refits the baseline on the same folds, in its own output folder,
  and is scored on identical held-out rows: near-duplicates removed, TCP windows removed, markers
  neutralized, UNSW-NB15 `ct_*` counts removed, and those controls combined. A result is
  shortcut-dependent only if the mean per-seed recall drop is at least 0.10 and its 95% interval lies
  above zero. Five dependencies met this rule: web attack on near-duplicates, CICIDS2017 DoS on TCP
  windows, UNSW-NB15 shellcode and reconnaissance on `ct_*` counts, and generic on `service`.
- **Evaluation views:** recall on raw published rows is primary. Two secondary views leave out
  feature vectors labelled with several attack families, and all repeated or conflicting rows.
- **Attempted flows:** the improved CICIDS2017 marks attack flows that carried no malicious behaviour
  as "Attempted". They are never trained on and are left out of the primary metric. A secondary
  metric counts them as benign, to show how often they would raise alarms.
- **Labels:** no label is changed. 38,045 CICIDS2017 benign rows that may be attack replies stay in
  the primary evaluation, and a separate run reports the effect of excluding them.
- **Model selection:** CICIDS2017 and UNSW-NB15 are now development data. Any choice between models
  or scores is made by inner leave-one-family-out on training and validation rows only, with the rule
  fixed in advance. A challenger replaces the default only if its mean inner recall is higher and it
  beats the default on a strict majority of inner families. The majority condition was added after the
  Config A re-check, where a single large inner win was enough to pick a score that then did worse.
- **Final claims:** come only from a dataset not yet loaded, evaluated once. Every decision made on
  the development data was informed by its results, so scores there are optimistic. An untouched
  dataset gives an honest estimate only if the analysis is fixed before it is opened: the metric,
  evaluation views, comparisons, family mapping and treatment of attempted attacks. The pre-registration
  records these choices first, so none of them can be made after seeing results. The loader refuses
  the external dataset unless a pre-registration names it and the code still matches the frozen
  Config A, and it logs every attempt.
- **Thresholds:** set from validation benign traffic only, with the false-positive rate
  actually reached reported alongside.
- **Realistic prevalence:** PR-AUC and precision are reweighted to assumed attack shares of
  1% and 0.1%. These shares are assumptions, not measurements.
- **Statistics:** results across seeds, with bootstrap confidence intervals, Wilcoxon paired
  tests and effect sizes.

## Getting started

Requires Python 3.11 or later.

```bash
python3 -m venv .venv
.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

`requirements.lock` records the exact package versions used in development (Python 3.12 on
Linux, CPU-only torch).

Check the pipeline end to end on generated data. This confirms that it runs, and says
nothing about real traffic:

```bash
.venv/bin/python -m aegis.experiments.baseline --config configs/smoke.yaml --out results/smoke
```

## Running on real data

Datasets are not included. Download them from their publishers and place the CSV files here:

| Dataset | Location | Files |
| --- | --- | --- |
| CICIDS2017, improved release ([CNS 2022](https://intrusion-detection.distrinet-research.be/CNS2022/)) | `data/cicids2017_improved/` | `monday.csv` to `friday.csv` |
| UNSW-NB15 | `data/unsw_nb15/` | `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` |

Full runs use [notebooks/config_a_baseline.ipynb](notebooks/config_a_baseline.ipynb), which
embeds the package source and can run on Colab or Kaggle without a clone. Use a machine with
more than 12 GB of RAM. Interrupted runs continue from the last finished fold.
[notebooks/artifact_resistance.ipynb](notebooks/artifact_resistance.ipynb) runs the shortcut
audit the same way and writes to `results/config_a_artifacts`, leaving Config A results alone.
[notebooks/selection_check.ipynb](notebooks/selection_check.ipynb) runs the nested selection check
and refuses to start unless the settings and code match the frozen Config A.

After changing anything in `src/`, rebuild the notebooks. A test fails if any is out of date:

```bash
.venv/bin/python notebooks/build_notebook.py
.venv/bin/python notebooks/build_artifact_notebook.py
.venv/bin/python notebooks/build_selection_notebook.py
```

Check whether the current code still matches the frozen Config A:

```bash
.venv/bin/python -m aegis.frozen
```

Re-freezing (`--write`) defines a new baseline. Do it only with a recorded reason.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/aegis/data/` | Dataset loaders, cleaning, leakage-controlled splits and the guarded external-test loader |
| `src/aegis/models/` | Random Forest baseline and autoencoder comparison scores |
| `src/aegis/evaluation/` | Detection metrics and paired statistics |
| `src/aegis/experiments/` | Resumable experiment runner, shortcut audit and nested selection |
| `src/aegis/frozen.py` | The frozen Config A identity and its check |
| `configs/` | Experiment settings |
| `notebooks/` | Full-run notebooks and the scripts that build them |
| `docs/` | Assessment of the proposed external test set |
| `tests/` | Test suite |

## Safety

Attackers run only in controlled simulation or an explicitly authorized isolated lab, never
against public networks or unauthorized systems.
