# Aegis

Aegis is a research project on adaptive cyber defense. It asks one question: does
co-training a defender against adaptive attackers, combined with opponent modeling, help
it detect attack families it has never seen?

> **Status: early-stage research.** The baseline defender (Config A) has been measured on
> CICIDS2017 and UNSW-NB15 held-out families. An audit found that some of those scores depend
> on dataset artifacts, so this repository makes no performance claims.

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
choice was made after seeing test results.

## Roadmap

Each phase closes on a measurement, not a date.

- [ ] **Phase 1, foundation and baseline:** Config A measured on real held-out families; stays open until the artifact audit is complete
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
  neutralized, UNSW-NB15 `ct_*` counts removed, and those controls combined. Raw published rows are
  primary, and deduplicated rows are secondary. A result is shortcut-dependent only if the mean
  per-seed recall drop is at least 0.10 and its 95% interval lies above zero.
- **Labels:** no label is changed. 38,045 CICIDS2017 benign rows that may be attack replies stay in
  the primary evaluation, and a separate run reports the effect of excluding them.
- **Final claims:** generalization claims need an untouched evaluation set or a nested protocol,
  which these results are not.
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
| CICIDS2017 | `data/cicids2017/` | The 8 `MachineLearningCVE` CSV files |
| UNSW-NB15 | `data/unsw_nb15/` | `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` |

Full runs use [notebooks/config_a_baseline.ipynb](notebooks/config_a_baseline.ipynb), which
embeds the package source and can run on Colab or Kaggle without a clone. Use a machine with
more than 12 GB of RAM. Interrupted runs continue from the last finished fold.
[notebooks/artifact_resistance.ipynb](notebooks/artifact_resistance.ipynb) runs the shortcut
audit the same way and writes to `results/config_a_artifacts`, leaving Config A results alone.

After changing anything in `src/`, rebuild both notebooks. A test fails if either is out of date:

```bash
.venv/bin/python notebooks/build_notebook.py
.venv/bin/python notebooks/build_artifact_notebook.py
```

## Repository layout

| Path | Contents |
| --- | --- |
| `src/aegis/data/` | Dataset loaders, cleaning and leakage-controlled splits |
| `src/aegis/models/` | Random Forest baseline and autoencoder comparison scores |
| `src/aegis/evaluation/` | Detection metrics and paired statistics |
| `src/aegis/experiments/` | Resumable experiment runner |
| `configs/` | Experiment settings |
| `notebooks/` | Full-run notebook and the script that builds it |
| `tests/` | Test suite |

## Safety

Attackers run only in controlled simulation or an explicitly authorized isolated lab, never
against public networks or unauthorized systems.
