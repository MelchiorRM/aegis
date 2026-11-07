# Aegis

Aegis is a research project on adaptive cyber defense. It asks one question: does
co-training a defender against adaptive attackers, combined with opponent modeling, help
it detect attack families it has never seen?

> **Status: early-stage research.** The baseline defender (Config A) is implemented and
> tested, but it has only been run on generated data. There are no results on real traffic
> yet, so this repository makes no performance claims.

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
| A | Static Random Forest + autoencoder | None | No | Baseline |
| B | Static Random Forest + autoencoder | Fixed adversarial scenarios | No | Adversarial data alone |
| C | Adaptive | RL + historical league | No | Co-training |
| D | Adaptive | RL + historical league | Yes | Opponent modeling |
| E | Adaptive | RL, no historical league | Yes | Opponent modeling without the league |

Config A takes its model design from Agrawal et al. (*Scientific Reports* 16:11673, 2026).
It is not a replication, because that paper does not release its preprocessing or model
settings.

## Roadmap

Each phase closes on a measurement, not a date.

- [ ] **Phase 1, foundation and baseline:** code complete; waiting on Config A measurements on real held-out families
- [ ] **Phase 2, fixed adversarial scenarios:** traffic realization layer, scripted attacker, Config B
- [ ] **Phase 3, co-training:** RL attacker, historical league, Config C
- [ ] **Phase 4, opponent modeling:** prediction models, Configs D and E
- [ ] **Phase 5, evaluation and write-up:** cross-dataset tests, sensitivity analysis, statistics

## How Config A is evaluated

- **No leakage:** duplicates are removed and the data is split before the imputer, scaler
  and encoder are fit on training rows only. Class weights replace SMOTE.
- **Unseen families:** each eligible attack family is removed from training and validation,
  then its recall is compared with a model that saw it, on the same test flows.
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

After changing anything in `src/`, rebuild the notebook. A test fails if it is out of date:

```bash
.venv/bin/python notebooks/build_notebook.py
```

## Repository layout

| Path | Contents |
| --- | --- |
| `src/aegis/data/` | Dataset loaders, cleaning and leakage-controlled splits |
| `src/aegis/models/` | Random Forest + autoencoder defender |
| `src/aegis/evaluation/` | Detection metrics and paired statistics |
| `src/aegis/experiments/` | Resumable experiment runner |
| `configs/` | Experiment settings |
| `notebooks/` | Full-run notebook and the script that builds it |
| `tests/` | Test suite |

## Safety

Attackers run only in controlled simulation or an explicitly authorized isolated lab, never
against public networks or unauthorized systems.
