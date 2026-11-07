# Aegis v2: Adaptive Cyber Defense Through Adversarial Learning and Opponent Modeling

Nov 7, 2026 · @Melchior Remilien

## Objective and positioning

Aegis v2 tests one question: does co-training a defender against adaptive attackers, combined with opponent modeling, improve generalization to unseen attack families while keeping detection performance and response cost acceptable?

It does not claim to invent multi-agent cybersecurity, adaptive attackers or intrusion detection. Its contribution is a leakage-controlled test of a hypothesis the baseline paper does not investigate: whether learning an opponent's evolving behavior yields a more generalizable defender than training against a fixed collection of attacks.

|  | Agrawal et al. (2026) | Aegis v2 |
| --- | --- | --- |
| Contribution | AI-driven multi-agent framework: adaptive attacker, anomaly detection, automated response in a cyber range | Experimental test of whether adaptive defender learning and opponent modeling improve generalization to unseen attack families |
| Evaluation | Random splits; static and rule-based baselines | Leakage-controlled splits, held-out attack families, cost and statistical controls |
| Scope | Broad system | One focused hypothesis, ablated |

## Research foundation

The work rests on five steps, in this order. Each depends on the one before it.

1. **Leakage-free evaluation:** attack families are excluded from training and validation.
2. **Artifact-resistant evaluation:** investigate duplicates, host fingerprints, feature shortcuts and mislabeled traffic, to establish whether apparent generalization is genuine or caused by dataset-specific shortcuts.
3. **Robust baseline:** establish a reliable Random Forest baseline using controlled preprocessing.
4. **Adaptive adversarial training:** investigate whether co-training improves performance on genuinely unfamiliar attacks.
5. **Opponent modeling:** investigate whether predicting an adaptive opponent provides benefits beyond historical opponent pools.

## Limitations of the baseline paper and the Aegis v2 fix

The paper (Agrawal et al., *Scientific Reports* 16:11673, 2026) reports a DQN attacker, an RF + autoencoder defender and fixed rule-based responses in CyDER 2.0. Its evaluation leaves these gaps, each addressed by a specific design choice here.

| # | Limitation in the paper | Aegis v2 fix |
| --- | --- | --- |
| 1 | Simulation and real data are disconnected: the defender trains on CICIDS2017/UNSW-NB15 flows, but the attacker acts through four abstract actions | Traffic realization layer: each attacker action samples a real attack flow and applies small, validity-constrained feature perturbations |
| 2 | Only the attacker learns; the defender is trained once and never adapts | Defender co-trains with the attacker against a league of past opponents |
| 3 | Attacker success (84.5%) and defender F1 (88-95%) are not reconciled; the opposing defender is not stated | Every attacker is evaluated against named, versioned defenders |
| 4 | SMOTE oversampling is listed before the train/test split, so leakage is possible | Split first, then resample or use class weights |
| 5 | Balanced \~50k-sample test set; real traffic is mostly benign | Evaluate PR-AUC and precision at realistic benign prevalence |
| 6 | "Hold-out" is a random split; no unseen attack families | Leave-one-attack-family-out and cross-dataset tests |
| 7 | Baselines are a static range and a hand-written rule-based MAS | Paper-inspired RF baseline, with RF + AE measured for comparison, plus an RL baseline from an existing environment |
| 8 | Cross-paper comparison table; "25+ agents" claimed, but runs use 2 attackers and 3 defenders per network | No cross-paper numeric comparisons; claims limited to what is run |
| 9 | Test counts, seeds and confidence intervals not reported | 5-10 seeds, bootstrap confidence intervals, paired tests for every claim |
| 10 | Response actions (quarantine, IP blocks) carry no cost, so false positives look free | Defender reward includes false-alarm, disruption and response costs |
| 11 | No released code; CyDER 2.0 not described; attacker modeled as a fully observed MDP | Public code and configs; partial observability stated explicitly |

The paper also has no generative component, no opponent modeling, no ablation and no cross-environment test.

## Research questions

Three connected questions, each independently measurable. Hypotheses are to be tested, not assumed.

| ID | Question | Hypothesis |
| --- | --- | --- |
| RQ1 | Does training a defender against adaptive attackers reduce its performance degradation on previously unseen attack families, compared with a static supervised defender? | H1: Co-trained defenders lose less recall on held-out families at equal false-positive rate. |
| RQ2 | Does opponent modeling improve defensive performance beyond adversarial training against a league of historical opponents? | H2: An opponent-aware defender outperforms an otherwise identical defender without opponent modeling. |
| RQ3 | Do the improvements transfer across datasets and simulation environments, and do they remain beneficial under realistic benign prevalence and response costs? | H3: Gains persist in cross-dataset tests, at realistic prevalence, and across a range of cost weights. |

A null result on any question is reportable if the evaluation is rigorous.

## Experimental configurations

Five configurations isolate the effect of adversarial training, the historical league and opponent modeling.

| Config | Defender | Attacker training | Opponent modeling | Isolates |
| --- | --- | --- | --- | --- |
| A | Static RF | None | No | Baseline |
| B | Static RF | Fixed adversarial scenarios | No | Value of adversarial data alone |
| C | Adaptive defender | RL + historical league | No | Value of co-training (RQ1) |
| D | Adaptive defender | RL + historical league | Yes | Value of opponent modeling (RQ2) |
| E | Adaptive defender | RL, no historical league | Yes | Opponent modeling without the league |

Configuration A originally used RF + AE. It was changed to the RF score after the Config A run, because RF was the strongest of the RF, AE and fused scores on held-out families; the choice used test results, so this must be disclosed. Configuration A is a paper-inspired baseline, not a replication. Exact replication is claimed only if the paper's preprocessing, model configuration and evaluation protocol can be reproduced; the paper does not release them, so deviations are documented.

## Metrics and defender reward

Each research question has one primary measurement; operational and prediction metrics are secondary.

| Objective | Primary measurement |
| --- | --- |
| RQ1 | Held-out-family recall at fixed false-positive rate |
| RQ2 | Difference in primary metrics with vs without opponent modeling |
| RQ3 | Cross-dataset performance; PR-AUC at realistic benign prevalence |
| Operational effectiveness | Response cost, detection time, containment success |
| Opponent prediction | Next-action accuracy and calibration |

The defender's reward accounts for security outcome and the cost of acting:

```latex
R_D = R_{security} - \lambda_1 C_{false\ alarm} - \lambda_2 C_{disruption} - \lambda_3 C_{response}
```

The weights λ1-λ3 are justified from stated operational assumptions and varied in a sensitivity analysis. They are not tuned to produce a favorable result, and conclusions must hold across the tested range or be reported as weight-dependent.

## Evaluation protocol

The protocol exists to stop two agents from becoming good only at playing each other.

- **Three environments:** training (both agents learn), validation (tune models and strategies), holdout (unseen scenarios, touched once at the end).
- **Leakage control:** split before any resampling; fit scalers and encoders on training data only; use class weights instead of SMOTE where possible.
- **Unseen families:** leave-one-attack-family-out on CICIDS2017 and UNSW-NB15; attack families in the holdout are never seen by the defender or the attacker's generator.
- **Artifact resistance:** a held-out result counts as generalization only after it is tested against dataset shortcuts. Each treatment refits the baseline on the same folds, in a separate output folder that preserves earlier results:
  - **Near-duplicates:** remove training attack rows that match the held-out family apart from timing.
  - **Duplicate handling:** compare recall on deduplicated rows with recall on all published rows.
  - **Host fingerprints:** remove TCP window features.
  - **Missingness:** neutralize missing-value markers, and test a model that sees only those markers.
  - **Combined:** apply the near-duplicate, TCP window and marker controls together.
- **Shortcut rule:** at the primary false-positive rate, a family's result is shortcut-dependent if a treatment lowers its recall by at least 0.10 and the paired interval excludes zero. This rule was set before the artifact-resistance run.
- **Labels:** no label is changed because of a suspected error. Suspect traffic is examined in its original capture context, and any later change is reported as a separate sensitivity analysis.
- **Cross-dataset:** train on one dataset, test on the other using shared features only.
- **Prevalence:** report PR-AUC and precision at realistic benign prevalence, not only on balanced sets.
- **Fixed baselines:** re-evaluate every checkpoint against frozen reference opponents to detect overfitting to the current attacker.
- **Statistics:** 5-10 random seeds, bootstrap confidence intervals, paired tests, and effect sizes for each claim.
- **Safety:** the attacker acts only inside the simulation or an explicitly authorized isolated lab.

## Extension: conditional generative model

The GAN is postponed, not abandoned. A generator is worth adding only if it improves scenario quality or diversity beyond what the simulator and adaptive attacker already provide.

1. Establish first whether adversarial learning and opponent modeling improve generalization (RQ1, RQ2).
2. Then add a conditional generator producing traffic for a given attack category.
3. Validate samples for statistical realism and feature validity before any training use.
4. Compare generator-based augmentation against simulator-generated scenarios on the same held-out families.
5. Keep it only if it adds a measurable gain; the discriminator remains separate from the defender agent.

## Roadmap, risks and scope

The work runs in five phases; each ends in a measured gate before the next begins. Dates are open until the available weeks and weekly hours are known.

1. **Foundation and baseline:** environment, data pipeline, Config A. Gate: Config A measured on held-out families, and its dependence on dataset shortcuts reported.
2. **Fixed adversarial scenarios:** realization layer, scripted attacker, Config B. Gate: Config B measured against A.
3. **Co-training:** RL attacker, historical league, Config C. Gate: C compared with A and B on held-out families.
4. **Opponent modeling:** prediction models, Configs D and E. Gate: D and E compared with C.
5. **Evaluation and write-up:** cross-dataset, sensitivity analysis, statistics. Gate: claims backed by seeds and intervals.

Each gate is a measurement, not a date: a phase closes only when its configuration has been evaluated on held-out attack families.

| Risk | Mitigation |
| --- | --- |
| Building a simulator consumes the schedule | Reuse an existing environment (CybORG, NASim or CyberBattleSim); pick one as primary, others for external validation |
| Co-trained agents cycle and forget old attacks | Train against a league of historical opponents; evaluate against frozen baselines |
| Simulated actions do not resemble real traffic | Traffic realization layer with validity constraints; check realism before training |
| Apparent generalization comes from dataset shortcuts | Artifact-resistance treatments and the shortcut rule; report results that fail it as shortcut-dependent |
| Reward weights drive the result | Justify weights; run sensitivity analysis |
| Opponent modeling adds nothing | Configurations D and E isolate it; report a null result honestly |
| Scope creep | Generative model deferred until RQ1 and RQ2 are answered |

Scope and safety: attackers run only in controlled simulation or an explicitly authorized isolated lab, never against public networks or unauthorized systems. Novelty is established through a literature review, not assumed from combining known techniques.
