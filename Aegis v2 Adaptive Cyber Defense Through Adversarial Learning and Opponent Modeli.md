# Aegis v2: Adaptive Cyber Defense Through Adversarial Learning and Opponent Modeling

Nov 7, 2026 · @Melchior Remilien · updated Nov 9, 2026 (Phase 1 status, improved-release audit, frozen identity, seven-phase roadmap)

## Objective and positioning

Aegis v2 tests one question: does co-training a defender against adaptive attackers, combined with opponent modeling, improve generalization to unseen attack families while keeping detection performance and response cost acceptable?

It does not claim to invent multi-agent cybersecurity, adaptive attackers or intrusion detection. Its contribution is a leakage-controlled test of a hypothesis the baseline paper does not investigate: whether learning an opponent's evolving behavior yields a more generalizable defender than training against a fixed collection of attacks.

**End goal (adopted Nov 9, 2026).** Aegis aims at a working adaptive cyber-defense platform, not only papers. Experiments decide its architecture: a component (opponent modeling, a generative model, an RL defender) is integrated only if it shows a measurable, statistically meaningful gain over simpler baselines. The research questions are unchanged. The roadmap below separates the experimental research (Phases 1–5) from system development (Phases 6–7).

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

**Where each question is measured (roadmap below):**
- **RQ1** in Phase 2: Config C against A and B on held-out families.
- **RQ2** in Phase 3: Configs D and E against C.
- **RQ3** in Phase 4: cross-dataset and cross-environment tests, realistic prevalence and cost-weight sensitivity, on development data.
- **All three, once, in Phase 5:** each frozen configuration is evaluated on the untouched CSE-CIC-IDS2018. That is the only source of final generalization claims, and it opens only through the separate Phase 5 opening authorization.

## Experimental configurations

Five configurations isolate the effect of adversarial training, the historical league and opponent modeling.

| Config | Defender | Attacker training | Opponent modeling | Isolates |
| --- | --- | --- | --- | --- |
| A | Static RF | None | No | Baseline |
| B | Static RF | Fixed adversarial scenarios | No | Value of adversarial data alone |
| C | Adaptive defender | RL + historical league | No | Value of co-training (RQ1) |
| D | Adaptive defender | RL + historical league | Yes | Value of opponent modeling (RQ2) |
| E | Adaptive defender | RL, no historical league | Yes | Opponent modeling without the league |

Configs B and C are built and measured in Phase 2, and D and E in Phase 3. All five are compared again in Phase 4 and evaluated once externally in Phase 5.

Configuration A originally used RF + AE. It was changed to the RF score after the Config A run, because RF was the strongest of the RF, AE and fused scores on held-out families; the choice used test results, so this must be disclosed. Configuration A is a paper-inspired baseline, not a replication. Exact replication is claimed only if the paper's preprocessing, model configuration and evaluation protocol can be reproduced; the paper does not release them, so deviations are documented.

**The autoencoder is excluded (decided Nov 9, 2026).** The AE and fused scores are not reproducible across environments. At a fixed PyTorch thread count the autoencoder repeats bit for bit, but a different thread count changes its results. On improved CICIDS2017 (seed 1, port scan held out), AE recall at 1% FPR was 0.685 on Colab, 0.661 locally at 2 threads and 0.146 locally at 4 threads, while RF was identical in all three. AE and fused therefore stay out of Configurations B–E and out of every research claim. Their historical results stay as recorded, with this caveat, and are not corrected. If anomaly detection is reconsidered, it first needs a pinned thread count and PyTorch version, and a stability test across thread counts and seeds.

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
- **Artifact resistance:** a held-out result counts as generalization only after it is tested against dataset shortcuts. This run is an artifact-resistance and sensitivity audit of the selected baseline, not an unbiased estimate of final generalization, because that baseline was chosen using the same test results. Each treatment refits the baseline on the same folds, in a separate output folder that preserves earlier results:
  - **Near-duplicates:** remove training attack rows that match the held-out family apart from timing.
  - **Duplicate handling:** recall is reported in three evaluation views, defined below. Raw published rows are primary.
  - **Host fingerprints:** remove TCP window features.
  - **Missingness:** neutralize missing-value markers, and test a model that sees only those markers.
  - **UNSW-NB15 `service`:** the publisher defines `-` as "not much used service", so it is a catch-all category and not missing data. Compare the column removed, `-` kept as a category (the reference), and the column reduced to a flag for `-`.
  - **Context counts:** remove the UNSW-NB15 `ct_*` features, to isolate family-specific dependence on them.
  - **Combined:** apply the near-duplicate, TCP window and marker controls together, as a conservative baseline against several shortcuts at once.
- **Shortcut rule:** compare the original model with each treatment on identical held-out rows and seeds, and take the per-seed difference in raw-row recall at the primary false-positive rate. A family's result is shortcut-dependent only if the mean recall drop is at least 0.10 and the 95% confidence interval of that mean lies entirely above zero, on the side of a decrease. The rule applies the same way to every family and to the signature, TCP window, marker, context count and combined treatments. The total number of comparisons is reported, with no multiple-comparison correction. A family whose reference recall is below 0.10 cannot meet the rule and is reported as not testable, not as passing. This rule was set before the artifact-resistance run.
- **Labels:** no label is changed because of a suspected error. Suspect traffic is examined in its original capture context. The 38,045 CICIDS2017 benign rows sent from victim to attacker, which may be attack replies, keep their labels and stay in the primary evaluation. A separate sensitivity run excludes them from training, validation and test, and the difference is reported.
- **Final generalization claims:** no final generalization claim comes from data used to select a model or threshold, which includes every Config A and artifact-resistance result. The protocol for selection and the untouched test is set out below.
- **Cross-dataset:** train on one dataset, test on the other using shared features only.
- **Prevalence:** report PR-AUC and precision at realistic benign prevalence, not only on balanced sets.
- **Fixed baselines:** re-evaluate every checkpoint against frozen reference opponents to detect overfitting to the current attacker.
- **Statistics:** 5-10 random seeds, bootstrap confidence intervals, paired tests, and effect sizes for each claim.
- **Safety:** the attacker acts only inside the simulation or an explicitly authorized isolated lab.

## Training cleaning and evaluation views

**Cleaning.** Before any split, each dataset is cleaned once. Every row whose exact feature vector appears under more than one family is removed, then one copy of each remaining vector is kept. The feature vector is what the model sees: identifiers are dropped, and so is `Destination Port` in CICIDS2017. Families are compared after label mapping, so CICIDS2017 `DDoS` counts as `dos`. Cleaning fits no statistics, so it cannot carry test information into a model. Training, validation and the deduplicated test set all come from the cleaned rows.

**Effect on alignment.** Raw test rows also include repeats and conflicting vectors. Conflicting vectors were never available for training, so the raw test distribution differs from the training distribution. The per-family effect is measured in `results/config_a_artifacts/analysis/cleaning_alignment.txt`:

| Dataset | Family | Raw rows | Kept | Repeats removed | Conflicts with benign | Conflicts with another attack family |
| --- | --- | --- | --- | --- | --- | --- |
| CICIDS2017 | All | 2,830,743 | 2,199,163 (77.7%) | 548,464 | 83,116 | 0 |
| CICIDS2017 | PortScan | 158,930 | 1,851 (1.2%) | 80,757 | 76,322 | 0 |
| CICIDS2017 | Brute force | 13,835 | 9,152 (66.2%) | 4,683 | 0 | 0 |
| UNSW-NB15 | All | 257,673 | 151,239 (58.7%) | 66,034 | 1,756 | 38,644 |
| UNSW-NB15 | Generic | 58,871 | 7,283 (12.4%) | 51,215 | 0 | 373 |
| UNSW-NB15 | DoS | 16,353 | 3,624 (22.2%) | 66 | 0 | 12,663 |
| UNSW-NB15 | Analysis | 2,677 | 450 (16.8%) | 166 | 0 | 2,061 |
| UNSW-NB15 | Backdoor | 2,329 | 350 (15.0%) | 2 | 0 | 1,977 |
| UNSW-NB15 | Exploits | 44,525 | 25,451 (57.2%) | 2,567 | 0 | 16,507 |

Benign rows that share a vector with an attack row count under "conflicts with benign". The shift is largest on UNSW-NB15, where attacks are 63.9% of raw rows but 43.6% of cleaned rows. Generic loses mostly repeats, while analysis, backdoor and DoS lose mostly vectors shared with other attack families. In CICIDS2017, PortScan keeps 1.2% of its raw rows, because about half repeat and half match benign rows. Every other CICIDS2017 family keeps 66% or more. A raw-view result therefore weights flows that the model could never have trained on, and the secondary views separate that effect.

These figures are for the original CICIDS2017 release. On the improved release (development data since Nov 8, 2026), no feature vector carries two attack families, so its overlap-excluded view equals its raw view. Port scan keeps 7,695 cleaned rows of 230,833 raw rows, almost all of the rest being repeats.

**Views.** Recall is reported in three views, with the same threshold in each. No label is changed, and no row leaves the primary view.

| View | Rows | Role |
| --- | --- | --- |
| Raw | All published rows of the held-out family, and the benign rows of the test partition with their repeats, plus benign rows removed as conflicting | Primary: the published dataset as released |
| Overlap-excluded | Raw rows, without feature vectors that carry two or more attack families | Secondary sensitivity analysis |
| Deduplicated | Cleaned test rows only | Secondary sensitivity analysis |

An attack-label overlap is an exact feature vector found under two or more attack families. A vector found under one attack family and benign is not an overlap. When a vector is an overlap, all its rows leave the overlap-excluded view, benign rows included. UNSW-NB15 has 2,032 such vectors, covering 38,644 of 164,673 raw attack rows (23.5%) and 2 benign rows. CICIDS2017 has none, so its overlap-excluded view equals its raw view.

## Phase 1 results

### Original CICIDS2017 release and UNSW-NB15

These results come from the artifact-resistance audit of 2026-11-08 on the original releases. It is a sensitivity audit of the selected baseline, not an unbiased estimate of generalization. Raw recall at 1% FPR, 5 seeds.

The rule was applied to 60 comparisons. 8 met it, and 18 were not testable because reference recall was under 0.10 (CICIDS2017 bot and PortScan, UNSW-NB15 analysis and fuzzers). Three of the 8 come from the combined treatment and repeat a single-treatment result, which leaves five distinct shortcut dependencies:

| Dataset | Family | Depends on | Recall: reference to treated |
| --- | --- | --- | --- |
| CICIDS2017 | Web attack | Near-duplicate signatures of training attacks | 0.874 to 0.043 |
| CICIDS2017 | DoS | TCP window features | 0.417 to 0.163 |
| UNSW-NB15 | Shellcode | `ct_*` context counts | 0.716 to 0.216 |
| UNSW-NB15 | Reconnaissance | `ct_*` context counts | 0.477 to 0.202 |
| UNSW-NB15 | Generic | The `service` column | 0.212 to 0.034 |

Generic's dependence is on `service` itself, not on missingness: `-` is a documented category. The combined treatment repeats the web attack (0.014), DoS (0.154) and generic (0.043) results.

- **Inconclusive:** brute force without TCP windows falls from 0.194 to 0.071, a drop of 0.122, but the interval runs from -0.010 to 0.235. It is classified as inconclusive, neither shortcut-dependent nor robust.
- **Labels:** the possibly mislabeled CICIDS2017 benign rows keep their labels in every primary result. Excluding them, as a separate sensitivity analysis, raises brute force from 0.194 to 0.269 and DoS from 0.417 to 0.459, and changes no other family.

### Improved CICIDS2017 release

The improved release (Liu, Engelen et al., IEEE CNS 2022) replaced the original as development data on 2026-11-08, together with the improved CSE-CIC-IDS2018 as the untouched test. Its audit ran the same day (`results/config_a_artifacts_improved`), again as a sensitivity audit. Raw recall at 1% FPR, 5 seeds, held-out families with at least 200 cleaned rows. Web attack drops out, because most of its flows are "Attempted", which are never trained on.

| Family | Reference | Without TCP window | Markers neutralized | Verdict under the rule |
| --- | --- | --- | --- | --- |
| Bot | 0.960 | 0.856 | 0.815 | Shortcut-dependent (window removed: drop 0.104, CI 0.027–0.211; markers neutralized: drop 0.145, CI 0.009–0.280) |
| Brute force | 0.563 | 0.524 | 0.574 | Not dependent |
| DoS | 0.998 | 0.993 | 0.997 | Not dependent |
| Port scan | 0.679 | 0.369 | 0.458 | Shortcut-dependent (window removed: drop 0.310, CI 0.090–0.530) |

- **Totals:** 5 of the 16 improved-CICIDS2017 comparisons meet the rule. UNSW-NB15's verdicts are unchanged.
- **No near-duplicate leakage and no overlaps:** `remove_matching_signatures` removes no training rows, and the overlap-excluded view equals the raw view.
- **The window explains part of the jump from the original release, not the headline.** Without it, a model that never saw the family still catches bot 0.86, DoS 0.993 and brute force 0.52 (original release: 0.004, 0.446, 0.104).
- **Bot transfer depends on port scan in training:** inner-fold bot recall is 0.045 without port scan training rows and about 0.95 with them. A shared internal-host signature is a hypothesis, not a finding.
- **Exploratory `no_extractor_features` (pre-registration 6.2):** its development run failed the reproduction check of amendment 1 on 2026-11-09 and produced no result. It is not repeated. On CSE-CIC-IDS2018 it is reported only as an external exploratory ablation, with no development-to-external claim.
- No generalization claim is made from improved-CICIDS2017 held-out recall.

### Development reference under the current frozen identity

Config A was rerun on the development data under `25685b84dd83f65c` on 2026-11-09 (`results/config_a_improved_25685b84dd83f65c`). This run is the development reference for the external comparison. RF results equal the historical run in every row except PR-AUC, which differs by at most 1.1e-5 in 12 of 260 rows.

| Improved CICIDS2017 family (RF, mean of seeds 0–4) | Held-out recall at 1% FPR | Seen minus held out (95% CI) | Held-out recall at 0.1% FPR |
| --- | --- | --- | --- |
| Bot | 0.957 | 0.044 (0.035–0.048) | 0.000 |
| Brute force | 0.564 | 0.436 (0.429–0.444) | 0.039 |
| DoS | 0.998 | 0.002 (0.002–0.003) | 0.903 |
| Port scan | 0.444 | 0.555 (0.350–0.685) | 0.048 |

## Baseline selection and the untouched test

**Development data.** CICIDS2017 (both the original and the improved release) and UNSW-NB15 are development data from now on. Every result on them has been seen, and the Random Forest baseline was chosen using their test results. No final generalization claim can come from them.

**Frozen baseline.** Config A is frozen before any final test: Random Forest settings, preprocessing, cleaning, dropped features, training cap, and the threshold rule (the validation-benign quantile at the target false-positive rate). The freeze is recorded by source version and configuration file, and is not changed after the untouched data is loaded.

- **Current frozen identity: `25685b84dd83f65c`** (`python -m aegis.frozen`). It was set by pre-registration amendment 2 (signed Nov 9, 2026), which changed only the Random Forest scoring: tree outputs are added in a fixed order, so scores no longer depend on the worker count.
- **Earlier identities:** `72166b4d433f5b87` (the improved pair; its results stay intact as historical results) and, before that, `e7ab3bfcae0bb6b0` and `c5a771a0ce2826a6` (original data). `bf0b730d63353ec8` was an intermediate draft, abandoned before signing and never used for a result.

**Selection for Configs B to E.** Models, thresholds and hyperparameters are selected on development data only, with a nested protocol. For each outer held-out family, an inner leave-one-family-out loop over the remaining training families makes every selection. The outer family is used only to report development results, never to choose.

**Untouched test.** The final test uses a dataset that no one in this project has loaded: **CSE-CIC-IDS2018, improved release** (confirmed Nov 8, 2026). It is produced with the same fixed CICFlowMeter as improved CICIDS2017, so the pair isolates network shift from extractor shift, though some column names need mapping. It is pre-registered in `docs/preregistration/cse_cic_ids2018.md` (registered Nov 8, 2026; amendments 1 and 2 signed Nov 9, 2026). It is opened once, at Phase 5. Its known caveats include labeling errors and tool artifacts similar to those in CICIDS2017, so the same audit treatments apply.

- **Pre-registration:** before the first load, record the metrics, the three views, the shortcut rule, the families, and every planned comparison.
- **One evaluation:** each frozen configuration is evaluated once. Any rerun after results have been seen is reported as such, with the reason.
- **Data handling:** checksums are recorded at download. The data is not explored before the pre-registered evaluation, beyond the schema and label checks the loaders run.

**Phase 1 closed on Nov 9, 2026**, when the project owner accepted the exit review (`docs/phase1-exit-review.md`, with its findings and conclusion). Phase 2 begins with the Config B design (`docs/config-b-design.md`).

**Phase 1 exit criteria.** Phase 1 closes when the artifact audit is reported, the three UNSW-NB15 views are reviewed, this protocol is fixed, and Config A is frozen. Documentation is not enough: the safeguards below must be implemented in code and verified by tests. Config B and adversarial co-training do not start before then.

**Required safeguards, implemented and tested:**
1. **Nested selection:** a selection routine that, for each outer held-out family, chooses among candidates by inner leave-one-family-out on the training families only. A test must show that it never reads outer test rows.
2. **Baseline re-check:** run nested selection over the Config A candidate scores (rf, ae, fused) and report whether rf is still selected without test access. The result is reported either way.
3. **Frozen baseline:** a recorded identity for Config A (settings, preprocessing, cleaning, threshold rule, source hash). Later runs refuse to call a model Config A if it differs.
4. **Untouched-test guard:** the external test set can be loaded only through a guarded entry point. It refuses to run without a pre-registration file matching the frozen identity, and it logs every access.

Status, 2026-11-09: all four are implemented and tested.
- **Baseline re-check:** run on both releases. Original: rf in 49 of 65 outer folds, fused in 16, ae in none. Improved pair: rf in 60 of 60, with the majority rule set before any improved-release result. In 13 of those folds fused had the higher mean but no majority. Those margins rest on the AE score, which is not reproducible across environments.
- **Untouched-test guard:** signing amendments does not open the external set. `guarded_load` also requires a separate, mandatory Phase 5 opening authorization from the project owner. It is bound to the exact pre-registration file, confirms each opening condition of plan section 9.2, and lists the frozen identity of every authorized configuration. No such authorization exists, and the 2018 data has not been downloaded.
- **Limitation of the guard:** a "signature", on an amendment or on the opening authorization, is an attestation: a name and a UTC timestamp in a JSON file. The guard checks that it is present, names the registered owner, and is consistent in time and with the pre-registration's hash. It verifies no cryptographic signature or signed commit, so it does not authenticate the signer. Its integrity rests on the reviewed git history. The guard prevents accidental or premature opening, not deliberate circumvention.

The external dataset is assessed in `docs/cse-cic-ids2018-assessment.md`. It is not downloaded before the Phase 5 opening authorization. The Phase 1 exit review is `docs/phase1-exit-review.md`.

## Extension: conditional generative model

The GAN is postponed, not abandoned. A generator is worth adding only if it improves scenario quality or diversity beyond what the simulator and adaptive attacker already provide.

1. Establish first whether adversarial learning and opponent modeling improve generalization (RQ1, RQ2).
2. Then add a conditional generator producing traffic for a given attack category.
3. Validate samples for statistical realism and feature validity before any training use.
4. Compare generator-based augmentation against simulator-generated scenarios on the same held-out families.
5. Keep it only if it adds a measurable gain; the discriminator remains separate from the defender agent.

## Roadmap, risks and scope

The work runs in two stages and seven phases; each phase ends in a measured gate before the next begins. Dates are open until the available weeks and weekly hours are known.

**Stage 1, experimental research:** what works, and why.

1. **Baseline and integrity (closed Nov 9, 2026):** environment, data pipeline, dataset integrity, Config A. Gate: the Phase 1 exit criteria above: audit reported, three UNSW-NB15 views reviewed, selection and untouched-test protocol fixed, and Config A frozen.
2. **Adaptive co-training:** realization layer, scripted attacker and Config B, then the RL attacker, historical league and Config C. Gate: B measured against A, and C compared with A and B on held-out families.
3. **Opponent modeling:** prediction models, Configs D and E. Gate: D and E compared with C.
4. **Robustness and ablations:** cross-dataset tests (RQ3), ablations, prevalence and cost-weight sensitivity, robustness, all on development data. Gate: claims backed by seeds, intervals and the shortcut rule, and every configuration to be compared frozen and recorded by amendment.
5. **External evaluation:** the pre-registered, one-time evaluation of every frozen configuration on CSE-CIC-IDS2018. It is a separate, mandatory gate: the data is opened only with the project owner's Phase 5 opening authorization, which is never implied by signing amendments or by completing Phase 4. Gate: every result reported, including failed or unfavourable ones.

**Stage 2, system development:** only methods validated in Stage 1.

6. **System integration:** assemble only the components that passed their gates into one system: input layer, the validated detection engine, opponent intelligence and the adaptive defense agent, if each passed. Gate: each integrated component reproduces its validated measurement.
7. **Interface and operations:** operational dashboards, monitoring and an experiment interface. Any deployment uses real telemetry in controlled environments only.

Each gate is a measurement, not a date. In Stage 1, a phase closes only when its configuration has been evaluated on held-out attack families. In Stage 2, a phase closes only when what it builds reproduces the measurements that validated it.

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
