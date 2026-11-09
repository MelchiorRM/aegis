# Config B design (Phase 2) — draft for owner approval

**Status:** design only, 2026-11-09. No code is written and no experiment runs until the project owner approves
this document. Configs C, D and E have not started. CSE-CIC-IDS2018 stays closed: Phase 5 is a separate, mandatory
opening authorization, and nothing here touches it.

## Summary
- **What Config B is.** In the v2 specification, Config B is the static Random Forest of Config A, trained with
  added data from fixed (scripted, non-learning) adversarial scenarios. It isolates "the value of adversarial data
  alone".
- **Proposal:**
  - **Simulator:** CybORG, CAGE Challenge 4 scenario (CybORG 4.0), pinned to a commit, as the primary simulator for
    Phase 2. It is the only candidate with attacker, defender and benign-user agents, partial observability and
    cost-bearing defender actions, which Config C needs and Config B must share. Adoption depends on a time-boxed
    spike with go/no-go criteria (section 1.4).
  - **Realization:** the simulator supplies scenario structure (which attack actions, in which order and context),
    not traffic. Each action is realized by sampling real development flows, never by inventing traffic. Feature
    perturbation is a secondary, clearly labelled arm whose outputs are not claimed to be valid attacks.
  - **Comparison:** Config B is evaluated exactly like Config A on real held-out dataset flows, with an equal-size
    control arm that separates "scenario-shaped data" from "more data".
- **What it can show:** whether adding scenario-generated training data, in the Random Forest's feature space,
  reduces held-out-family recall loss against Config A at equal false-positive rate. This is the "data alone"
  control for RQ1, so that Config C against Config B isolates adaptive co-training.
- **What it cannot show:** anything about adaptive attackers, defender learning, opponent modeling, the realism of
  simulated traffic, or external generalization.

## 1. Simulator selection

### 1.1 Candidates (checked 2026-11-09)
- **CybORG, CAGE Challenge 4** (`cage-challenge/cage-challenge-4`, CybORG 4.0, MIT and public domain):
  - **Agents:** red (attacker), blue (defender) and green (benign user) agents, with five decentralized blue agents.
    The enterprise network is generated per episode by `EnterpriseScenarioGenerator`.
  - **Activity:** the last substantive commit was 2024-04, and README-only updates followed in 2025.
  - **Dependencies:** it pins `gym==0.26.2` and `gymnasium==0.28.1`. The environment takes a seed.
- **CybORG++** (`alan-turing-institute/cyborg_plus_plus`, MIT): a debugged CAGE 2 CybORG plus MiniCAGE, a
  reimplementation the authors report runs up to 1000× faster in parallel (Emerson et al., 2024). It was active
  until 2025-08, with a license update in 2026-01.
- **NASim** (`Jjschwartz/NetworkAttackSimulator`, MIT): v0.12.0, 2023-05. Its README describes it as a stable
  release with no further development planned, though still maintained for bug fixes. It has a Gymnasium
  interface and YAML-defined scenarios.
- **CyberBattleSim** (`microsoft/CyberBattleSim`, MIT):
  - **Activity:** dependency updates through 2026-08, and no releases.
  - **Model:** lateral movement over planted vulnerabilities and credentials. Its authors state that modelling
    actual network traffic "was not necessary".

### 1.2 Comparison
| Criterion | CybORG (CAGE 4) | NASim | CyberBattleSim |
|---|---|---|---|
| **Action space** | Red: discover systems, aggressive and stealth service discovery, exploit remote service, privilege escalation, impact, degrade services, discover deception, withdraw. Blue: monitor, analyse, deploy decoy, remove, restore, block and allow traffic. Green: local work, access service. Actions take several time steps. | Attacker only: service, OS, subnet and process scans, exploits, privilege escalation. | Attacker: local and remote vulnerability exploits, connect with credentials. Defender: a basic scan-and-reimage agent, or a custom one. |
| **Observation model** | Partially observable, per agent. Blue sees probabilistic alerts (network-connection and process events), analysis results and firewall state. Green users raise false alerts. | Host-vector observation; an optional partially observable mode. | Discovered nodes, credentials and properties. |
| **Network topology** | Fixed enterprise structure (zones, mission phases), randomized per episode. | User-defined in YAML, or generated. | Chain, capture-the-flag, random or custom networks defined in Python. |
| **Extensibility** | Python, large code base. CybORG++ reports persistent bugs and inefficiency. Custom agents through wrappers and PettingZoo. | Simple. New scenarios are YAML files. | Python model definitions; flexible. |
| **Telemetry** | Event-level alerts with detection probabilities. No packets or flows. | None. | None (traffic explicitly not modelled). |
| **Reproducibility** | Seeded generator. Bit-for-bit repeatability unverified (spike item). | Seeded Gymnasium environment. | Seeded Gym environment. |
| **Maintenance** | Thin since 2024 upstream. CybORG++ is a maintained CAGE 2 fork. | Stable, no new development. | Dependency upkeep, few features. |
| **Implementation cost** | High: heavy environment, old gym pins, multi-agent wrappers. | Low. | Moderate. |
| **Fit for Aegis Phases 2–3** | Attacker, defender and benign users with costs: needed for C's co-training, D's opponent modeling and the spec's false-alarm and disruption costs. | No defender, so it cannot host C, D or E. | Defender too limited for C, D and E without substantial extension. |

### 1.3 Recommendation and trade-offs
- **Primary: CybORG CAGE 4**, pinned to a commit and vendored in an isolated environment.
  - It is the only candidate where Configs B and C can share one scenario definition and one realization layer.
    That sharing is what lets C against B isolate co-training.
  - Its green agents and blue action costs map directly to the spec's reward terms (false alarm, disruption,
    response).
- **Costs accepted:** complexity, old gym pins, slow stepping and thin upstream maintenance. They are mitigated by
  the spike, the pin, and a fallback.
- **Fallback: CybORG++ / MiniCAGE (CAGE 2),** if CAGE 4 fails the spike: debugged, faster and maintained, at the
  price of a smaller scenario.
- **Secondary environments for Phase 4 (RQ3, cross-environment):** NASim, and CyberBattleSim. They are not used in
  Phase 2.
- **For Config B alone, the simulator matters little.** Its attacker is scripted and its defender does not act. It
  is chosen now because B and C must share it.

### 1.4 Spike (time-boxed, before the simulator is adopted)
A go/no-go evaluation of at most two weeks, in a separate environment, producing a written report and no Aegis
results. It passes only if all of these hold:
1. **Install:** it installs from a pinned commit with locked dependencies, in an isolated environment beside the
   Aegis one.
2. **Reproducibility:** two runs with the same seed give identical trajectories, compared step by step, at a pinned
   thread count.
3. **Logging:** every red action can be logged with host, service, outcome and time step.
4. **Throughput:** enough scenario episodes per fold within the compute budget (target set by the owner).
5. **Scripted red agents:** a scripted red agent can run fixed strategies without learning.

On failure, the spike evaluates CybORG++ against the same criteria and reports both.

## 2. Traffic realization

### 2.1 Three layers, kept distinct
1. **Simulator state transitions:** abstract changes, for example host H compromised or service S discovered. They
   are ground truth only inside the simulator.
2. **Simulated telemetry:** what the simulator emits about those transitions. In CybORG these are probabilistic
   alerts and analysis results: events, not packets or flows.
3. **Dataset flows:** real CICFlowMeter (improved CICIDS2017) or Argus/Bro (UNSW-NB15) records from the development
   data, sampled or transformed.

**Neither layer 1 nor layer 2 is network traffic.** The Random Forest consumes only layer-3 records, so every
link from the simulator to a flow is a modelling assumption that must be stated and checked.

### 2.2 Realization arms
- **R-sample (primary).** A fixed, pre-registered table maps red action types to development attack families, for
  example service discovery → port scan, exploit remote service → brute force or exploits, degrade services or
  impact → DoS.
  - Each executed action draws real rows of the mapped family. They come from the **current fold's training
    partition only**, never from validation or test rows and never from the held-out family.
  - Actions with no corresponding family (`DiscoverDeception`, `Withdraw`, `Sleep`) produce no flows, and this is
    reported.
  - The data is real traffic. The simulator determines only its mix, sequence and context.
- **R-transform (secondary, labelled ablation).** R-sample rows with constrained feature perturbations.
  - **Constraints:** non-negativity, integer counts, min ≤ mean ≤ max, totals consistent with counts and means,
    flag counts ≤ packet counts, protocol-specific fields only where valid, and duration consistent with
    inter-arrival times.
  - **What constraint satisfaction shows:** only that a record is internally consistent as a flow record. **It does
    not show that the record is an executable attack, or what a real attacker would produce.**
  - Perturbation can also create artifacts the model learns as shortcuts.
- **R-emulate (not in Config B).** Executing scenarios in an explicitly authorized, isolated lab and extracting flows
  with the same extractor is the only route to claims about valid generated traffic. It is deferred, and needs its
  own design and safety review.

### 2.3 Validation of the action-to-flow relationship
1. **Mapping audit:** each table entry is justified by the matching ATT&CK technique and the dataset's own attack
   documentation. It is reviewed and frozen before any Config B result exists.
2. **Leakage checks**, automated, pass or fail:
   - no realized row comes from the held-out family, validation or test rows;
   - no exact feature vector of a realized row appears in the fold's test rows.
3. **Distribution checks:**
   - R-sample against its source families: per-feature distributions and family proportions, with any departure
     explained by the scenario mix;
   - R-transform: an invariant-violation rate, which must be zero;
   - R-transform: nearest-neighbour distance to source rows;
   - a two-sample classifier, real against transformed. If it separates them easily, the transformed rows carry
     artifacts and R-transform is reported as such.
4. **Simulator-to-dataset correspondence is not validated** in Config B: nothing checks that a CybORG alert
   corresponds to a flow. This is stated as a limitation.

### 2.4 Claims the data supports
- **Supported:** "a Random Forest trained on development data plus R-sample (or R-transform) rows, shaped by
  scripted CybORG scenarios, has held-out-family recall X on real dataset flows."
- **Not supported:**
  - that simulated attacks resemble real ones;
  - that perturbed flows are valid attacks;
  - that the scenario mix reflects real attacker behaviour;
  - any robustness to adaptive attackers.

## 3. Comparison with Config A

### 3.1 Kept identical (directly comparable)
- **Data and splits:** the development datasets (improved CICIDS2017, UNSW-NB15), cleaning, `make_partition` and
  `holdout_fold` with seeds 0–4. The test rows are identical for A and B, because B adds rows to training only.
- **Families:** held-out families with at least 200 cleaned rows. Attempted flows are handled as in Config A.
- **Defender pipeline:** preprocessing, Random Forest settings and fixed-order scoring, all inherited from
  `25685b84dd83f65c`.
- **Thresholds:** the threshold rule (validation-benign quantile), at 1% and 0.1% target FPR. Validation rows are
  unchanged, so B's realized FPR is comparable with A's.
- **Views and metrics:** the three views with raw rows primary; recall, realized FPR, PR-AUC and precision at 1% and
  0.1% prevalence.
- **Shortcut audit:** the same treatments, applied to B. The shortcut rule is unchanged (drop ≥ 0.10 and 95%
  interval above zero), with every comparison counted and no correction.
- **Statistics:** per-seed paired differences, bootstrap intervals (10,000 samples), paired tests and effect sizes.

### 3.2 Primary estimand
Per held-out family, the mean per-seed paired difference in raw-view held-out recall at 1% target FPR, B minus A,
with its 95% bootstrap interval. The per-seed difference in degradation (seen minus held out) is secondary. Every
family is reported, including null and negative results.

### 3.3 Controls and selection
- **Equal-size control (B0):** the same number of extra rows per family, sampled uniformly from the same training
  pool with no simulator sequencing.
  - **B against A** measures "this extra data".
  - **B against B0** measures "the scenario structure".
  - If B ≈ B0, the simulator adds nothing beyond resampling, and that is reported.
- **Data budget:** the per-family training cap (100,000) applies to real and realized rows together, so B cannot win
  through more training data than A. A variant without the cap is secondary.
- **Nested selection:** B's choices (realization arm, augmentation ratio, scenario set) are selected by inner
  leave-one-family-out on training families only, with the majority rule. Outer families are only reported.

### 3.4 Not directly comparable
- **Simulator-level outcomes** (episode reward, time to detect, containment, response cost):
  - Config A was never evaluated in a simulator.
  - Placing either Random Forest in CybORG as a detector requires the realization map in reverse, so the result
    would depend on that map more than on the model.
  - They are reported only as secondary and simulator-conditional, if at all.
- **Defender actions and costs:** B's defender is static and takes no actions, so operational metrics belong to
  Config C onward.
- **Cross-dataset and cross-environment results:** Phase 4.
- **External results:** Phase 5, through the opening authorization only.

## 4. Research scope
- **Config B tests** whether fixed, scenario-generated adversarial training data, in the Random Forest's feature
  space, reduces held-out-family recall loss against Config A at equal false-positive rate. Two controls go with
  it: equal size (B0) and the data budget.
- **Its role for RQ1:** it is the "adversarial data alone" baseline. RQ1's claim, that co-training against
  adaptive attackers helps, is tested by C against A and B. A gain of C over B, but not of B over A, would point to
  adaptivity rather than data.
- **It does not test:**
  - adaptive or learning attackers, defender learning, co-training or the historical league (Config C);
  - opponent modeling (Configs D and E, Phase 3);
  - response effectiveness or cost weights (C onward, Phase 4 sensitivity);
  - generative models (deferred extension);
  - cross-dataset transfer (Phase 4);
  - external generalization (Phase 5).
- **No opponent model, attacker predictor or learned attacker** is built for Config B.

## 5. Reproducibility and pre-registration
Recorded and frozen before any Config B experiment, as a Config B identity (an extension of `aegis.frozen`) and a
dated development pre-registration. Its identity is added to the CSE-CIC-IDS2018 pre-registration by signed
amendment (`frozen_identities.config_b`) before Phase 5.
- **Inherited:** Config A identity `25685b84dd83f65c`: datasets, cleaning, splits, Random Forest, fixed-order
  scoring, threshold rule, seeds 0–4, target FPRs, prevalences, bootstrap samples.
- **Simulator:**
  - package and git commit SHA, CybORG version, Python version and full dependency lock (gym and gymnasium pins);
  - scenario generator and its parameters, episode length, number of episodes per fold;
  - seed derivation (simulator seed as a fixed function of fold seed and episode index);
  - thread counts pinned.
- **Agents:**
  - scripted red strategies (the exact finite-state definition or script);
  - the blue policy during scenario generation (for example `Sleep`, or a fixed scripted policy);
  - green agent parameters, including false-alert rates.
- **Observation and action definitions:** the wrappers used, action enumeration, invalid-action handling, and the
  observation fields logged.
- **Reward:** not used for training in Config B. If simulator-level outcomes are reported, the cost tables and the
  λ weights of the spec's defender reward are frozen with their stated assumptions.
- **Stopping conditions:** episode length, termination rules, episodes per fold, total realized rows per family.
- **Realization:**
  - the action-to-family table, with its hash;
  - sampling rules (pool, with or without replacement, ratio);
  - perturbation operators, bounds, the invariant set and the rejection rule, with their seeds.
- **Evaluation:**
  - the primary estimand, views, families, the shortcut treatments and rule, B0, the data budget;
  - the selection candidates and rule;
  - which outputs are primary and which are secondary.
- **Determinism checks:** a rerun on the same environment must reproduce every rule input exactly before results
  are reported. This is the lesson of the autoencoder and of thread-order scoring in Phase 1.

## 6. Risks
| Risk | Effect | Mitigation |
|---|---|---|
| Simulator-to-dataset mismatch | CybORG's enterprise topology and abstract actions do not correspond to the CICIDS2017 or UNSW-NB15 testbeds. The action-to-family map is coarse. | R-sample uses only real flows. The mapping is audited and frozen. Claims are limited to the feature space (2.4). B0 shows whether the scenario structure adds anything. |
| Reward design | A poorly justified reward would drive Config C later. | Config B does not train on reward. The reward and λ weights are justified and frozen before C, with sensitivity analysis in Phase 4. |
| Unrealistic attacker behaviour | Scripted red strategies and random strategy choice are not real campaigns. | No realism claim. The strategies are frozen and reported. Several fixed strategies are run, and results are reported per strategy if they differ. |
| Environment complexity | CybORG bugs (reported by CybORG++), old gym pins and slow stepping. | Spike with go/no-go criteria, pinned commit, isolated environment, fallback to CybORG++ / MiniCAGE. |
| Schedule (the spec's top risk) | The simulator consumes the phase. | Time-boxed spike. R-sample needs only action logs, not deep simulator changes. No custom simulator. |
| Leakage through realization | Held-out-family or test rows enter training. | Automated leakage checks (2.3), run on every fold, pass or fail. |
| Shortcuts created by perturbation | R-transform rows teach artifacts. | The shortcut audit applies to B. A two-sample classifier check. R-transform stays secondary. |
| More data, not better data | B beats A only through volume. | Data budget and B0. |
| Nondeterminism | Results change across environments, as the autoencoder's did. | Pinned threads, recorded versions, a rerun check before reporting. No PyTorch component in Config B. |
| Safety | — | Simulation only. R-emulate, if ever, only in an explicitly authorized isolated lab. |

## 7. Decisions requested from the owner
1. Approve CybORG CAGE 4 as primary, with CybORG++ / MiniCAGE as fallback, subject to the spike (1.4), or choose
   otherwise.
2. Set the spike's time box and compute budget (throughput target).
3. Approve R-sample as primary and R-transform as a labelled secondary arm (R-emulate excluded from Config B).
4. Approve the controls: B0, and a data budget applying the 100,000 cap to real and realized rows together.
5. Approve the primary estimand (3.2) and the freeze list (section 5).

After approval, the next step is the spike only. No Config B experiment runs before its development
pre-registration is written and frozen.
