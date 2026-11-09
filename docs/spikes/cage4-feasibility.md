# CAGE Challenge 4 feasibility spike (Config B, Phase 2)

**Date:** 2026-11-09, one working day of the 10 approved. **Compute:** 0.77 CPU-hours of the 20 approved, no GPU,
at most 2 concurrent simulation workers (`spikes/cage4/ledger.csv`). **Scope:** feasibility only. No dataset was
loaded, no Config B training data was generated, and no model was fitted or compared.

**Accepted by the owner on 2026-11-09,** with commit `8c3c50c`, the compatibility editable install, `pyarrow==17.0.0`
and the complete 107-package lock. Upstream test result: **679 passed, 1 failed, 15 skipped.** The failing
firewall test is not a Config B blocker. It is a known unresolved issue for Config C, to be investigated and
resolved, or explicitly accounted for, before C begins.

**Verdict: every critical criterion passed.** Two installation defects needed pins, and one upstream test is
intermittent. Neither affects Config B, and both are recorded below for the owner's decision. Nothing switched
environment.

## Environment
- **Isolated WSL environment:** `~/aegis-spike/venv`, Python 3.12.3, beside the Aegis `.venv` and sharing nothing
  with it.
- **CAGE Challenge 4:** commit `8c3c50ca54b176c2de199847944e8dcc035497e3` (2025-10-27, "Update README with
  publication citations").
- **Version, verified:** the installed package's metadata reports `CybORG 4.0`. That value is read from
  `CybORG/version.txt`, which has said `4.0` since the challenge's release, so the commit, not the version string,
  identifies the code.
- **Dependency lock:** `spikes/cage4/requirements.lock` (107 packages, `pip freeze`). `pip check`: no broken
  requirements.
- **Agents:** red and green agents are internal and rule-based (`FiniteStateRedAgent`, `EnterpriseGreenAgent`).
  The five blue agents are externally controlled through `parallel_step`. Six red agents appeared over a 500-step
  episode. **Config B's attacker is therefore scripted, not adaptive.**

## Results by criterion
| Criterion | Result | Evidence |
|---|---|---|
| **Clean installation** | **Pass, with two pins** | The documented `pip install -e .` installs, but `CybORG` is not importable (defect 1). With setuptools' compatibility editable mode it imports. The CAGE 4 test suite then failed to collect because of an unpinned `pyarrow` (defect 2); after a pin it ran: **679 passed, 1 failed, 15 skipped** (27 min, 1 worker). The failure is an intermittent upstream test (below). |
| **Scenario initialization** | **Pass** | `CybORG(EnterpriseScenarioGenerator(...), "sim", seed=s)`: 74 agents, 97 hosts in the IP map, 500-step episodes (499 executed steps; the episode ends on step 499). |
| **Scripted agent interaction** | **Pass** | Blue was driven externally by three fixed scripts. **Sleep** and **Monitor** give identical red behaviour, because CAGE 4 runs Monitor automatically every step (documented). **Restore-on-alert** changes the world: on seed 0, red actions went from 1,190 to 1,146 and red successes from 686 to 797, blue host events from 319 to 385, and the summed blue reward from −31,035 to −19,730. |
| **Action and event logging** | **Pass** | Per step and agent: action type, target (`hostname`, `ip_address`, `subnet`, `session`), outcome (`TRUE`, `FALSE`, `IN_PROGRESS`, `UNKNOWN`), and for `ExploitRemoteService` the concrete exploit chosen (`sub_action`). Also logged: blue observation host events (the simulated telemetry), green action counts, and rewards. |
| **Same-seed reproducibility** | **Pass** | Seed 0 gave an identical trajectory hash in every fresh process, whatever the string-hash randomization: `d16fe187…` under random, 0 and 1 `PYTHONHASHSEED`, and `724e864d…` (final probe) under 7 and 8. Seed 1 differs. Restore-on-alert also reproduced (`45d0d3e7…` twice). |
| **Throughput** | **Pass** | One 500-step episode takes 37–41 s on one worker (about 13 steps per second). Two concurrent workers took 33 and 35 s each, so throughput scales to 2 workers (about 3.4 episodes per minute). |

## Findings for the owner
1. **Defect 1, the editable install.** `setup.py` declares no packages (`py_modules=[]`), so a modern setuptools
   editable install maps nothing. Fix: `pip install -e ./cc4 --config-settings editable_mode=compat`, which adds
   the repository to the import path as older setuptools did. CAGE's code is unchanged.
2. **Defect 2, an unpinned dependency.** `ray[rllib]` is unpinned and now pulls `pyarrow` 26, which requires
   NumPy 2, while CAGE pins `numpy==1.26.4`. Fix: `pyarrow==17.0.0`. Only RLlib-related code imports it, not the
   simulator.
3. **The intermittent upstream test** is `test_blue_agents_can_open_and_close_firewalls`.
   - It failed once in the full suite and once in 20 isolated runs (about 5%).
   - Its fixture builds an unseeded environment, so the network differs each run, and the test assumes a brute
     force attempt succeeds.
   - It is not nondeterminism under a fixed seed: every seeded run above reproduced exactly.
   - It concerns blue firewall actions, which Config B does not use. Config C would, so it should be understood
     before C.
   - **Status: open for Config C (C-1).**
   - **A related latent defect (C-2),** found by reading the code after the spike and not exercised by it: when red
     has found a decoy, `FiniteStateRedAgent` uses `PIDSelectiveExploitActionSelector`, whose
     `get_exploit_action` does not accept the `priority` argument `ExploitRemoteService` passes. Blue never
     deploys decoys in Config B, so B never reaches it. To be checked before Config C.
4. **Torch** (2.2.0, installed from the CPU index to match the no-GPU budget) and Ray come in through CAGE's
   requirements but are not used by the simulator. They add install weight, not risk to Config B.
5. **gym 0.26.2** prints an "unmaintained" notice on import. It is pinned by CAGE and works.
6. **Facts for the replay mapping**, from seed 0 under Sleep; descriptive only, not a mapping:
   - Red action counts (successes): Impact 355 (21), DegradeServices 329 (329), ExploitRemoteService 228 (58),
     DiscoverDeception 93, PrivilegeEscalate 58, AggressiveServiceDiscovery 45, DiscoverRemoteSystems 42,
     StealthServiceDiscovery 40.
   - Concrete exploits: SSHBruteForce 52 (52 successful), HTTPRFI 11 (0), SQLInjection 6 (6), and 159
     `ExploitRemoteService` steps with no concrete exploit logged.
   - Green: about 10,400 each of local work and service access.
   - **Consequences for the design:** the action mix is dominated by Impact and DegradeServices, and many actions
     fail. Whether replay is conditioned on attempted or successful actions, and how multi-step `IN_PROGRESS`
     outcomes are counted, are choices to freeze. The concrete exploit makes a finer, more defensible mapping
     possible than the abstract action type.

## Runtime estimate for the planned Config B experiment (`spikes/cage4/estimate.py`)
*As estimated during the spike. It is superseded by the compute plan in `docs/config-b-design.md` section 3.5,
which adds B0's selection and audit (owner decision) and corrects the selection fit count (one fit per
unordered family pair): a 152.2 CPU-h ceiling against the 180 CPU-h budget. The table below also counted ordered
pairs, so its selection line is twice too high.*

The model costs are measured Random Forest fold times from Phase 1 logs (8 workers): improved CICIDS2017 0.76 min,
UNSW-NB15 0.26 min per fold. No model was run for this estimate. The counts are the draft design's assumptions.

| Part | CPU-hours |
|---|---|
| A, B, B0: outer folds, 5 seeds, both datasets (210 fits) | 12.3 |
| Perturbation arm (exploratory), outer folds | 4.1 |
| Shortcut audit of B (same treatments as Config A) | 21.2 |
| Nested selection of B, 3 replay-ratio candidates (B0 matched to the pick) | 47.4 |
| Determinism rerun of the primary arms | 12.3 |
| CAGE 4 scenarios: 50 episodes × 5 seeds (trajectories do not depend on the fold) | 2.7 |
| **Total** | **about 100 CPU-h**, roughly 12.5 h of wall time on this 8-core machine, one fit at a time |

- **Auditing and selecting B0 separately** would add about 69 CPU-h.
- **The simulator is a small share:** even 200 episodes per seed is about 10.7 CPU-h, or about 5 h of wall time on
  2 workers. **Nested selection dominates.**
- **Fit with the budget:** the only budget set so far is the spike's (20 CPU-h), which the experiment exceeds by
  design. On this machine (8 cores, 7 GB RAM) the estimate is feasible as sequential runs over about two days, but
  **the experiment budget is the owner's decision**. The levers are the number of selection candidates and the
  audit scope.

## Reproducing the spike
```bash
mkdir -p ~/aegis-spike && cd ~/aegis-spike
git clone https://github.com/cage-challenge/cage-challenge-4.git cc4
git -C cc4 checkout 8c3c50ca54b176c2de199847944e8dcc035497e3
python3.12 -m venv venv
venv/bin/pip install "pip==24.3.1"
venv/bin/pip install --extra-index-url https://download.pytorch.org/whl/cpu "torch==2.2.0+cpu"
venv/bin/pip install --extra-index-url https://download.pytorch.org/whl/cpu -e ./cc4
venv/bin/pip install --no-deps -e ./cc4 --config-settings editable_mode=compat   # defect 1
venv/bin/pip install "pyarrow==17.0.0"                                            # defect 2
venv/bin/python /path/to/aegis/spikes/cage4/probe.py --seed 0 --steps 500 --blue sleep
```
For an exact environment, install from `spikes/cage4/requirements.lock` instead of resolving.

## Not done, by design
- No action-to-family mapping was drafted.
- No dataset was opened, and no replay or training records were produced.
- No model was fitted, and no comparison was run.
- CSE-CIC-IDS2018 was not touched.
- Configs C–E were not started.
