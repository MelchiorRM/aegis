# Issue history

A running record of the major issues met in Aegis: what happened, the cause, the fix, and the recommendation that
follows. Newest phase last. **Status** is one of *fixed*, *open*, or *accepted limitation*. Each entry cites the
document or record it rests on. Failed runs stay preserved and are never reinterpreted.

## Phase 1 — Config A baseline (closed 2026-11-09)

### 1. Amended rerun failed its reproduction check (fixed)
- **What happened:** the amended development rerun failed the AUC tolerance by 3.29e-11. One tied score broke
  differently.
- **Cause:** scikit-learn's multithreaded `predict_proba` sums tree outputs in whatever order the threads finish,
  so the last digits vary between calls.
- **Fix:**
  - The run was reported as failed, and the tolerance was not widened.
  - Fixed-order scoring (`forest_probability`) was added. It is bit-identical to `predict_proba` with
    `n_jobs=1`, for any worker count.
  - Config A was re-frozen through amendment 2, and the failed run was preserved.
  - Records: `docs/preregistration/`, `results/config_a_exploratory_improved_amended/STATUS.md`,
    `docs/phase1-exit-review.md` (finding 6).
- **Recommendation:** treat any multithreaded reduction as nondeterministic until shown otherwise, and check exact
  reproduction before trusting a result.

### 2. Missing feature-count check in fixed-order scoring (fixed)
- **What happened:** `forest_probability` did not check that the input had the forest's feature count.
- **Fix:** the check was added. This changed the identity from `bf0b730d63353ec8` (abandoned, never used) to
  `25685b84dd83f65c`, and the change is disclosed.
- **Recommendation:** review new code for input validation before freezing, because every fix after a freeze costs
  an identity.

### 3. Autoencoder not reproducible across thread counts (accepted limitation)
- **What happened:** port-scan recall at 1% FPR was 0.685, 0.661 and 0.146 across environments. Random Forest
  results were identical in all three.
- **Cause:** the PyTorch thread count changes reconstruction errors (by up to 18% on synthetic data). The result is
  fragile to tiny numerical changes.
- **Fix:** ae and fused were excluded from Configs B–E and from every claim (owner decision).
- **Recommendation:** before any neural model returns, pin its thread count, record the torch version in its
  identity, and check stability across thread counts and seeds.

### 4. Diagnostic script artifacts under pandas 3 (fixed)
- **What happened:** a diagnostic showed differences of about 1e-16.
- **Cause:** it ran under pandas 3, not the pinned pandas 2.2.3.
- **Fix:** it was rerun under pandas 2.2.3, which gave correct results.
- **Recommendation:** run every diagnostic in the project's pinned environment, never the system one.

### 5. External-data guard did not enforce the opening conditions (fixed)
- **What happened:** signed amendments alone would have satisfied the guard.
- **Fix:** the guard now requires a separate Phase 5 opening authorization (`<stem>.opening.json`). It checks the
  pre-registration hash, phase 5, the frozen confirmations, each named opening condition, the frozen identities,
  the signer, and the timestamp order. Each refusal is tested. Record: `src/aegis/data/external.py` (commit
  `457b906`).
- **Recommendation:** make every safeguard default-deny, and test each refusal path.

### 6. Guard signer fields described as "signed" (fixed in wording; accepted limitation)
- **What happened:** the documentation implied the signer fields authenticate the signer.
- **Cause:** they are names and timestamps in JSON, attestations rather than cryptographic signatures.
- **Fix:** the wording was changed to "attested", and the limitation is documented (`docs/phase1-exit-review.md`).
- **Recommendation:** never claim cryptographic authentication. Verifying signed commits is a possible later
  safeguard.

### 7. Test helper dated in the future (fixed)
- **What happened:** an opening-authorization test fixture carried a timestamp that the future-date check rejected
  as inconsistent.
- **Fix:** the fixture date was set to 05:31:41Z, after every signature.
- **Recommendation:** derive fixture timestamps from the signatures they must follow, not literals.

### 8. Stale statements in the v2 specification (fixed)
- **What happened:** the specification lagged behind the improved-release audit, the re-checks, the identity, the
  ae exclusion and the roadmap.
- **Fix:** corrected in `dd3bfae`.
- **Recommendation:** update the specification at each phase exit, as part of the exit checklist.

## Phase 2 — Config B design and feasibility (in progress)

### 9. CAGE 4 editable install not importable (fixed by pin)
- **Cause:** `setup.py` declares `py_modules=[]`, so modern setuptools maps nothing in editable mode.
- **Fix:** `pip install -e ./cc4 --config-settings editable_mode=compat`. CAGE's code is unchanged. Approved by the
  owner. Record: `docs/spikes/cage4-feasibility.md`.
- **Recommendation:** pin the install command with the commit, and keep the full lock.

### 10. Unpinned `ray[rllib]` pulled a NumPy-2 `pyarrow` (fixed by pin)
- **Cause:** pyarrow 26 requires NumPy 2, and CAGE pins `numpy==1.26.4`.
- **Fix:** `pyarrow==17.0.0`, approved, with the 107-package lock.
- **Recommendation:** resolve once, then always install from the lock.

### 11. Intermittent upstream firewall test, C-1 (open, for Config C)
- **What happened:** `test_blue_agents_can_open_and_close_firewalls` fails in about 5% of runs. Full suite: 679
  passed, 1 failed, 15 skipped.
- **Cause:** its fixture builds an unseeded environment. It is not nondeterminism under a fixed seed.
- **Fix:** none yet. It is not a Config B blocker.
- **Recommendation:** resolve, or explicitly account for, before Config C begins (owner requirement).

### 12. Latent decoy-path `TypeError`, C-2 (open, for Config C)
- **What happened:** found by reading the code, and never exercised. `PIDSelectiveExploitActionSelector` does not
  accept the `priority` argument that `ExploitRemoteService` passes.
- **When it triggers:** only after red discovers a decoy. Blue never deploys decoys in Config B.
- **Recommendation:** check, and fix or work around, before Config C, whose blue may deploy decoys.

### 13. "Monitor" did not test scripted interaction (fixed)
- **Cause:** CAGE 4 runs Monitor automatically every step, so a Monitor-only blue changes nothing.
- **Fix:** a scripted restore-on-alert blue was added to the spike probe. It changed red's actions, successes and
  the reward, and it reproduced exactly.
- **Recommendation:** an interaction test must use an action whose effect is not already automatic.

### 14. Spike wait loop hung (fixed)
- **Cause:** a `pgrep` loop matched its own command line.
- **Fix:** the task was stopped. The episodes had completed.
- **Recommendation:** wait on process IDs or completion files, not on command-line patterns.

### 15. CAGE's exploit selector shapes the action mix (accepted limitation)
- **Cause:** `DefaultExploitActionSelector` sets `odds_of_top_choice = 0`. When several exploits apply, the
  highest-weight one is never chosen. That is why `SSHBruteForce` (weight 0.1) dominates.
- **Fix:** none. CAGE is not modified. The behaviour is frozen and reported. Record:
  `docs/config-b-mapping-draft.md`, section 6.
- **Recommendation:** report the simulator's action distribution as a property of its code, not of attackers.

### 16. B0 defined so that B − B0 would be zero (fixed in design)
- **Cause:** the first draft matched B0 to B per family, from the same pool. Both arms draw uniformly within a
  family, so they would have been the same procedure.
- **Fix:** B0 draws uniformly from the whole seen attack pool, with B's realized total. Approved. Record:
  `docs/config-b-design.md`, section 3.2.
- **Recommendation:** for every control, ask what exactly differs from the treatment, and check it is not zero by
  construction.

### 17. Per-family cap would have displaced real rows (fixed in design)
- **Cause:** applying the 100,000 cap to real and replayed rows together meant B0's replays into `dos` (already at
  the cap) would have pushed out real rows.
- **Fix:** the cap applies to real rows as in Config A, and replays are added on top, so all arms have identical
  distinct rows. Approved.
- **Recommendation:** state invariants such as "same distinct records" explicitly, and test them.

### 18. Compute estimate double-counted nested selection (fixed)
- **What happened:** the first plan projected 181.6 CPU-h, over the 180 CPU-h budget, and was rejected.
- **Cause:** the estimate charged one fit per ordered family pair, but `aegis.experiments.selection` fits each
  unordered pair once and scores both directions.
- **Fix:** corrected to a 152.2 CPU-h ceiling, with nothing removed. Approved. Records: `spikes/cage4/estimate.py`,
  `docs/config-b-design.md`, section 3.5.
- **Recommendation:** derive cost models from the code's actual loops, and measure CPU in a calibration run
  rather than trusting wall time × cores.

### 19. Config A's fit path would not keep "differ only in weights" (fixed in design)
- **Cause:** found by reading `src/aegis/models/baseline.py`.
  - The preprocessor is fitted on the training matrix, so copies could shift medians and push a rare category
    past `min_frequency=20`.
  - `balanced_subsample` treats copies and `sample_weight` differently.
  - `min_samples_leaf` counts copies.
- **Fix:** a Config B wrapper fits preprocessing once on distinct rows and shares it across A, B and B0. Replay is
  encoded as integer copies. Tests T1–T10 and pre-fit invariant checks stop on failure. Config A is unchanged.
  Approved. Record: `docs/config-b-design.md`, sections 3.2.1–3.2.2.
- **Remaining limitation:** the minimum-leaf effect is accepted and documented.
- **Recommendation:** before reusing a frozen pipeline in a new setting, trace every statistic it fits.

### 20. E4 draft would have read validation and test labels (caught before running)
- **What happened:** the first E4 draft tallied `web_attack` labels across all partitions, which would have read
  validation and test rows.
- **Fix:** removed before the run. Only training-partition rows are read.
- **Recommendation:** review every evidence script line by line against its constraints before running, and
  prefer assertions that make a violation impossible.

### 21. E4 run 1 failed the label-reproduction check (fixed; failed run preserved)
- **Cause:** the script located kept rows through `cleaned.X.index`, but `Dataset.__post_init__` resets the index.
- **Fix:**
  - **Run 2:** recomputes the kept mask with `remove_duplicates`' own expression, and uses it only after it
    reproduces Config A's cleaned row count, family array and row hashes exactly. It passed.
  - **Owner approval:** one controlled rerun.
  - **Preservation:** run 1 is kept in `results/config_b_evidence/e4_failed_run_1/`.
- **Recommendation:** never rely on DataFrame indices across Aegis `Dataset` boundaries. Verify alignment against
  the reference output, as the check here did.

### 22. E1 source list named the wrong improved-release paper (fixed in reporting)
- **Cause:** E1 listed Engelen et al. (2021) as "the improved release's paper". Aegis uses the CNS 2022 release
  (Liu, Engelen et al.).
- **Fix:** both were consulted and agree. The discrepancy is reported in `docs/config-b-evidence.md`.
- **Recommendation:** cite datasets from their recorded provenance (`configs/`, the loader docstrings), not from
  memory.

### 23. UNSW-NB15 primary taxonomy papers not openly accessible (accepted limitation)
- **What happened:** the Moustafa and Slay papers are paywalled (ResearchGate returned 403). An unofficial copy was
  deliberately not used.
- **Consequence:** no taxonomy support for any UNSW-NB15 entry. They stay unmapped (owner decision), and Config B's
  primary comparison is limited to improved CICIDS2017. That is not cross-dataset validation.
- **Recommendation:** check source access before designing evidence steps that depend on it.

### 24. Scenario hashes differed from two spike runs (explained; no defect)
- **What happened:** the trajectory hashes of seeds 2 and 3 differed from the spike's.
- **Cause:** those spike runs predate the probe's `sub_action` logging, which changes the logged records and so
  the hash. Every behavioural count matched exactly, and seed 0, logged with `sub_action`, matched the spike's
  final hash.
- **Recommendation:** record the probe's own file hash beside every trajectory hash, so that version differences
  are visible.

### 25. Stage-0 simulator cost was understated (fixed in the plan)
- **What happened:** the plan's stage-0 figure was 2.7 CPU-h. Measured: 3.24 CPU-h for the 250 planned episodes.
- **Cause:** the figure was single-worker wall time per episode. It left out process start-up and imports, and was
  not a CPU ceiling like the Random Forest figures.
- **Fix:** the corrected plan total is 152.7 CPU-h, still inside the 153 planning ceiling. Record:
  `docs/config-b-evidence.md`.
- **Recommendation:** label every estimate as either a ceiling or a point estimate, and replace each with a
  measurement as soon as one exists.

### 26. Scenario bank builder run by accident (verification only; accepted by the owner)
- **What happened:** on 2026-11-10, while the pre-registration amendment was being drafted, `python -I
  spikes/config_b_evidence/scenario_bank.py --help` was run to read its options. The script takes no arguments and
  ignored the flag. It ran in full and rewrote `scenario_bank_manifest.json`.
- **Verification:** the script stops on any mismatch and writes the manifest only after every check passes. It
  completed, so all 250 logs were re-read and passed:
  - each summary's seed, step count (499) and blue policy (`sleep`) were checked;
  - the counts recomputed from the logs equalled the earlier summary;
  - each log's sha256 was recomputed.
- **Outcome:**
  - the rewritten manifest is byte-identical, with sha256
    `11021c5d6371f7744962b2b868e3b86052d28e32a02a0a5aea6c0203f13c222e` before and after;
  - `git status` was unchanged (clean for the manifest);
  - no bank log was written, because the script only reads them.
- **Status:** accepted by the owner (2026-11-10) as a verification-only incident. No simulation ran, no data was
  generated, and nothing else changed.
- **Recommendation:** give scripts that write records an argument parser, and a `--write` flag for the write. Read
  a script's source, not `--help`, when its interface is unknown.

### 27. Two protocol gaps found while implementing the stage runner (draft amendment 1)
- **What happened:** the registered protocol could not be executed as written in two places:
  - **G1:** the selection rule gives no ratio to the seen fold;
  - **G2:** stage 1 fits B's and B0's outer folds before their ratios are selected in stage 2.
- **Found:** by writing the runner against the protocol, before any Config B fit on real data.
- **Fix, proposed:** Config B amendment 1 (draft, unsigned):
  - the seen fold uses the default 0.25;
  - stage 1 fits arm A only, and B's and B0's seed-0 outer folds move to stage 3.
  - The compute total is unchanged. The runner refuses every stage until the amendment is signed.
- **Recommendation:** dry-run a protocol's stage order and every fit's inputs on paper, or in code on synthetic
  data, before registering it.

### 28. UNKNOWN outcomes in the scenario bank (no effect; recorded)
- **What happened:** the bank has 1,250 red steps with outcome UNKNOWN. The seed-0 check had found none.
- **Finding:** every one of them is a `Sleep` action (5 per episode), and `Sleep` is never counted. No count
  changes. The Config B counter applies O6 explicitly, and its counts equal the manifest's.
- **Recommendation:** check outcome rules on the whole bank, not one episode.

### 29. Measured CPU would have left out scoring and loading (fixed before the identity)
- **What happened:** the first draft of the ledger timed only preprocessing and forest fitting. Scoring the test
  and raw rows, and loading the dataset, went unmeasured. That would understate measured CPU against the budget.
- **Fix:** the ledger now measures each fit with its scoring, each inner selection fold, dataset loading, and
  failed fits.

### 30. Notebooks rebuilt after adding the Config B package
- **What happened:** the three Colab notebooks embed the whole `aegis` package, and their tests check it is
  current. Adding `src/aegis/config_b/` made them stale.
- **Fix:** rebuilt with their builders, the documented procedure. Only the embedded source changes. Config A's
  frozen identity is unchanged.

## Recurring lessons
1. **Exact reproduction first.** Rerun before reporting, and treat thread order, library versions and indices as
   suspects.
2. **Report failures as failures.** Preserve the run, don't widen a tolerance, and fix forward under a new
   identity.
3. **Read the frozen code before reusing it in a new setting.** Issues 16–19 and 21 were all caught by tracing the
   real code path, not by assumption.
4. **Make safeguards default-deny and make invariants executable.** Assertions stopped E4 before any count was
   produced.
5. **Keep the decision with the owner.** No automatic fallback, no silent scope cut, and no promotion of a mapping
   without evidence.
