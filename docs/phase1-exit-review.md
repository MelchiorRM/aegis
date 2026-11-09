# Phase 1 exit review

**Phase 1 is closed.** The project owner (MelchiorRM) accepted this review and approved closing Phase 1 on
2026-11-09, at repository state `dd3bfae`. Phase 2 begins with the Config B design document
(`docs/config-b-design.md`), with no implementation and no experiments until that design is approved.

Checked against the v2 specification, "Phase 1 exit criteria" and "Required safeguards". Each item cites the record
it rests on.

## Findings
1. **The baseline:** Config A is a static Random Forest, frozen as `25685b84dd83f65c`. Measured on held-out attack
   families with leakage-controlled splits, it loses much of its recall on families it has not seen. The development
   reference on improved CICIDS2017 (held-out recall at 1% FPR): bot 0.957, brute force 0.564, DoS 0.998, port scan
   0.444, against 0.9995–1.0 when the family is seen.
2. **Apparent generalization is partly shortcut-driven:**
   - original releases: 5 distinct shortcut dependencies (web-attack near-duplicates, DoS on TCP window features,
     UNSW-NB15 shellcode and reconnaissance on `ct_*` counts, generic on `service`);
   - improved CICIDS2017: bot and port scan depend on TCP window features (5 of 16 comparisons meet the rule);
   - the window does not explain the remaining transfer, and bot transfer depends on port scan being in training
     (a shared internal-host signature is a hypothesis, not a finding).
3. **Dataset integrity matters as much as the model:** cleaning removes 22% of original CICIDS2017 and 41% of
   UNSW-NB15 raw rows (repeats and conflicting vectors), and port scan keeps only 1.2% (original) and 3.3%
   (improved) of its raw rows. Results are therefore reported in three views, with raw rows primary.
4. **The baseline choice survives a test-free re-check:** nested selection picks rf in 49 of 65 outer folds on the
   original data and 60 of 60 on the improved pair.
5. **The autoencoder is not reproducible:** its results change with the PyTorch thread count (port-scan recall
   0.685, 0.661 and 0.146 across environments), so ae and fused are excluded from later configurations.
6. **Scoring is now deterministic:** the Random Forest's multithreaded `predict_proba` was not bit-for-bit
   repeatable. Fixed-order scoring makes rf scores independent of the worker count, and rerunning under the new
   identity reproduced every rf recall and FPR exactly.
7. **The exploratory `no_extractor_features` development run failed its reproduction check** and produced no
   result. It is reported as failed and not reinterpreted.

## Conclusion
- **What Phase 1 established:** a trustworthy, frozen and reproducible baseline, an evaluation protocol that
  separates held-out-family performance from dataset shortcuts, and safeguards in code: nested selection, the
  frozen identity, and a default-deny guard on the external test.
- **What it did not establish:** any generalization claim. Every Phase 1 number comes from development data that
  informed decisions, so none is an unbiased estimate. The only source of final claims is the pre-registered,
  one-time CSE-CIC-IDS2018 evaluation in Phase 5, behind its separate opening authorization.
- **What it means for Phase 2:** later configurations must beat a baseline whose held-out recall is partly
  shortcut-driven, so every comparison with Config A uses the same views, shortcut rule and nested selection.

## Exit criteria
| Criterion | Status | Evidence |
|---|---|---|
| Artifact audit reported | **Met** | Original release: `results/config_a_artifacts/analysis/FINDINGS.md` (60 comparisons, 8 meet the rule, 5 distinct dependencies; accepted 2026-11-08 as a sensitivity audit). Improved CICIDS2017: `results/config_a_artifacts_improved/analysis/FINDINGS.md` (5 of 16; bot and port scan shortcut-dependent). |
| Three UNSW-NB15 views reviewed | **Met** (2026-11-08) | `results/config_a_artifacts/analysis/FINDINGS.md`, "Three UNSW-NB15 evaluation views"; `results/config_a_artifacts_unsw_views/views_review.txt`. Raw recall stays primary (`38cfa92`); the other two views stay secondary. |
| Protocol fixed | **Met** | Selection: nested leave-one-family-out with the majority rule (`aegis.experiments.selection`). Untouched test: `docs/preregistration/cse_cic_ids2018.md`, registered 2026-11-08T17:07:51Z. Amendments 1 and 2 were signed (attested) by MelchiorRM at 2026-11-09T05:31:40Z and committed in `2bf8a22`. |
| Config A frozen | **Met** | `25685b84dd83f65c` (`python -m aegis.frozen`: matches). Development reference: `results/config_a_improved_25685b84dd83f65c` (commit `e39355f`). Earlier identities: `72166b4d433f5b87` (historical results, intact), `bf0b730d63353ec8` (abandoned, never used). |

## Required safeguards (implemented and tested)
| Safeguard | Status | Evidence |
|---|---|---|
| 1. Nested selection never reads outer test rows | **Met** | `tests/test_safeguards.py::test_nested_selection_never_reads_the_outer_test_rows` and 5 related tests pass. |
| 2. Baseline re-check | **Run and reported** | Original release: rf in 49 of 65 outer folds, fused in 16, ae in none (`results/config_a_selection/analysis/FINDINGS.md`). Improved CICIDS2017: rf in 60 of 60 (`results/selection_check_improved/analysis/FINDINGS.md`). **Caveat:** the ae and fused inputs to these checks are environment-dependent (see "Autoencoder" below). rf's own scores are not. |
| 3. Frozen baseline | **Met** | `verify_config_a` refuses any change to the settings or the implementation hashes (tests pass). |
| 4. Untouched-test guard | **Met, strengthened** | `aegis.data.external.guarded_load` denies by default. It needs the pre-registration, signed (attested) amendments, the matching frozen identity, **and** a separate, mandatory Phase 5 opening authorization from the owner (`cse_cic_ids2018.opening.json`). Every access is logged, and the safeguard tests pass. No authorization and no access log exist, and the data is not downloaded. The limitation is below. |

## Gaps found on 2026-11-09, and their state
1. **Signed amendments committed:** done, `2bf8a22`.
2. **The guard did not enforce the opening conditions:** fixed. The new check:
   - requires a separate opening authorization file. Signing amendments never creates it;
   - requires the authorization to be attested by the registered owner (`authorized_by`), with a UTC timestamp
     (`authorized_utc`) no earlier than every amendment's and not in the future;
   - binds it to the exact pre-registration file (sha256), so any later edit voids it;
   - requires phase 5, a confirmation that every configuration and analysis is frozen, and each condition of plan
     section 9.2 confirmed by name;
   - requires it to list each authorized configuration's frozen identity, each equal to the identity recorded by
     signed amendment, with Config A equal to the code's.
   
   Signed amendments alone are refused, and a missing, unattested, mismatched or stale authorization is refused,
   each with a test.
3. **Stale statements in the v2 specification:** corrected. The specification now covers the improved-release
   audit, both re-checks, the confirmed dataset, the current identity, the autoencoder exclusion, the end goal and
   the seven-phase roadmap, with each research question mapped to its phase. The roadmap, the public README and the
   code comments agree: Configs B and C in Phase 2, D and E in Phase 3, cross-dataset tests and ablations in
   Phase 4, CSE-CIC-IDS2018 in Phase 5.
4. **Insider README status line:** fixed (local file).

## Limitation of the guard: attestations, not cryptographic signatures
The signer fields (`amended_by`, `amended_utc`, `authorized_by`, `authorized_utc`) are names and timestamps in
JSON files. The guard checks that they are present, name the registered owner, and are consistent in time and with
the pre-registration's hash. It verifies no cryptographic signature and no signed commit, so it does not
authenticate the signer, and anyone with write access could write these fields. Their integrity rests on the
reviewed git history, in which the owner commits them. The guard prevents accidental or premature opening of the
2018 data, not deliberate circumvention. Verifying signed commits would be a separate, later safeguard.

## Closure
Accepted by the project owner on 2026-11-09. Phase 1 is closed. Phase 2 starts with the Config B design only.
Configs C, D and E have not started, and the 2018 data stays closed until the Phase 5 opening authorization.

## Autoencoder (ae, fused)
- **Finding, 2026-11-09:** the autoencoder is bit-for-bit repeatable at a fixed torch thread count, but changing
  the thread count changes its results.
  - On synthetic data, individual reconstruction errors moved by up to 18%.
  - On the development data (improved CICIDS2017, seed 1, port scan held out), ae recall at 1% FPR was 0.685
    (historical, Colab), 0.661 (local at 2 threads) and 0.146 (local at the default 4 threads).
  - rf was identical in all three.
- **Reading:** thread count explains most of the cross-environment difference, and the torch version and Python the
  rest. More importantly, a tiny numerical change in training moves this ae result by about 0.5, so the ae and fused
  scores are fragile, not only environment-dependent.
- **Decision (owner, 2026-11-09): accepted.**
  - ae and fused stay out of Configs B–E and out of every claim. This changes no plan: the v2 configurations use the
    static RF (B) and the adaptive defender (C–E).
  - Historical ae and fused numbers stay as recorded, with this caveat attached.
  - If anomaly detection returns (the target architecture lists it as a possible detection engine), three things
    come first: a pinned thread count in the configuration, the torch version recorded in its identity, and a
    stability check across thread counts and seeds before any comparison.
