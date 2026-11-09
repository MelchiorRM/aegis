# Phase 1 exit review (revised 2026-11-09)

Checked against the v2 specification, "Phase 1 exit criteria" and "Required safeguards". Each item cites the record
it rests on. This is a draft for the project owner. Phase 1 closes only when the owner accepts it.

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

## Remaining before closing
- Owner's decision: accept this review and declare Phase 1 closed. Config B does not start before then.

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
