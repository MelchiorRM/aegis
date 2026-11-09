# Phase 1 exit review (draft, 2026-11-09)

Checked against the v2 specification, "Phase 1 exit criteria" and "Required safeguards". Each item cites the record
it rests on. This is a draft for the project owner. Phase 1 closes only when the owner accepts it.

## Exit criteria
| Criterion | Status | Evidence |
|---|---|---|
| Artifact audit reported | **Met** | Original release: `results/config_a_artifacts/analysis/FINDINGS.md` (60 comparisons, 8 meet the rule, 5 distinct dependencies; accepted 2026-11-08 as a sensitivity audit). Improved CICIDS2017: `results/config_a_artifacts_improved/analysis/FINDINGS.md` (5 of 16; bot and port scan shortcut-dependent). |
| Three UNSW-NB15 views reviewed | **Met** (2026-11-08) | `results/config_a_artifacts/analysis/FINDINGS.md`, "Three UNSW-NB15 evaluation views"; `results/config_a_artifacts_unsw_views/views_review.txt`. Raw recall stays primary (`38cfa92`); the other two views stay secondary. |
| Protocol fixed | **Met, once the signatures are committed** | Selection: nested leave-one-family-out with the majority rule (`aegis.experiments.selection`). Untouched test: `docs/preregistration/cse_cic_ids2018.md`, registered 2026-11-08T17:07:51Z; amendments 1 and 2 signed 2026-11-09T05:31:40Z. |
| Config A frozen | **Met** | `25685b84dd83f65c` (`python -m aegis.frozen`: matches). Development reference: `results/config_a_improved_25685b84dd83f65c` (commit `e39355f`). Earlier identities: `72166b4d433f5b87` (historical results, intact), `bf0b730d63353ec8` (abandoned, never used). |

## Required safeguards (implemented and tested)
| Safeguard | Status | Evidence |
|---|---|---|
| 1. Nested selection never reads outer test rows | **Met** | `tests/test_safeguards.py::test_nested_selection_never_reads_the_outer_test_rows` and 5 related tests pass. |
| 2. Baseline re-check | **Run and reported** | Original release: rf in 49 of 65 outer folds, fused in 16, ae in none (`results/config_a_selection/analysis/FINDINGS.md`). Improved CICIDS2017: rf in 60 of 60 (`results/selection_check_improved/analysis/FINDINGS.md`). **Caveat:** the ae and fused inputs to these checks are environment-dependent (see "Autoencoder" below). rf's own scores are not. |
| 3. Frozen baseline | **Met** | `verify_config_a` refuses any change to the settings or the implementation hashes (tests pass). |
| 4. Untouched-test guard | **Met as specified** | `aegis.data.external.guarded_load`: needs the pre-registration, the matching frozen identity and signed amendments, and logs every access (tests pass). No access log exists. |

## Gaps to resolve before closing
1. **Commit the signed amendments** (`docs/preregistration/cse_cic_ids2018.json`, `tests/test_safeguards.py`).
2. **The guard does not enforce the opening conditions.** Now that the amendments are signed, `guarded_load` would
   load the 2018 data. Section 9 keeps it closed until Phase 5, after every compared configuration is frozen and
   listed by amendment, and only procedure enforces that today (the data is not downloaded). Proposed: the guard
   also refuses unless a signed amendment declares the opening conditions met, listing every configuration's frozen
   identity (plan sections 9.2 and 10).
3. **Stale statements in the v2 specification** (the owner's document; none changes a result):
   - "Phase 1 results" reports only the original-release audit; the improved-release audit is missing;
   - "Status, 2026-11-08: … The baseline re-check has not been run yet": it has run, on both releases;
   - "CSE-CIC-IDS2018 … a proposal and needs confirmation": the improved release is confirmed and pre-registered;
   - the five-phase roadmap predates the seven-phase plan of 2026-11-09 (Phase 5 is now external evaluation, and
     Phases 6–7 add system integration and operations);
   - the frozen identity is not named.
4. **Insider README status line** still says the UNSW-NB15 views "await review" (local file only).

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
- **Recommendation:**
  - ae and fused stay out of Configs B–E and out of every claim. This changes no plan: the v2 configurations use the
    static RF (B) and the adaptive defender (C–E).
  - Historical ae and fused numbers stay as recorded, with this caveat attached.
  - If anomaly detection returns (the target architecture lists it as a possible detection engine), three things
    come first: a pinned thread count in the configuration, the torch version recorded in its identity, and a
    stability check across thread counts and seeds before any comparison.
