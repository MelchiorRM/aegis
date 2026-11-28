# Config B audit evidence

Read-only checks that ran around Config B stages, with their outputs. None of these files is part of the
Config B identity (`7b900fea59b6cf35`), and none of them changes the experiment. Hashes of every file here are
in `SHA256SUMS`.

## Stage 3 (owner authorization 2026-11-27)

| File | What it is |
|---|---|
| `config_b_prestage3_check.py` | The read-only check that ran before stage 3: both selection files, the ratios stage 3 would use, the neither-family control, identities, ledger, and separation of held-out data |
| `config_b_prestage3_check.log` | Its output just before stage 3 started: all checks passed |
| `config_b_pre_stage3_results_sha256.txt` | SHA-256 of the 137 result files that existed before stage 3, excluding the ledger |
| `config_b_pre_stage3_ledger.csv` | The compute ledger as it stood before stage 3 (74 rows) |
| `config_b_poststage3_check_initial_buggy.py` | The first version of the post-stage-3 check, with a filtering bug (below) |
| `config_b_poststage3_check_initial_failed.log` | Its failed output, reproduced (below) |
| `config_b_poststage3_check.py` | The corrected post-stage-3 check |
| `config_b_poststage3_check.log` | Its output: all checks passed |
| `config_b_post_stage3_results_sha256.txt` | SHA-256 of all 279 result files after stage 3, including the ledger. It is the baseline for checking that later stages preserve the stage 3 outputs |
| `config_b_post_stage3_full_test_suite.log` | Complete output of the full test suite after stage 3 |

### The first post-stage-3 check failed because of a bug in the check, not in the run

- **What failed:** the line `FAIL [1] 14 fit rows, by arm {'A': 4, 'B': 5, 'B0': 5}`. Every other line passed.
- **Cause:** the check counted a ledger row as a fit when its label had exactly three colons
  (`r["label"].count(":") == 3`). Fit labels have the form `<arm>:reference:<fold>:seed<n>`. The seen fold is
  `A:reference:seen:seed1`, with three colons. A held-out fold is `A:reference:holdout:bot:seed1`, with four.
  So only the 14 seen-fold fits were counted, and the 56 held-out fits were listed as non-fit rows. The stage's
  fit CPU appeared as 0.9573 CPU-h and the CPU outside fits as 3.1339 CPU-h.
- **Fix:** a fit row is any row whose label contains `:reference:`. That is the only change between the two
  scripts (line 30). The corrected check counts 70 fits (A 20, B 25, B0 25), 4.0169 CPU-h in fits, and 0.0743
  CPU-h outside fits. The stage total, 4.0912 CPU-h, is the same in both runs, because the bug only moved rows
  between the two groups.
- **The ledger and the run were never affected.** The runner records its own rows. Only this check misread them.
- **About the failed log:** the original failed run printed to the terminal and was not saved to a file. The
  log here is a reproduction. The buggy script was run again, read-only, against the same saved inputs: the
  ledger and results are unchanged since stage 3 finished, as `config_b_post_stage3_results_sha256.txt` shows.
  Its key lines match the original terminal output exactly: the 14 fit rows by arm, 0.9573 CPU-h in fits and
  3.1339 CPU-h outside.

### How to rerun the checks

```
.venv/bin/python -I docs/audits/config_b_poststage3_check.py \
    docs/audits/config_b_pre_stage3_results_sha256.txt docs/audits/config_b_pre_stage3_ledger.csv
.venv/bin/python -I docs/audits/config_b_prestage3_check.py   # Only meaningful against the pre-stage-3 state.
```

## Stage 4a (owner authorization 2026-11-27)

Stage 4a is the shortcut audit of arm B: 5 seeds x 4 held-out families x 5 treatments (the four of the decision
rule and `missingness_only`), each at B's selected ratio. The checks cover execution integrity only: no score is
read or compared.

| File | What it is |
|---|---|
| `config_b_pre_stage4a_ledger.csv` | The compute ledger as it stood before stage 4a (147 rows) |
| `config_b_post_stage3_fingerprints_reconstructed.json` | The fingerprint registry as it stood after stage 3, rebuilt (below) |
| `config_b_poststage4a_check_initial_buggy.py` | The first version of the post-stage-4a check, with a comparison bug (below) |
| `config_b_poststage4a_check_initial_failed.log` | Its failed output, saved when it ran |
| `config_b_poststage4a_check.py` | The corrected post-stage-4a check |
| `config_b_poststage4a_check.log` | Its output: all checks passed |
| `config_b_post_stage4a_results_sha256.txt` | SHA-256 of all 480 result files after stage 4a, including the ledger. It is the baseline for checking that later stages preserve the earlier outputs |
| `config_b_post_stage4a_full_test_suite.log` | Complete output of the full test suite after stage 4a (218 passed) |

### The first post-stage-4a check failed because of a bug in the check, not in the run

- **What failed:** the line `FAIL [1] stage_4a.done's figures for the bank and stages 1 to 3 equal the ledger`.
  Every other line passed.
- **Cause:** the check compared the bank (`"0"` in `stage_4a.done`, 3.2381 CPU-h) with `ledger.measured_hours("0")`.
  The bank is not stored as ledger rows: it is the constant `protocol.STAGE0_SPENT_CPU_HOURS`, which
  `Ledger.total_hours()` adds. So the ledger side was always 0.0. Stages 1, 2a, 2b and 3 matched exactly.
- **Fix:** the bank is compared with the protocol constant, and stages 1 to 3 with the ledger. That is the only
  change between the two scripts (lines 53 to 55).
- **The ledger and the run were never affected.** Only this check misread the bank.
- Unlike stage 3, the failed log here is the original output, saved when the check first ran.

### The rebuilt post-stage-3 fingerprint registry

Stage 4a extends `preprocessing_fingerprints.json` with 100 entries, so its post-stage-3 hash no longer applies, and
no copy of the old file was kept. To check that none of the 55 earlier entries changed, the 100 audit entries were
removed from the current registry and the rest written back in the registry's own format
(`json.dumps(..., indent=1, sort_keys=True)`). The result has SHA-256 `bf8cab4c1d70ddb9...`, exactly the hash
recorded for the registry in `config_b_post_stage3_results_sha256.txt`. So the 55 earlier entries are byte-for-byte
unchanged, and the rebuilt file is the post-stage-3 registry.

### How to rerun the check

```
.venv/bin/python -I docs/audits/config_b_poststage4a_check.py \
    docs/audits/config_b_post_stage3_results_sha256.txt docs/audits/config_b_pre_stage4a_ledger.csv \
    docs/audits/config_b_post_stage3_fingerprints_reconstructed.json
```

It is meaningful only while the results are in their post-stage-4a state: once stage 4b runs, the ledger gains
rows of another stage.

## Stage 4b (owner authorization 2026-11-29)

Stage 4b is the shortcut audit of arm B0: 5 seeds x 4 held-out families x 5 treatments, each at B0's selected ratio.
The checks cover execution integrity only: no score is read or compared.

| File | What it is |
|---|---|
| `config_b_pre_stage4b_ledger.csv` | The compute ledger as it stood before stage 4b (250 rows) |
| `config_b_pre_stage4b_fingerprints.json` | The fingerprint registry as it stood before stage 4b, copied before the run (155 entries) |
| `config_b_poststage4b_check_initial_buggy.py` | The first version of the post-stage-4b check, with a bug in its expected file set (below) |
| `config_b_poststage4b_check_initial_failed.log` | Its failed output, saved when it ran |
| `config_b_poststage4b_check.py` | The corrected post-stage-4b check, adapted from the stage 4a check |
| `config_b_poststage4b_check.log` | Its output: all checks passed |
| `config_b_post_stage4b_results_sha256.txt` | SHA-256 of all 681 result files after stage 4b, including the ledger. It is the baseline for checking that later stages preserve the earlier outputs |
| `config_b_post_stage4b_full_test_suite.log` | Complete output of the full test suite after stage 4b (218 passed) |

Stage 4b did not change the fingerprint registry: B0's audit folds reuse the 155 fingerprints already registered,
since the registry is shared across arms. Only the ledger changed among the 480 files that existed after stage 4a.

### The first post-stage-4b check failed because of a bug in the check, not in the run

- **What failed:** the line `FAIL [2] folds/ holds exactly the 75 reference + 100 audit files (275)`. It listed
  the 100 arm B audit files of stage 4a as unexpected. Every other line passed.
- **Cause:** when the stage 4a check was adapted to B0, the expected set of fold files kept only the stage 3
  reference files and the new B0 audit files, and left out the B audit files from stage 4a. Those files were
  present and unchanged: the preservation check against `config_b_post_stage4a_results_sha256.txt` passed.
- **Fix:** the expected set includes the audit files of both B and B0. That is the only change between the two
  scripts (lines 99 to 103).
- **The ledger and the run were never affected.**

### How to rerun the check

```
.venv/bin/python -I docs/audits/config_b_poststage4b_check.py \
    docs/audits/config_b_post_stage4a_results_sha256.txt docs/audits/config_b_pre_stage4b_ledger.csv \
    docs/audits/config_b_pre_stage4b_fingerprints.json
```

It is meaningful only while the results are in their post-stage-4b state.
