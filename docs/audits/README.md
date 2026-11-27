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
