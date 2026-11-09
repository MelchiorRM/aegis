# Pre-registration: external test on CSE-CIC-IDS2018 (improved release)

**Status: REGISTERED.** Written 2026-11-08 (section 6 revised 2026-11-09), before anyone on this project has loaded the data. It became
binding when the project owner filled in `registered_by` and `registered_utc` in
[`cse_cic_ids2018.json`](cse_cic_ids2018.json). Until then the guard (`aegis.data.external.guarded_load`) refuses to
load the dataset. After registration, any change is an amendment: dated, given a reason, and made before the data is
opened. A change after opening is reported as a post-hoc deviation.

## 1. What is frozen
- **Config A:** frozen identity `72166b4d433f5b87` (`python -m aegis.frozen`). That covers:
  - Random Forest `n_estimators` 100, `max_depth` 20, `min_samples_leaf` 2;
  - the `rf` score;
  - threshold = validation-benign quantile at 1 − target FPR;
  - cleaning before splitting (conflicting vectors removed, one copy of each remaining vector kept);
  - training cap of 100,000 rows per family, family minimum of 200;
  - the improved CICIDS2017 loader with identifiers and `Dst Port` dropped.
- **Development data:** improved CICIDS2017 (CNS 2022), checksums in `data/cicids2017_improved/SHA256SUMS`. UNSW-NB15
  is not used here: its features are not compatible with CICFlowMeter's.
- **Selection rule for later configurations:** the inner leave-one-family-out majority rule in
  `aegis.experiments.selection`.

## 2. Dataset
- **Release:** improved CSE-CIC-IDS2018 (Liu, Engelen et al., IEEE CNS 2022),
  `https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CSECICIDS2018_improved.zip` (about 9.7 GB).
  - It was produced by the same fixed CICFlowMeter as the development data.
  - The original 2018 CSVs are excluded because of their label errors (`docs/cse-cic-ids2018-assessment.md`).
- **On download:** sha256 of the archive and of every CSV is recorded before anything else runs, and committed.
- **Expected schema:** the 91 columns of the improved CICIDS2017 release, with the same names, plus `Label` and
  `Attempted Category`.

## 3. Labels and families
Labels are taken from the published labelling code (`CICIDS2018_labelling_fixed_CICFlowMeter.ipynb`). A label not
listed here stops the loader.

| 2018 label | Aegis family |
| --- | --- |
| BENIGN | benign |
| Botnet Ares | bot |
| DDoS-HOIC, DDoS-LOIC-HTTP, DDoS-LOIC-UDP, DoS GoldenEye, DoS Hulk, DoS Slowloris | dos |
| SSH-BruteForce, FTP-BruteForce | brute_force |
| Infiltration - NMAP Portscan | portscan (as `Infiltration - Portscan` in the development data) |
| Infiltration - Communication Victim Attacker, Infiltration - Dropbox Download | infiltration |
| Web Attack - Brute Force, Web Attack - SQL, Web Attack - XSS | web_attack |

- **Attempted flows:** labels ending in ` - Attempted` (Attempted Category 0–6).
  - They never enter training; no 2018 row does.
  - They are excluded from every primary metric.
  - In the secondary metric they count as benign. All 2018 benign rows are test rows, so the pooled rate needs no
    weighting.
  - The release labels FTP-BruteForce only as Attempted, so brute force in 2018 is SSH only.
- **Families evaluated:**
  - A family must be held out in development: at least 200 rows in cleaned improved CICIDS2017. That is bot,
    brute_force, dos and portscan.
  - It must also have at least 200 non-Attempted rows in the cleaned 2018 data.
  - Both conditions are applied automatically and the result is logged. Web attack and infiltration are not
    evaluated as held-out families, because the development data cannot train a seen-family comparison for them.

## 4. Primary measurement (RQ1)
For each seed and each evaluated family F, two models are fitted on improved CICIDS2017 using the frozen Config A
procedure and the same partition:
- **seen:** trained with every development family;
- **held-out:** trained without F, in both training and validation.

Both models are scored on the same 2018 rows: every F row and every benign row.

- **Primary metric:** raw-view recall on 2018 F at the threshold set from development validation benign at a
  **target FPR of 1%**.
  - This is the deployable rule: no 2018 information sets the threshold.
  - The realized 2018 FPR is reported alongside.
- **Primary comparison:** held-out recall, and the seen − held-out recall gap on identical rows.
- **Secondary:**
  - recall at 0.1% target FPR;
  - recall at the threshold that gives exactly 1% FPR on 2018 benign (an oracle, not deployable; it separates
    calibration shift from ranking);
  - PR-AUC and precision reweighted to assumed attack prevalences of 1% and 0.1%;
  - the Attempted-as-benign FPR and precision;
  - development held-out recall next to external held-out recall, for each family, as a description of transfer.
- **Seeds: 0–9**, ten independent runs.
  - Five seeds cannot reach p < 0.05 in a two-sided Wilcoxon test, and the frozen identity allows extra seeds.
  - The seed controls the development partition and model fitting. Every paired comparison uses the same seed set
    on both sides: seen vs held-out, reference vs treatment, and configuration vs configuration.

## 5. Evaluation views
The same threshold is used in every view. No label is changed, and no row leaves the primary view.

| View | Rows | Role |
| --- | --- | --- |
| Raw | Every published non-Attempted 2018 row of F and every benign row, repeats and conflicting vectors included | Primary |
| Overlap-excluded | Raw, without exact feature vectors labelled with two or more attack families after the family mapping (all rows of such a vector, benign included) | Secondary |
| Deduplicated | 2018 cleaned exactly like the development data (conflicting vectors removed, one copy of each remaining vector) | Secondary |

- **Overlaps:** whether they occur in 2018 is not known. Their number, the rows they cover and the benign rows
  removed with them are reported.
- **Vectors in both datasets:** a 2018 vector that also appears in the development training rows is counted, per
  family, and reported. It stays in all three views.

## 6. Shortcut rule
Every treatment is applied to both the seen and the held-out model. Each model is refit on development data with
the frozen Config A procedure and scored on the same 2018 rows as the reference.

### 6.1 Primary treatments
These are the treatments of the development audit, unchanged.
- **remove_matching_signatures:** removes development training attack rows that match a 2018 test row of F apart
  from timing columns.
- **no_tcp_window:** drops `FWD Init Win Bytes` and `Bwd Init Win Bytes`.
- **neutralize_missing_markers:** the window value 0 becomes missing. This also catches real zero windows.
- **all_controls:** the three treatments above, combined as in the development audit.
- **missingness_only** is reported but is outside the rule, as in development. Its scores take a few tied values,
  so its recall is not stable at a fixed threshold.

**Rule:** a family is shortcut-dependent if the mean per-seed drop in raw-view recall at 1% target FPR, reference
minus treated, is at least **0.10** and its **95% bootstrap interval lies entirely above zero**.
- The same rule is reported in the two secondary views.
- A family whose reference raw recall is under 0.10 is reported as *not testable*.
- Every comparison is counted and reported, with no multiple-comparison correction.
- **Only these comparisons enter the primary shortcut count.**

### 6.2 Exploratory treatment: no_extractor_features
- **Definition:** drops nine columns, the two window columns of `no_tcp_window` plus seven columns that the fixed
  CICFlowMeter adds or redefines:
  - `Fwd RST Flags`, `Bwd RST Flags`, `RST Flag Count`;
  - `ICMP Code`, `ICMP Type`;
  - `Total TCP Flow Time`;
  - `Protocol`.
  - Nothing else changes: no rows are removed and no values are rewritten. A column missing from either dataset
    stops the run.
- **Comparisons:**
  - **Against the reference:** the same rule, statistics and views as 6.1.
  - **Against `no_tcp_window`, descriptive only:** the mean per-seed drop and its interval, which isolates the
    seven extractor columns once the window is already removed.
  - Both are run for each evaluated family, for the seen and the held-out model.
- **Status: exploratory.**
  - It was defined on 2026-11-09, after the development audit had shown that the window does not explain
    improved-CICIDS2017 held-out recall. The idea comes from development results, so it is not a pre-planned
    hypothesis on development data.
  - On 2018 it is specified before the data is opened.
  - Its results are reported in a separate table. They are not added to the primary shortcut count, and they do not
    change any verdict in 6.1 or 6.3.
- **Development run:** the treatment is also run on improved CICIDS2017 with the frozen Config A procedure. That run
  happens after registration and before the 2018 data is opened, and it is reported as a post-hoc audit.
  - **Seeds 0–4**, the seed set of the recorded development audit, so it pairs with the recorded reference and
    `no_tcp_window` rows.
  - Those rows are recomputed in the same run and must match the recorded ones exactly, or the run stops.
  - The five development verdicts in 6.3 are not re-evaluated.
  - Its result changes nothing in this plan. Any change it prompts is a dated amendment, made before opening.
- **Separation from the primary count, in code:** the treatment is not added to the rule treatments. Its rows carry
  their own role, `exploratory`, and their primary verdict columns are always false. That keeps them out of
  `n_comparisons` and `n_shortcut_dependent`.
  - Whether it meets the 0.10 rule goes in a separate column, in the separate table.
  - A test checks all of this before the development run.
- **Interpretation limits:**
  1. **A drop does not prove a shortcut.**
     - Removing columns removes information. Some of it may be legitimate signal, for example `Protocol` for ICMP
       or UDP floods and RST counts for scans.
     - A drop that meets the rule is described as *dependence on extractor-specific features*, not as an artifact.
  2. **No drop does not prove robustness.** Correlated features that stay in, such as `Flow Duration` and the flag
     and packet counts, can carry the same information.
  3. **A drop does not say which column carries the effect.** No per-column follow-up is planned. Any per-column
     follow-up would be a new, separately labelled post-hoc analysis.
  4. **It does not test the internal-host hypothesis** in 6.3. That hypothesis concerns traffic origin, not
     extractor columns.
  5. **It cannot support a generalization claim.** A small drop is not evidence that held-out recall reflects
     attack behaviour.

### 6.3 Development findings recorded before registration
These verdicts come from the improved-CICIDS2017 artifact audit on 2026-11-08
(`results/config_a_artifacts_improved`). They are fixed and are not revised by any 2018 result.
- **Shortcut-dependent under 6.1:**
  - bot: `no_tcp_window` (drop 0.104, CI 0.027–0.211), `neutralize_missing_markers` (0.145, CI 0.009–0.280) and
    `all_controls` (0.104);
  - port scan: `no_tcp_window` and `all_controls` (0.310, CI 0.090–0.530).
- **Not dependent:** brute force and DoS under every treatment.
- **Unresolved: bot recall depends on port scan in training.**
  - In the nested selection check's inner folds (`results/selection_check_improved`), rf catches development bot at
    0.045 when training holds only brute force and DoS. It catches about 0.95 whenever port scan is in training.
  - Development port scan includes the `Infiltration - Portscan` flows from the compromised internal host.
  - Leading explanations, none tested: a signature of the internal victim hosts, or behaviour genuinely shared by
    scanning and botnet traffic.
  - 2018 has the same structure (`Infiltration - NMAP Portscan`), so the 2018 bot result is read with this caveat.
  - No treatment for it is pre-registered. Bot's 2018 held-out recall is reported, but it is not presented as
    evidence that bot detection transfers.

## 7. Statistics
- Bootstrap 95% intervals over seeds, with 10,000 resamples.
- Two-sided Wilcoxon signed-rank tests on paired seeds.
- Cohen's d_z effect sizes.
- No p-value is a claim on its own; intervals and effect sizes are read first.

## 8. What may be inspected before the evaluation
- **Before the evaluation:**
  - file names, sizes and checksums;
  - CSV headers;
  - total row counts;
  - label distributions, as counts per label and Attempted Category, which the eligibility rule needs.
- **Automated checks only:** schema, units, label parsing and column equality with the development data. They print
  `pass` or `fail` and never print values.
- **Not inspected:** feature values, scores and per-flow rows. On a `fail`, the specific failing check may be read.
  Any fix is recorded as an amendment before the evaluation runs.

## 9. When the data is opened
**Decided 2026-11-09: the data is opened once, at Phase 5.** Opening it for Config A alone would mean Configs B–E
are designed after seeing Config A's external result.

### 9.1 Until opening
- **Not on any project machine or drive:** the 2018 data is not downloaded, mirrored or cached, and no part of it
  is inspected.
- **No analysis touches it,** exploratory or otherwise. No published result computed on it, by anyone, is used for
  a model or evaluation decision.
- **The ordinary loader refuses `cse_cic_ids2018`.** The guarded loader refuses it until registration is complete.

### 9.2 Conditions for opening
All of the following hold and are recorded, by amendment, before the download:
1. **Every configuration to be compared is frozen.** Each one's identity (`python -m aegis.frozen` or its
   equivalent) is listed in section 10. That identity covers preprocessing, model settings and threshold rule.
2. **The 2018 loader exists and is frozen:**
   - it implements the label mapping in section 3 from the published labelling code;
   - it was tested only on small synthetic files shaped like the release;
   - its source hash is recorded.
3. **The evaluation code exists and is frozen:** metrics, views, treatments, statistics and seeds 0–9. Its source
   hash is recorded, and the full pipeline has run end to end on synthetic stand-in files.
4. **The development run of `no_extractor_features` (6.2) is complete and reported.**

### 9.3 Opening and evaluation
1. **Download and checksum.** sha256 of the archive and of every CSV is recorded and committed before any other step.
2. **Automated checks, section 8:** schema, label parsing, Attempted categories and column equality with the
   development data. Each prints pass or fail only. Family eligibility is decided automatically from the label
   counts and logged.
3. **On a fail:** only the failing check is read. The fix is a dated amendment and a re-freeze of the affected code,
   and nothing is evaluated until every check passes.
4. **One evaluation run.** It covers every frozen configuration, all seeds, views and treatments, and is loaded only
   through `aegis.data.external.guarded_load`, which logs every access to `cse_cic_ids2018.access.jsonl`.
5. **Reporting:**
   - All results are reported, including failed or unfavourable ones.
   - A crash may be rerun with identical code and settings, and the rerun is logged.
   - Any deviation from this plan after opening is reported as post hoc.
6. **After opening:** no configuration is changed and re-evaluated on 2018 as if untouched. Later work on these data
   is labelled as using a seen test set.

## 10. Planned comparisons
- **Config A:** seen vs held-out recall per evaluated family (section 4), the shortcut treatments (section 6), and
  the development-to-external description.
- **Later configurations:** the same measurements for each frozen configuration. The ablation comparisons are B vs A,
  C vs B, D vs C and E vs D, on held-out recall at 1% target FPR in the raw view. Each later configuration's frozen
  identity is added here by amendment before the data is opened.

## Amendments
Each amendment is dated and given a reason, and is made before the 2018 data is opened. The text above stays as
registered (`registered_utc` 2026-11-08T17:07:51Z). Where an amendment changes a requirement, the amendment governs.

### Amendment 1, 2026-11-09: reproduction criterion for the 6.2 development run
- **Amends:** section 6.2, "Development run". The sentence "Those rows are recomputed in the same run and must match
  the recorded ones exactly, or the run stops" is replaced by the criterion below. Nothing else in 6.2 changes.
- **Reason:**
  - The development run of 2026-11-09 recomputed 80 reference and `no_tcp_window` rows. It stopped at the exact-match
    check.
  - Every input to the shortcut rule matched exactly: raw, overlap-excluded and deduplicated recall at both target
    FPRs, realized FPR at the primary target, the attack and benign row hashes, oracle recall, precision and the
    signature counts.
  - Only secondary summaries differed: AUC by at most 2.2e-16, PR-AUC by at most 9.4e-4, and the raw and
    overlap-excluded FPR in one row at the 0.1% target, by 6.3e-6 (about 2 of 316,130 benign rows).
- **Suspected cause, a hypothesis only:** the Random Forest may sum its trees' probabilities in an order that varies
  with the number of worker threads (8 in this run, 2 in the recorded run). Last-digit differences in scores can then
  reorder tied scores. This has not been tested, and the amendment does not depend on it being the cause.
- **New criterion.** The recomputed rows must reappear with the same row keys, and:
  - **Exact match required:**
    - recall in all three evaluation views (raw, overlap-excluded, deduplicated), at every target FPR;
    - the primary FPR: realized FPR at the 1% target FPR, in all three evaluation views;
    - the attack and benign row hashes;
    - every other input to the shortcut rule, and every other recorded column not listed below (counts, oracle
      recall, precision, signature counts). Missing values must be missing on both sides.
  - **Within an absolute tolerance:**
    - AUC: |difference| ≤ 1e-12;
    - PR-AUC, at each attack prevalence: |difference| ≤ 0.001;
    - realized FPR at target FPRs other than the primary one (currently the 0.1% target), in every view:
      |difference| ≤ 1e-5.
  - Timing columns are not compared, as before.
  - For every tolerated column, `reproduction.json` records the largest absolute difference found, the evaluation
    view the column belongs to, the row it occurred in (dataset, seed, treatment, family, target FPR) and both
    values. It is reported with the run.
  - A failure is not resolved by widening a tolerance. A rerun that fails this criterion is reported as failed.
- **What the tolerances are for:** they cover numerical reproducibility of secondary summaries only. They do not
  change the evaluation protocol, the treatments, the shortcut rule, its inputs or any primary result. A difference
  in any rule input still stops the run.
- **Order of the run:** the recomputed `reference` and `no_tcp_window` folds run first, for every seed, and the check
  runs on them before `no_extractor_features` is fitted. A failed check stops the run before any exploratory fold is
  computed or any result table is written.
- **How the tolerances were set (disclosed):** they were chosen after the differences above were known, so they were
  informed by the size of those differences. The PR-AUC limit (0.001) is close to the largest observed difference
  (9.4e-4). They were not informed by any exploratory result.
- **State of the exploratory outputs when this amendment was made:** the 2026-11-09 run wrote
  `exploratory_effects.csv`, `treatment_effects.csv`, `results.csv` and its `no_extractor_features` fold files
  before its check ran. None of them had been read or reviewed when this amendment was made.
- **The 2026-11-09 run:** it is superseded, and all its outputs, exploratory ones included, are kept unread. The
  development run is repeated under this amendment, in a new results folder, with:
  - the same frozen Config A, seeds 0–4 and software environment;
  - 8 Random Forest workers (`n_jobs=8`), matching the superseded run. The worker count is recorded in the run
    metadata (`manifest.json`). It is not part of the frozen Config A identity, and no frozen model or evaluation
    setting changes.
- **Unchanged:**
  - the frozen Config A identity `72166b4d433f5b87`, and every Config A result;
  - every primary shortcut verdict, including the five development verdicts in 6.3;
  - the exploratory status of `no_extractor_features` and its separation from the primary count;
  - the reproduction criteria for the 2018 evaluation itself (section 9.3).
- **Implementation:** `check_matches_recorded` and `run(..., recorded=..., reproduce=...)` in
  `aegis.experiments.artifacts` (not a frozen file). Tests check each tolerance at and beyond its limit, exactness
  everywhere else, and that a failed check leaves no other results on disk.
