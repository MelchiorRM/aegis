# Config B mapping evidence: E1, E2, E4 results (2026-11-09)

**Revision 2.** E4 was rerun once after its correction (owner approval), and the owner's clarifications are
answered in section "Clarifications". The owner's decisions on revision 1 are recorded in the section of that name.

**Authorization:** E1, E2 and E4 only, under the approved constraints (owner, 2026-11-09). Procedures:
`docs/config-b-mapping-draft.md`, section 5. E1b stays deferred, E3 withdrawn, and CSE-CIC-IDS2018 closed.

**What did not happen:**
- no model was fitted or scored;
- no training data was generated;
- no validation or test record was read;
- no individual row was inspected;
- no numeric feature value was read;
- no mapping was promoted.

**Config A identity:** "Matches the frozen Config A" before and after both data steps, at commit `2b54ef8`.

| Step | Outcome |
|---|---|
| **E1** literature | **Completed for improved CICIDS2017. Incomplete for UNSW-NB15:** its primary papers are not openly accessible. |
| **E2** UNSW-NB15 `exploits` services | **Completed.** Every safety assertion passed. |
| **E4** improved CICIDS2017 `web_attack` composition | **Run 1 stopped** on its label-reproduction check (a script defect), and is preserved. **Run 2, the one controlled rerun approved: completed.** Every check passed before any count was computed. |

## E1 — taxonomy from the datasets' own documentation
- **Method:** sources were fetched on 2026-11-09 and their text extracted with `pypdf` 5.1.0, in a scratch
  environment outside Aegis.
- **Record:** the extractions, SHA-256 hashes and URLs are in `results/config_b_evidence/e1/` (gitignored).
- **Quotations:** verbatim from the extracted text. Line breaks are joined, and the PDF ligature "ﬁ" is shown as
  "fi".

### Improved CICIDS2017 `web_attack`
**S1. Sharafaldin, Lashkari and Ghorbani (2018), ICISSP, doi:10.5220/0006639801080116**
(`scitepress.org/Papers/2018/66398/66398.pdf`):
- **p. 2, Section 1:** "…common updated attacks such as DoS, DDoS, Brute Force, XSS, SQL Injection, Infiltration,
  Port scan and Botnet."
- **p. 4, Section 3, attack profiles:** "Web Attack: This attack types are coming out every day, because
  individuals and organizations take security seriously now. We use the SQL Injection, which an attacker can create
  a string of SQL commands, and then use it to force the database to reply the information, Cross-Site Scripting
  (XSS) which is happening when developers dont test their code properly to find the possibility of script
  injection, and Brute Force over HTTP which can tries a list of passwords to find the administrator's password."
- **p. 5, Table 2 (attack schedule):** "Thurs. | Web and Infiltration Attacks | Web BForce, XSS and Sql Inject."
- **p. 5, Section 4:** "Web attack (Thursday morning): In order to implement this attack scenario, we used Damn
  Vulnerable Web App (DVWA), which is a vulnerable PHP/MySQL web application. In order to automate the attacks in
  XSS and Brute-force section we developed an automated code with Selenium framework. The attacker is a Kali Linux
  and the victim is an Ubuntu 16.04 system as a web server."

**S2. Engelen, Rimmer and Joosen (2021), IEEE SPW, doi:10.1109/SPW53761.2021.00009**
(`lirias.kuleuven.be/retrieve/713070`):
- **Table I (per-class trace counts under successive corrections):** "Web Brute Force 1507 1365 151", "Web Attack
  XSS 652 679 27", "Web Attack SQL 21 12 12".
- **Section V:** "Note that Web Attack - SQL Injection ends up with 12 traces in total, and all 3 test traces are
  mispredicted as Benign. This may be due to the attack being hardly distinguishable from benign traces and poorly
  represented in the training data."

**S3. Liu, Engelen, Lynar, Essam and Joosen (2022), IEEE CNS, doi:10.1109/CNS56114.2022.9947235**
- **Source used:** the improved release Aegis uses. The paper is not openly available, so the authors' public
  CIC-IDS-2017 documentation page was used instead
  (`intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html`). Only the 2017 page was opened; the 2018
  page was not.
- **What the page lists:** its web-attack sections are "8. Web Attack - SQL Injection", "9. Web Attack - XSS" and
  "10. Web Attack - Brute Force".
- **Quotation:** "For all of the web attacks, the authors use the Damn Vulnerable Web App (DVWA). For this attack,
  they did not use the dedicated Password Brute Force page as their target, but instead attacked the initial DVWA
  login screen."
- **Note on E1's source list:** it named S2 as "the improved release's paper". The release Aegis uses is in fact
  S3's (CNS 2022, as `configs/baseline.yaml` and `aegis.data.improved` record). Both were consulted, and they
  agree.

**Finding:**
- **Subtypes:** all three sources document exactly three web-attack subtypes, against DVWA: web brute force, XSS
  and SQL injection.
- **No remote file inclusion:** a case-insensitive search of all three texts for "inclusion" and "RFI" found
  nothing except one false match, the "rfi" inside "surfing".

### UNSW-NB15 `exploits`
- **S4. The dataset's official page** (`research.unsw.edu.au/projects/unsw-nb15-dataset`): "This dataset has nine
  types of attacks, namely, Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode and
  Worms."
- **S5–S6. Moustafa and Slay (2015), MilCIS, doi:10.1109/MilCIS.2015.7348942; (2016), Information Security
  Journal:** not openly accessible. ResearchGate returned HTTP 403, and the publishers are paywalled. A Scribd
  re-upload exists and **was deliberately not used**: it is not an authorized public version.
- **Secondary, checked:** Zoghi and Serpen, arXiv:2101.05067. It gives only the category names.

**Finding:** no accessible passage defines `exploits` beyond its name, or lists its attacks, services or CVEs. That
is an umbrella term only.

### E1 against its decision rule (fixed before running)
| Provisional entry | Taxonomy support? | Reason |
|---|---|---|
| `HTTPRFI` → CICIDS2017 `web_attack` | **No** | The three sources list brute force, XSS and SQL injection only. RFI is never named, and no narrower class containing it is documented. |
| `SQLInjection` → UNSW-NB15 `exploits` | **Not established** | Only the umbrella name is accessible. |
| `HTTPRFI` → UNSW-NB15 `exploits` | **Not established** | as above |
| `HarakaRCE` → UNSW-NB15 `exploits` | **Not established** | as above |
| `FTPDirectoryTraversal` → UNSW-NB15 `exploits` | **Not established** | as above |

**Context for the approved `SQLInjection` → `web_attack` (broad family-level match):** S1 and S3 confirm that SQL
injection is one of the family's three subtypes. S2's counts show it is by far the smallest of the three: 12 traces
after correction in the original release, against 151 and 27. E4 was to measure this in the improved release's
training rows.

## E2 — UNSW-NB15 `exploits`: services observed in training (completed)
- **Run:** `spikes/config_b_evidence/e2_unsw_exploits.py`. Output: `results/config_b_evidence/e2/`.
- **Data:** SHA-256 of `UNSW_NB15_training-set.csv` is `bec7dd5e…48fa`, and of `UNSW_NB15_testing-set.csv`
  `734fe664…a559`.
- **Cleaning:** reproduced Config A's manifest: 257,673 rows before, 40,400 with conflicting labels, 151,239 after.
- **Rows selected:** 15,271 `exploits` rows of the seed-0 training partition.
- **Safety assertions, all passed:** the selected rows are disjoint from the partition's validation and test rows,
  and from the validation and test rows of all 8 held-out folds.
- **Columns read:** `service`, `proto` and `state` only, as aggregate counts.

| `service` | Rows | Share |
|---|---|---|
| `http` | 6,580 | 43.1% |
| `-` (none identified) | 3,917 | 25.6% |
| `smtp` | 2,434 | 15.9% |
| `pop3` | 865 | 5.7% |
| `ftp` | 695 | 4.6% |
| `ftp-data` | 572 | 3.7% |
| `dns` | 141 | 0.9% |
| `ssl`, `dhcp`, `irc`, `radius`, `ssh`, `snmp` | 29, 13, 9, 6, 6, 4 | < 0.2% each |

- **`proto`:** `tcp` 14,836 (97.2%), `udp` 435 (2.8%).
- **`state`:** `FIN` 14,764 (96.7%), `INT` 267, `CON` 235, `RST` 5.
- **By protocol:** `http`, `smtp`, `ftp` and `ftp-data` are 100% `tcp`.

| Provisional entry | Service | `tcp` rows | Behaviour rule (≥ 100 `tcp` rows) |
|---|---|---|---|
| `SQLInjection`, `HTTPRFI` | `http` | 6,580 | **Met** |
| `HarakaRCE` | `smtp` | 2,434 | **Met** |
| `FTPDirectoryTraversal` | `ftp` | 695 | **Met** |

The behaviour rule is necessary, not sufficient (procedure E2). It shows `exploits` contains flows on these
services. It does not show that those flows are these techniques.

## E4 — improved CICIDS2017 `web_attack` composition

### Run 1 — failed, preserved (`results/config_b_evidence/e4_failed_run_1/`)
- **What happened:**
  - The carried raw labels reproduced Config A's families before cleaning, but not after.
  - The script stopped before selecting a partition or computing any count, and wrote nothing.
- **Cause:** it located kept rows through `cleaned.X.index`, which `Dataset.__post_init__` resets to 0…n−1.
- **What is preserved:** the script as it ran (sha256 `0cc0481e…14fe5`), its console output and a status note.

### Run 2 — completed (`spikes/config_b_evidence/e4_cicids_web_attack_v2.py`; output `results/config_b_evidence/e4_run_2/`)
- **The fix:** the kept-row mask is computed with `remove_duplicates`' own expression, and used only after it
  reproduces Config A's cleaned output.
- **Checks passed, in order, before any count was computed:**

| Check | Result |
|---|---|
| Raw labels reproduce Config A's families before cleaning | Pass |
| Mask keeps exactly Config A's cleaned row count (1,705,736) | Pass |
| Mask reproduces Config A's cleaned family array, row for row | Pass |
| Mask reproduces Config A's cleaned rows: the row hash of every kept feature row | Pass |
| Cleaned row count and family counts equal Config A's manifest | Pass |
| Selected rows disjoint from the partition's validation and test rows, and from those of all 4 held-out folds | Pass |
| Config A identity before and after | "Matches the frozen Config A" (commit `df33fcc`) |

- **Columns read:** `Label` and `Attempted Category` only. Day-file SHA-256 values equal those in
  `data/cicids2017_improved/FORMAT_CHECK.md`.

| `web_attack`, seed-0 training partition (62 rows) | Rows | Share |
|---|---|---|
| Web Attack - Brute Force | 41 | 66.1% |
| Web Attack - XSS | 12 | 19.4% |
| **Web Attack - SQL Injection** | **9** | **14.5%** |

**Against E4's fixed rule:**
- 9 SQL-injection training rows is below the floor of 20, so **the approved `SQLInjection` → `web_attack` mapping
  replays mostly other web attacks.**
- 85.5% of the replayed family is web brute force and XSS.
- This is the size of the "broad family-level match" made concrete. It belongs in the frozen table and in every
  report of B.

## Owner decisions on revision 1 (2026-11-09)
1. **E1 findings accepted.** The improved CICIDS2017 taxonomy supports three web-attack subtypes. `HTTPRFI` stays
   unmapped.
2. **E2 findings accepted as descriptive evidence only.** They do not establish technique equivalence. **Every
   UNSW-NB15 mapping stays unmapped.**
3. **E4 correction and one controlled rerun approved,** with the failed run preserved. Done (above).
4. **CICIDS2017 candidates for final approval:**
   - `SSHBruteForce` → `brute_force`;
   - both service discoveries → `portscan`;
   - `SQLInjection` → `web_attack`, as a broad family-level match;
   - `HTTPRFI` unmapped.
   - **The mapping is not frozen until E4 is reviewed.**
5. **UNSW-NB15 `exploits` entries unmapped.** E1b and institutional paper access are deferred. Unofficial copies
   are not used.
6. **The weighting formula is not changed** to compensate for low counts. The actual scenario distribution and its
   limitations are reported.
7. **UNSW-NB15 unmapped:** Config B's primary comparison is limited to improved CICIDS2017. It **cannot be presented
   as cross-dataset validation.**

## Proposed final mapping, for the owner's review (nothing promoted or frozen)
| Entry | Before evidence | Evidence | **Proposed** |
|---|---|---|---|
| `SSHBruteForce` → CICIDS2017 `brute_force` | Approved | — | **Map** (approved) |
| `SQLInjection` → CICIDS2017 `web_attack` | Approved, broad family-level match | E1 confirms it is a documented subtype. E4: 9 of 62 training rows (14.5%) are SQL injection. | **Map**, documented as a broad family-level match. 85.5% of the replayed family is web brute force and XSS. |
| Aggressive and stealth service discovery → CICIDS2017 `portscan` | Approved (high; medium-high) | — | **Map** (approved) |
| `HTTPRFI` → CICIDS2017 `web_attack` | Provisional | E1: no taxonomy support | **Unmapped** |
| `SQLInjection`, `HTTPRFI`, `HarakaRCE`, `FTPDirectoryTraversal` → UNSW-NB15 `exploits` | Provisional | E2 is descriptive only. E1 taxonomy support is not established. | **Unmapped** (owner decision). E1b and paper access are deferred. |
| All other entries | Unmapped or excluded | — | Unchanged |

**Consequences if this is accepted:**
- **UNSW-NB15:** B = B0 = A on UNSW-NB15. The Config B intervention contrasts are limited to improved CICIDS2017,
  and that is reported as a single-dataset result, not cross-dataset validation.
- **Improved CICIDS2017:** replay goes to `brute_force`, `portscan` and `web_attack`. Without `HTTPRFI`, the
  `web_attack` weight comes from `SQLInjection` alone, 6 attempts in the seed-0 episode.
- **Compute:** the UNSW-NB15 B and B0 fits would not run, so measured CPU would fall below the 152.2 CPU-h ceiling.
  The plan and stop rules are unchanged.

**UNSW-NB15 (owner decision 7):**
- Config B's primary comparison is limited to improved CICIDS2017, and cannot be presented as cross-dataset
  validation.
- The routes that could reopen the UNSW-NB15 entries (E1b, institutional paper access) are deferred.

## Clarifications requested by the owner

### C1. The fourth focus service in E2, and why it was not reported against the threshold
- **The fourth service is `ftp-data`:** 572 rows, all `tcp`.
- **Why it was listed:** E2's procedure listed `{http, smtp, ftp, ftp-data}` as focus services for context, because
  FTP sessions use two channels.
- **Why it was not judged:** the decision rule tests only the service each provisional entry targets: `http` for
  `SQLInjection` and `HTTPRFI`, `smtp` for `HarakaRCE`, and `ftp` for `FTPDirectoryTraversal`.
  - `FTPDirectoryTraversal` attacks the FTP server on its control channel (CAGE's TCP 21, process `femitter`).
  - `ftp-data` is the separate data channel.
  - No entry targets `ftp-data`, so it was not tested.
- **If it had been tested:** 572 is above the 100-row threshold. That would change nothing, because the rule is
  necessary but not sufficient, and every UNSW-NB15 entry stays unmapped (decision 2).

### C2. The six `SQLInjection` attempts, and counts for every simulator seed
- **The six came from a single episode:** the spike's seed-0 episode (500 steps, blue `Sleep`). They are not a
  50-episode total.
- **Counts for every planned seed:** see "Scenario distribution". The seed-0 episode's 6 is the per-episode
  median. Each fold seed's 50 episodes give 289–346 attempts.

## Scenario distribution (all 250 planned seeds)
- **What ran (owner approval 2026-11-09):** the unchanged spike probe in the isolated spike environment. Blue
  `Sleep`, 500 steps (499 executed), at most 2 workers.
  - **Seeds:** simulator seed = 1000 × fold seed + episode index, for fold seeds 0–4 and episodes 0–49. The 250
    seeds are unique, and give 250 distinct trajectories.
  - **What was not done:** no dataset, no model, no training data.
  - **Code and outputs:** `spikes/config_b_evidence/scenario_counts.py`; outputs in
    `results/config_b_evidence/scenarios/` (per-episode counts and trajectory hashes). The episode logs are in
    `~/aegis-spike/runs/config_b_seeds/`.
- **Measured compute:** 11,657 CPU-seconds (**3.24 CPU-h**, `RUSAGE_CHILDREN`), and 1.59 h wall.
  - That is above the plan's stage-0 figure of 2.7. That figure was single-worker wall time per episode, not a CPU
    ceiling, and it left out each episode's process start-up and import.
  - Corrected, the plan's total is 152.7 CPU-h. That is still inside the 153 planning ceiling and the 180 budget.
  - If the frozen protocol reuses these episodes instead of regenerating them, stage 0 costs nothing further.
    That would be the owner's decision at the freeze.
- **Reproducibility cross-check:**
  - Seed 0's trajectory hash equals the spike's final-probe hash (`724e864d…`).
  - For seeds 2 and 3, every behavioural count equals the spike's runs exactly: red actions, red successes, blue
    events, blue reward and blue actions.
  - Their hashes differ only because those spike runs predate `sub_action` logging.

### Counts per fold seed (executed actions; in-progress steps never counted)
| Action (outcome rule) | Seed 0 | 1 | 2 | 3 | 4 | Total |
|---|---|---|---|---|---|---|
| **Mapped → `brute_force`:** `SSHBruteForce` attempts (all succeeded) | 2,398 | 2,389 | 2,417 | 2,460 | 2,409 | 12,073 |
| **Mapped → `portscan`:** aggressive + stealth service discovery | 4,046 | 4,043 | 3,991 | 4,045 | 4,017 | 20,142 |
| **Mapped → `web_attack`:** `SQLInjection` attempts (all succeeded) | 346 | 318 | 318 | 318 | 289 | 1,589 |
| `HTTPRFI` attempts, all failed (unmapped) | 672 | 768 | 627 | 702 | 688 | 3,457 |
| `ExploitRemoteService` unreachable (O4, reported separately) | 7,157 | 7,451 | 7,166 | 7,319 | 7,382 | 36,475 |
| `Impact` attempts (successes) | 18,577 (915) | 18,058 (876) | 18,929 (885) | 18,056 (860) | 18,216 (867) | 91,836 (4,403) |
| `DegradeServices` | 18,506 | 17,957 | 18,553 | 18,051 | 17,731 | 90,798 |
| `DiscoverDeception` | 3,727 | 3,901 | 3,619 | 3,792 | 3,674 | 18,713 |
| `PrivilegeEscalate` (`V4L2KernelExploit`) | 2,662 | 2,656 | 2,669 | 2,702 | 2,631 | 13,320 |
| `DiscoverRemoteSystems` | 1,841 | 1,827 | 1,864 | 1,858 | 1,833 | 9,223 |
| **All red actions** | 59,932 | 59,368 | 60,153 | 59,303 | 58,870 | 297,626 |
| No `UNKNOWN` outcome (O6) occurred | | | | | | |

### Family weights B would use (unchanged formula; owner decision 6)
| Fold seed | `brute_force` | `portscan` | `web_attack` | Mapped attempts |
|---|---|---|---|---|
| 0 | 35.3% | 59.6% | 5.1% | 6,790 |
| 1 | 35.4% | 59.9% | 4.7% | 6,750 |
| 2 | 35.9% | 59.3% | 4.7% | 6,726 |
| 3 | 36.1% | 59.3% | 4.7% | 6,823 |
| 4 | 35.9% | 59.8% | 4.3% | 6,715 |

**Per episode (250 episodes), mean ± sd [min–max]:**
- `brute_force`: 48.3 ± 5.8 [33–62];
- `portscan`: 80.6 ± 8.0 [58–99];
- `web_attack` (`SQLInjection`): **6.4 ± 2.6 [0–16]**, and zero in 1 of 250 episodes.

**C2 answered:** the six attempts were one episode, seed 0, which sits at the per-episode median of 6. Over each
fold seed's 50 episodes there are 289–346 attempts.

### Limitations of the scenario distribution
1. **Mapped attempts are a small share of red activity:** 33,804 of 297,626 red actions (11.4%). Local `Impact`
   and `DegradeServices` make up 61% and are unmapped. Unreachable exploits (O4) make up 12.3%.
2. **The weights are very stable across fold seeds,** within about 1 percentage point. Pooling 50 episodes per
   seed averages out episode-level variation. So the five seeds give B almost the same family weights, and seed
   variation in B comes mostly from the data partition, not the scenario.
3. **`web_attack`'s weight (4.3–5.1%) comes from `SQLInjection` alone.** It is an artifact of CAGE's exploit
   selector (issue 15), not attacker behaviour. And 85.5% of the replayed `web_attack` training rows are not SQL
   injection (E4). The weight is reported as it is and not adjusted.
4. **Every mapped attempt succeeded in CAGE** (`SSHBruteForce`, `SQLInjection`, scans). The attempted-versus-
   successful distinction, approved in the outcome rules, therefore changes nothing for the mapped entries. It
   matters only for `HTTPRFI` (all 3,457 failed), which is unmapped.
5. **These are scripted red agents under a sleeping blue.** The distribution describes CAGE 4's
   `FiniteStateRedAgent` against no defence. It is not an attacker population.

## Decisions requested
1. Approve the final mapping of improved CICIDS2017 candidates, now that E4 is complete, or amend it.
2. Note the scenario distribution and its limitations (above).
3. Decide at the freeze whether stage 0 reuses these 250 episodes or regenerates them (the trajectories are
   deterministic and would be identical).
