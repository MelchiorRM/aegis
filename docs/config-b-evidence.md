# Config B mapping evidence: E1, E2, E4 results (2026-11-09)

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
| **E4** improved CICIDS2017 `web_attack` composition | **Stopped: label-reproduction check failed.** It stopped before any count was computed or written. The cause is a defect in the E4 script (below), not the data. Not rerun. |

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

## E4 — stopped on the label-reproduction check
- **What happened:**
  - Config A's loader and cleaning ran.
  - The carried raw labels reproduced Config A's families exactly **before** cleaning.
  - **After** cleaning, they did not, so the script stopped.
  - No partition was selected, no count was computed, and nothing was written: `results/config_b_evidence/e4/`
    does not exist.
  - Config A's identity matched afterwards.
- **Cause, found by reading the code, not by rerunning:**
  - The script mapped raw labels to cleaned rows through `cleaned.X.index`, assuming it held the original row
    positions.
  - But `Dataset.__post_init__` (`src/aegis/data/dataset.py`) calls `X.reset_index(drop=True)`, so the cleaned
    index is 0…n−1, and the labels were misaligned.
  - The check worked as designed.
- **Proposed fix, for the owner's approval before any rerun:**
  - Compute the kept-row mask with the same expression `remove_duplicates` uses (row hash of the features, plus the
    family).
  - Then require that the mask reproduces Config A's cleaned output exactly before using it. The row count, the
    family array and a hash of every kept feature row must all equal those of `remove_duplicates`' output.
  - Everything else in the approved procedure, including every assertion and the stop rule, is unchanged.
  - The script would still read no numeric value itself. The hash comparison compares Config A's own row hashes,
    not values.

## Proposed final mapping, for the owner's review (nothing promoted or frozen)
| Entry | Before evidence | Evidence | **Proposed** |
|---|---|---|---|
| `SSHBruteForce` → CICIDS2017 `brute_force` | Approved | — | **Map** (approved) |
| `SQLInjection` → CICIDS2017 `web_attack` | Approved, broad family-level match | E1 confirms SQL injection is a documented subtype, and the smallest one. E4 pending. | **Map**, documented as a broad family-level match. The replayed family is mostly web brute force and XSS. |
| Aggressive and stealth service discovery → CICIDS2017 `portscan` | Approved (high; medium-high) | — | **Map** (approved) |
| `HTTPRFI` → CICIDS2017 `web_attack` | Provisional | E1: no taxonomy support | **Unmapped** |
| `SQLInjection`, `HTTPRFI`, `HarakaRCE`, `FTPDirectoryTraversal` → UNSW-NB15 `exploits` | Provisional | E2 behaviour rule met. E1 taxonomy support not established. | **Unmapped** for now. They remain provisional only if the owner chooses a further evidence route (below). Otherwise, unmapped. |
| All other entries | Unmapped or excluded | — | Unchanged |

**Consequences if this is accepted:**
- **UNSW-NB15:** B = B0 = A on UNSW-NB15. The Config B intervention contrasts are limited to improved CICIDS2017,
  and that is reported as a single-dataset result, not cross-dataset validation.
- **Improved CICIDS2017:** replay goes to `brute_force`, `portscan` and `web_attack`. Without `HTTPRFI`, the
  `web_attack` weight comes from `SQLInjection` alone, 6 attempts in the seed-0 episode.
- **Compute:** the UNSW-NB15 B and B0 fits would not run, so measured CPU would fall below the 152.2 CPU-h ceiling.
  The plan and stop rules are unchanged.

**Routes that could still support the UNSW-NB15 entries. Each is a separate owner decision, and none is
proposed as automatic:**
1. **E1b:** the ground-truth table's attack names and references.
2. **Owner-provided access** to the 2015 or 2016 paper's category definitions, for example through institutional
   access.
3. **Accept** that they stay unmapped.

## Decisions requested
1. Accept or amend the proposed final mapping above.
2. Approve the E4 fix and a rerun of E4, or waive E4 and record its question as open.
3. Choose how the UNSW-NB15 entries are resolved: E1b, paper access, or unmapped.
