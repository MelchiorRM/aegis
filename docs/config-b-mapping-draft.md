# Config B action-to-family mapping — DRAFT, revision 2, for owner review

**Status: draft, not frozen, not used.** Revision 2 stands, with the owner's 2026-11-09 approvals recorded in section 5.
- **History:** revision 1 was drafted on 2026-11-09. Revision 2 (also 2026-11-09) applies the owner's decisions on
  revision 1.
- **What has not happened:** no training data was generated, no record was replayed, no model was run, no dataset
  was opened, and no evidence step (section 5) has run.
- **Evidence used:**
  - CAGE 4's source at commit `8c3c50ca54b176c2de199847944e8dcc035497e3`;
  - one spike episode (seed 0, blue `Sleep`);
  - the families' documented definitions;
  - the cleaned family counts already recorded in Config A's manifest.
- **Freezing:** no provisional entry is frozen without evidence. The table is frozen only through the
  pre-registration amendment, before any Config B result exists.

## 1. Rules
- **Evidence:** the concrete exploit or scan, its target service and protocol, and its technical behaviour.
  - No abstract category (`Impact`, `DegradeServices` and so on) is mapped as such.
  - A shared port is never enough.
- **Ambiguous actions stay unmapped:**
  - **Ambiguous** means the behaviour fits two families equally, or fits no family's documented behaviour closely
    enough to stand in for it.
  - **Taxonomy support:** shared membership in a broad umbrella category (for example "web attack") is not, by
    itself, taxonomy support (owner, 2026-11-09).
- **No forced mappings:** UNSW-NB15 is never mapped just to make Config B active on both datasets. If nothing is
  justified there, B = A on UNSW-NB15, and that is reported.
- **Families and replay pool:** mapped families are Config A's families. Replay draws only from the current fold's
  training rows of the family, and selects nothing when that family is held out.

## 2. Outcome handling (approved, owner 2026-11-09)
| Rule | Outcome | Counted? | Basis |
|---|---|---|---|
| **O1** | **In-progress step** | **Never**, and never treated as success | CAGE executes a multi-tick action once, on its last tick. On earlier ticks the agent's recorded action is `Sleep` and its observation `IN_PROGRESS` (`SimulationController.py`, the tick loop). In the seed-0 log, no non-`Sleep` red action carried `IN_PROGRESS`. |
| **O2** | **Executed, reached a service, succeeded** | Once, as an attempt | The attempt crossed the network. Success is logged and reported. |
| **O3** | **Executed, reached a service, failed** | Once, as an attempt | CAGE checks the vulnerability only after it contacts the service (`ExploitAction.sim_exploit`), and a blocked attempt leaves a connection event at the blocking host. Success is not the inclusion criterion. |
| **O4** | **Executed, failed before reaching any service** | **No.** Reported separately as "unreachable failed exploits" | `ExploitRemoteService` returned before choosing an exploit: no session, unknown ports, a blocked route between subnets, or no applicable exploit. Seed 0: **159** of 228. |
| **O5** | **Exploit reached a decoy service** | Once, as an attempt, flagged | Traffic reached the decoy. |
| **O6** | **`UNKNOWN`** | No; reported separately | None in seed 0. |

- **Each executed action is counted once.** Per episode and seed, the report lists each mapped action's attempted
  and successful counts, the O4 and O6 counts, and the unmapped actions' counts.
- **Improved CICIDS2017's "Attempted" rows are not used.** They are outside Config A's training data.

## 3. Mapping table, revision 2
**Status key:**
- **Approved:** the owner approved it. It is still frozen only with the protocol.
- **Provisional:** unmapped unless the evidence in section 5 supports it before the freeze.
- **Unmapped** and **excluded:** unchanged from revision 1.

Seed-0 counts are attempts executed (successful).

| Concrete action (CAGE 4) | Target service / protocol | Candidate family | Technical justification and evidence | Network activity expected? | Outcomes | Confidence | Status |
|---|---|---|---|---|---|---|---|
| **`SSHBruteForce`**. Seed 0: 52 (52) | SSH, TCP 22 | CICIDS2017 `brute_force` | The family is SSH-Patator and FTP-Patator runs, automated password guessing against a login service (ATT&CK T1110.001). `SSHBruteForce` is password guessing against SSH. Replay is family-level, so FTP-Patator rows are replayed too: same technique, another service. | Yes: repeated TCP sessions to port 22, whatever the outcome | O2, O3 | High | **Approved** |
| | | UNSW-NB15: none | No credential-guessing family. | Yes | — | — | **Unmapped** (owner) |
| **`SQLInjection`**. Seed 0: 6 (6) | Database process on TCP 3390, selectable only when the host also serves 80 or 443: injection through a web front end | CICIDS2017 `web_attack` | **A broad family-level match, not an exact attack equivalence.** The family pools three CIC web-application attacks run over HTTP: web brute force, XSS and SQL injection. One of the three is the same technique. What is replayed is the whole family, of which SQL injection is only a part (E4 counts that part). CAGE's port 3390 is a modelling artifact, not evidence. | Yes: HTTP requests to the web front end | O2, O3 | Medium-high | **Approved, broad family-level match** |
| | | UNSW-NB15 `exploits` | The documented definition, leveraging a known software vulnerability, is broad. Support needs evidence from the dataset's actual taxonomy (E1) and its observed services (E2). | Yes | O2, O3 | — | **Provisional (E1, E2)** |
| **`HTTPRFI`**. Seed 0: 11 (0) | Web server with the `rfi` property, HTTP, TCP 80 | CICIDS2017 `web_attack` | The same delivery as the family (injected input in HTTP requests). However, remote file inclusion is not one of the family's documented attacks, and shared membership of the umbrella "web attack" is not enough. It needs E1 to find RFI, or a technique the family documents that RFI is an instance of. **Expected outcome, stated now:** revision 1's summaries list only brute force, XSS and SQL injection, so it is likely to stay unmapped. | Yes, including failed attempts | O3 is the common case | — | **Provisional (E1)** |
| | | UNSW-NB15 `exploits` | As for `SQLInjection`. | Yes | O2, O3 | — | **Provisional (E1, E2)** |
| **`HarakaRCE`**. Seed 0: 0 | SMTP (Haraka < 2.8.9), TCP 25 | CICIDS2017: none | No SMTP exploitation family. | Yes | — | — | **Unmapped** |
| | | UNSW-NB15 `exploits` | Needs taxonomy evidence (E1) and observed SMTP flows in the family (E2). | Yes | O2, O3 | — | **Provisional (E1, E2)** |
| **`FTPDirectoryTraversal`**. Seed 0: 0 | FTP, TCP 21 | CICIDS2017: none | FTP-Patator shares the port but is credential guessing. | Yes | — | — | **Unmapped** |
| | | UNSW-NB15 `exploits` | Needs taxonomy evidence (E1) and observed FTP flows in the family (E2). | Yes | O2, O3 | — | **Provisional (E1, E2)** |
| **`AggressiveServiceDiscovery`** (`Portscan`, 1 tick, detection 0.75). Seed 0: 45 (45) | TCP connections to one host's open ports | CICIDS2017 `portscan` | The family is nmap port scans of a host. The technique and protocol are the same. | Yes | O2, O3 | High | **Approved** |
| **`StealthServiceDiscovery`** (the same `Portscan`, 3 ticks, detection 0.25). Seed 0: 40 (40) | as above | CICIDS2017 `portscan` | The same modelled traffic as the aggressive scan. Whether CIC ran slow scans is unverified. | Yes | O2, O3 | Medium-high | **Approved** |
| Both service discoveries | | UNSW-NB15 | The dataset's descriptions fit both `reconnaissance` and `analysis`. | Yes | — | — | **Unmapped** (owner) |
| **`DiscoverRemoteSystems`** (`Pingsweep`). Seed 0: 42 | ICMP host sweep | none | Host discovery is not port scanning. On UNSW-NB15 the same overlap applies. | Yes | — | — | **Unmapped** |
| **`HTTPSRFI`** | HTTPS, TCP 443 | none | TLS changes the flow features. No defensible stand-in. | Yes | — | — | **Unmapped** |
| **`DiscoverDeception`**. Seed 0: 93 | Service probes for decoys | none | No protocol or probe behaviour specified. | Probably | — | — | **Unmapped** |
| **`PrivilegeEscalate`**, **`Impact`**, **`DegradeServices`**, **`Withdraw`**, **`Sleep`**, **`InvalidAction`** | Local, or none | none | Local actions with no flow behaviour of their own. `Impact` is unmapped by the owner's rule. | No | — | — | **Unmapped** |
| Green actions, **`PhishingEmail`** | — | none | Only attack records are replayed. No command-and-control traffic is modelled. | — | — | — | **Unmapped** |
| **`EternalBlue`**, **`BlueKeep`**, **`RemoteCodeExecutionOnSMTP`** | — | — | Unreachable in CAGE 4. | — | — | — | **Excluded** |
| **`ExploitRemoteService` with no exploit chosen**. Seed 0: 159 | — | — | O4. | No service reached | O4 | — | **Not counted; reported separately** |

**What is approved now:**
- **Improved CICIDS2017:** three families receive replay: `brute_force`, `web_attack` (from `SQLInjection` only)
  and `portscan`.
- **UNSW-NB15:** nothing is mapped. Unless E1 and E2 support a provisional entry, B = A on UNSW-NB15, and the B
  intervention contrasts are limited to improved CICIDS2017. That is not cross-dataset validation.

## 4. Replay arithmetic, cap and effective sample size (`spikes/config_b_draft/replay_ess.py`)

### 4.1 What replay does to the training set
- A replayed record is a copy of a record already in the fold's training partition, so **it is not a new or
  independent observation.**
- Training on a record together with its k copies is the same as training once on that record with weight 1 + k.
  The Random Forest's bootstrap makes this only approximately true, but no copy carries information its original
  does not.
- So each training record i has a weight w_i = 1 + c_i, where c_i is its number of replays (0 for every record in
  Config A).

### 4.2 Effective sample size, precisely
- **Formula:** for a set of records with weights w_i, Kish's effective sample size is
  **ESS = (Σ w_i)² / Σ w_i²**.
- **What it means:** it is the number of equally weighted, independent records whose weighted mean would have the
  same variance as the weighted mean over these records.
- **Properties:**
  - With no replays, every w_i = 1 and ESS equals the number of records.
  - Replaying every record of a family the same number of times leaves the ESS unchanged.
  - Uneven replays lower it.
  - **It can never exceed the number of distinct records.** Replay therefore never increases the ESS of any family,
    and usually lowers it.
- **Draws:** replays within a family are dealt cyclically without replacement: each pass is a fresh permutation of
  the family's training rows, so replay counts within a family differ by at most one.
  - With n rows and m replays, k = ⌊m/n⌋ and q = m − kn.
  - n − q rows have weight 1 + k, and q rows have weight 2 + k.
  - ESS = (n + m)² / ((n − q)(1 + k)² + q(2 + k)²).
- **Reported per fold and per seed, beside nominal counts:**
  - for each family: distinct training rows, replays, nominal rows (distinct plus replays) and ESS;
  - for the attack class as a whole: the same, computed over every attack training record's weight;
  - for A, B and B0 alike.
- **Status:** it is a descriptive diagnostic only. Inference stays at the level of per-seed paired differences in
  held-out recall. No statistic treats replayed rows as observations.

### 4.3 The per-row cap (approved provisionally): at most 4 replays per training row
- **Applied to B:** if a family's requested replays exceed 4 × its training rows, the excess is **truncated** (not
  drawn) and **not redistributed**, because redistribution would change the simulator-derived proportions.
- **Applied to B0:** B0 draws from the whole seen attack pool, whose size far exceeds any realized total. Its cap
  therefore never binds in these illustrations, and it is checked all the same.
- **Reported per family, per fold and per seed:**
  - requested replays, realized replays, and truncated replays;
  - events whose family was held out ("excluded: held out");
  - events with no mapping (unmapped and O4/O6, reported separately);
  - B's realized total, which B0 matches.

### 4.4 Illustration (approved mappings only; seed-0 events; cleaned counts)
| Improved CICIDS2017, held out | r | Requested / realized (truncated) | B replays / training rows | Attack-class ESS: A | B | B0 |
|---|---|---|---|---|---|---|
| `bot` | 0.25 | 2,211 / 2,211 (0) | brute_force 804/4,159; portscan 1,314/4,617; web_attack 93/62 | 108,867 | 106,768 | 106,826 |
| `bot` | 1.0 | 8,838 / 8,715 (web_attack 123) | brute_force 3,214/4,159; portscan 5,253/4,617; web_attack 248/62 | 108,867 | 100,896 | 102,402 |
| `portscan` | 1.0 | 4,221 / 4,032 (web_attack 189) | brute_force 3,784/4,159; web_attack 248/62 | 104,692 | 100,576 | 101,218 |
| `dos` | 1.0 | 8,838 / 8,715 (web_attack 123) | as for `bot` | 9,309 | 8,670 | 9,163 |

- **The cap binds only on `web_attack`.** It has 62 training rows; with the approved mapping the cap truncates at
  r = 1, and with `HTTPRFI` added it would truncate from r = 0.25.
- **`web_attack`'s ESS stays at its 62 distinct rows** throughout.
- **UNSW-NB15:** nothing is mapped, so B = A in every fold.

## 5. Evidence steps — exact procedures
**Status (owner, 2026-11-09):**
- **E1, E2 and E4 procedures: approved.**
  - **Reading of constraint 4:** training-partition records may be read when they are never validation or test
    records in the relevant fold.
  - **Not permitted:** no validation or test record, no row-level inspection, no numeric feature access, and no
    model execution.
- **E1b: deferred.**
- **E3: withdrawn.**
- **Run status (2026-11-09):** E1, E2 and E4 were authorized and run. Results are in `docs/config-b-evidence.md`:
  - E1 completed for improved CICIDS2017, and is incomplete for UNSW-NB15 (sources not openly accessible);
  - E2 completed;
  - E4 stopped on its label-reproduction check, caused by a script defect. It is not rerun.
  - The table in section 3 is unchanged until the owner decides on the proposed final mapping.
- **Provisional entries:** every UNSW-NB15 entry stays provisional. A decision rule that is not clearly met leaves
  the entry unmapped, with no automatic promotion.
**Common constraints for every step:**
1. **Training partition only.** E2 and E4 read only rows in `make_partition(ds.family, seed=0, val_fraction=0.2,
   test_fraction=0.2).train`, with the frozen split code unchanged.
   - Before reading anything, the script asserts that the selected row indices are disjoint from that partition's
     `val` and `test` indices.
   - It never reads a validation or test row.
2. **Config A identity preserved.** `python -m aegis.frozen` must print "Matches the frozen Config A" before and
   after each step. No file in `src/` is modified. Each step's script is new and read-only, and loads data through
   Config A's own loaders and cleaning.
3. **No model and no scores.** No model is fitted, no score or prediction is produced, and no numeric feature is
   read: E2 reads three categorical columns, and E4 reads one label column. Only aggregate counts are written, never
   rows.
4. **Held-out families.**
   - Training-partition rows are never validation or test rows in any fold. `holdout_fold` drops the held-out
     family's training rows and tests on `partition.test`.
   - Evidence about family F is used only to decide F's mapping. When F is held out, that mapping selects nothing.
   - **Confirmed by the owner (2026-11-09).**
5. **Logs:** the dataset files' sha256, the commit, the identity check output, the seed, and the counts, written to
   `results/config_b_evidence/<step>/` (gitignored). Each step's decision rule (below) is fixed before it runs.

**E1, taxonomy from the datasets' own documentation (no data).**
- **Sources, in this order:**
  1. Sharafaldin, Lashkari and Ghorbani (2018), "Toward Generating a New Intrusion Detection Dataset and Intrusion
     Traffic Characterization", ICISSP. Also the dataset's page at the Canadian Institute for Cybersecurity.
  2. Engelen, Rimmer and Joosen (2021), "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case
     Study", IEEE SPW, the improved release's paper.
  3. Moustafa and Slay (2015), "UNSW-NB15: a comprehensive data set for network intrusion detection systems",
     MilCIS. Moustafa and Slay (2016), "The evaluation of Network Anomaly Detection Systems: Statistical analysis of
     the UNSW-NB15 data set and the comparison with the KDD99 data set", Information Security Journal.
- **Method:** fetch only publicly accessible versions. For each source, record the citation, URL, access date, and
  page or section.
- **Output:** verbatim quotations of every passage that defines or lists the attacks in `web_attack` (CICIDS2017)
  and in `exploits` (UNSW-NB15), including any listed subcategories, tools, services or CVEs.
- **Decision rule, fixed now:** a provisional entry is taxonomy-supported only if a quoted passage names the
  technique itself (remote file inclusion; SQL injection; an SMTP or Haraka remote code execution; FTP directory
  traversal), or a narrower attack class that the technique is documented to belong to. A broad umbrella term alone
  ("web attack", "exploits") does not count.
- **Optional E1b (separate decision):**
  - **Source:** UNSW-NB15's ground-truth table (`NUSW-NB15_GT.csv`), which lists attack category, subcategory,
    attack name and reference.
  - **Not local:** it is not in `data/` and would have to be downloaded from the dataset's site.
  - **Constraint conflict:** it has a row per attack event across the whole capture, so it does not meet constraint
    1 literally.
  - **If approved:** only the distinct values of (category, subcategory, attack name, reference) for `Exploits`
    would be read. No time, address or port column would be read, and nothing would be joined to records.

**E2, UNSW-NB15 `exploits`: services observed in training (observable network behaviour).**
- **Rows:** load UNSW-NB15 through Config A's loader and cleaning. Select rows of the seed-0 training partition
  whose family is `exploits`.
- **Output:**
  - counts and shares of `service`, of `proto`, and of `state` among those rows;
  - the counts for `service` ∈ {`http`, `smtp`, `ftp`, `ftp-data`} and `proto` = `tcp`.
- **Decision rule, fixed now:** a provisional UNSW-NB15 entry for service S (`http` for `SQLInjection` and
  `HTTPRFI`; `smtp` for `HarakaRCE`; `ftp` for `FTPDirectoryTraversal`) is supported on behaviour only if
  `exploits` training rows with service S number **at least 100** and use `tcp`.
  - This is necessary but not sufficient: it also needs E1's taxonomy support.
  - Replay would still draw from the whole `exploits` family. The report states how much of the family is service
    S, as a limitation.

**E3: withdrawn.** It was to separate `reconnaissance` from `analysis` for scans on UNSW-NB15. The owner kept service
discovery unmapped there, so it is not needed.

**E4, improved CICIDS2017 `web_attack`: composition (documents the broad family-level match).**
- **Rows:** load the improved release through Config A's loader and cleaning. In a new read-only script, carry the
  raw `Label` value alongside each row through the same cleaning.
- **Alignment check:** mapping the carried labels through `aegis.data.improved.FAMILIES` must reproduce Config A's
  `family` array exactly, row for row, and the cleaned row count must equal Config A's manifest. Any mismatch stops
  the step and is reported.
- **Output:** counts of each raw label (web brute force, XSS, SQL injection) among `web_attack` rows of the seed-0
  training partition.
- **Decision rule:** none on the mapping. The counts go into the frozen table, to quantify how much of the replayed
  family is SQL injection. If the family has fewer than 20 SQL-injection training rows, the report says the
  approved mapping replays mostly other web attacks.

## 6. Limitations
- **No flow-level correspondence.** Nothing checks that a CAGE event corresponds to any recorded flow. The method
  tests **simulator-derived family weighting**:
  - it does not generate traffic;
  - it does not model individual flow behaviour;
  - it does not select more realistic individual records, since records are drawn uniformly within a family.
- **CAGE's exploit selector shapes the mix.** It never picks the highest-weight exploit when several apply, so
  `SSHBruteForce` dominates. CAGE is not modified.
- **Most red actions are unmapped.** In seed 0, 742 of 1,190 red actions are local and unmapped, and 159 are
  unreachable failed exploits. Mapped attempts are 143 on improved CICIDS2017 (approved entries) and 0 on
  UNSW-NB15.
- **Family-level replay is coarse.** `SSHBruteForce` replays FTP-Patator rows too, and `SQLInjection` replays the
  whole `web_attack` family.
- **Small families:** `web_attack` (62 training rows) is capped, and `portscan` has few distinct raw rows.
- **The blue script shapes the red mix.** It is frozen with the protocol.
