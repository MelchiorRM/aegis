# CSE-CIC-IDS2018: proposed untouched test set

**Status:** proposed, not confirmed. Nobody on this project has downloaded or inspected its data. Everything below comes
from published documentation, as of 2026-11-08. It must not be acquired until the project owner confirms it.

## Releases

| Release | Feature extractor | Labels | Notes |
| --- | --- | --- | --- |
| Original (UNB / CIC, AWS bucket `cse-cic-ids2018`) | CICFlowMeter-V3 | Attack schedule matched on IPs, ports and protocol | "Processed Traffic Data for ML Algorithms" CSVs, one per day. Free to redistribute with citation. |
| Improved (Liu, Engelen et al., IEEE CNS 2022) | Modified CICFlowMeter | Relabelled by IP, port, protocol, time window and payload | Recreated from the PCAPs. Adds "Attempted" labels. Labelling code is public. |
| BCCC-CSE-CIC-IDS2018 (York University BCCC) | Not checked | DoS labels matched by attacker IP instead of timestamps | Not reviewed in detail. |
| LycoS-Unicas-IDS2018 | Patched CICFlowMeter | Corrected | Not reviewed in detail. |

## Known data-quality issues
From the CNS 2022 documentation unless stated otherwise.

- **Labelling errors overall:** about 7.5% of flows in the original release are reported mislabelled, and some attack
  classes are corrupted by over 75% (Rosay et al., as cited in arXiv 2402.10974).
- **Attacks that did not happen as documented:**
  - FTP-Patator found port 21 closed, so its flows are "Attempted". It also appears on a day it was not scheduled.
  - No successful DoS Slowhttptest attack exists; the tool appears to have targeted port 21.
  - Heartleech has no documented attacker, victim or window, and no evidence it is present.
  - The botnet traffic contains no Zeus, only Ares on port 8080.
- **Wrong timing:**
  - SSH-Patator started on port 21 for about 30 seconds.
  - GoldenEye and Slowloris windows are 1-2 minutes off at each end.
  - DDoS HOIC started about 6 minutes late.
  - The 22-02 web brute force start is in the wrong time zone.
  - The labelling rules contain timestamp typos.
- **Wrong labels:**
  - All DDoS-LOIC-UDP flows on 20-02 are labelled DDoS-LOIC-HTTP.
  - On 28-02 the infected victim, not the attacker, ran the port scan.
  - Dropbox download traffic was labelled benign.
  - 41.7% of the 23-02 web brute force flows were other traffic: UDP port 500, port 0, DHCP and SSH.
- **Feature generation:**
  - The 120 s timeout splits single Slowloris connections into several flows.
  - ARP was processed as IP, and ICMP as UDP.
  - TCP segmentation offload makes many botnet flows show protocol and ports 0.
  - Late RSTs after LOIC become unlabellable flows.
  - The original tool ended a TCP flow on a single FIN and ignored RST.
- **Values:** NaN, Infinity and -1 window sentinels are present, as in CICIDS2017.
- **Official documentation:** the feature count is given as both 80 and 83, some feature descriptions are wrong, and one
  infiltration window is listed twice.
- **Unverified, to check on first load:** community reports of one day file with extra identifier columns (Flow ID,
  Src IP, Src Port, Dst IP) and of header rows repeated inside files. Neither was confirmed from documentation.

## Labelling methodology in the improved release
- **Labelling rules:** flows are labelled by source and destination IP, port, protocol, time window and payload size.
  - Web brute force flows with more than 20 forward packets are malicious.
  - GoldenEye flows under 5.05 s with a forward RST are "Attempted".
  - DHCP is excluded from infiltration.
  - Infiltration splits into Dropbox download, victim-attacker communication and NMAP port scan.
- **"Attempted" categories:** 0, no attacker payload; 1, port or system closed; 2, startup or teardown artefact; 3, no
  malicious payload; 4, attack artefact; 5, implemented incorrectly; 6, target unresponsive.
- **Authors' advice on "Attempted":** never train on "Attempted" as its own class, and treat it as benign when in doubt.
  Aegis must fix its handling before first load: exclude these flows, or count them as benign. Report both if they
  differ.

## Schema compatibility with the CICIDS2017 copy used here
- **Names:** all 76 model features of the CICIDS2017 `MachineLearningCVE` copy have a counterpart in the documented
  2018 header, under abbreviated names.
  - Examples: `Total Fwd Packets` → `Tot Fwd Pkts`, `Init_Win_bytes_forward` → `Init Fwd Win Byts`,
    `min_seg_size_forward` → `Fwd Seg Size Min`.
  - Checked by name mapping against the header published on the COMIDDS dataset page, not against real files.
- **Columns to drop:** the 2018 header adds `Protocol` and `Timestamp`. Both must be dropped, because the CICIDS2017
  copy has neither. `Dst Port` is dropped, as `Destination Port` is now. The 2017 duplicate `Fwd Header Length.1` has no
  2018 counterpart and is already dropped.
- **Feature extractor:** this is the main compatibility risk. The CICIDS2017 copy used for development comes from the
  original CICFlowMeter, with its FIN and RST handling.
  - Original 2018 CSVs: same generation of tool, so features are comparable, but labels carry the errors above.
  - Improved 2018 release: correct labels, but its fixed tool changes flow boundaries and feature values. A model
    trained on original 2017 features and tested on it would face a feature-extractor shift as well as a new network.
  - Consistent pair: the improved CICIDS2017 and CSE-CIC-IDS2018 together. That changes the development data, so
    Config A would have to be re-measured and the shortcut audit repeated.
- **Units:** both releases are expected to give durations and IATs in microseconds. Verify on first load.
- **Families:**

  | Family | In CSE-CIC-IDS2018 | Caveat |
  | --- | --- | --- |
  | dos | yes | Slowhttptest effectively absent |
  | dos, from DDoS (LOIC, HOIC) | yes | Grouped with dos, as in CICIDS2017 |
  | brute_force | yes | FTP-Patator mostly "Attempted" |
  | web_attack (brute force, XSS, SQL injection) | yes | Small classes, contaminated in the original |
  | bot | yes | Ares only |
  | infiltration | yes | Includes an NMAP port scan |
  | portscan | no standalone family | |
  | heartbleed | not found | |

## Decisions needed before acquisition
1. **Which release:**
   - original 2018 CSVs, with label errors disclosed;
   - improved 2018 only, with extractor shift disclosed;
   - the improved 2017 and 2018 pair, which re-opens Config A.
2. **"Attempted" handling,** fixed in the pre-registration.
3. **What may be inspected before the single evaluation:** for example headers, row counts and label counts only.
   Anything else touches the test set.

## Sources
- Liu, Engelen, Lynar, Essam, Joosen, "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and
  CSE-CIC-IDS-2018", IEEE CNS 2022, pp. 254-262, doi:10.1109/CNS56114.2022.9947235.
- Improved-dataset documentation: https://intrusion-detection.distrinet-research.be/CNS2022/ (CSECICIDS2018.html,
  Tools_Documentation.html, Dataset_Download.html). Code: https://github.com/GintsEngelen/CNS2022_Code
- Official page and attack schedule: https://www.unb.ca/cic/datasets/ids-2018.html
- Header listing: https://fkie-cad.github.io/COMIDDS/content/datasets/cse_cic_ids2018
- Error rates: https://arxiv.org/html/2402.10974v1
- BCCC release: https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/large-scale-intrusion-detection-dataset-bccc-cse-cic-ids2018/
