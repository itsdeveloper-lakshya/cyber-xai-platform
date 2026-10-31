# CICIDS2017 Episode Catalog (Module 4 Step N1)

## 1. Overview
This catalog documents every ground-truth attack episode in `network_flows_clean` (2,827,609 total flows).
Cross-checked against the official University of New Brunswick (UNB) CICIDS2017 attack schedule.

## 2. Daily Summary
| Day | Total Flows | Benign Flows | Attack Flows | Attack % | Earliest Timestamp | Latest Timestamp |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Monday | 529,450 | 529,450 | 0 | 0.0% | 2017-07-03 01:00:01 | 2017-07-03 12:59:58 |
| Tuesday | 445,641 | 431,809 | 13,832 | 3.1% | 2017-07-04 01:00:00 | 2017-07-04 12:59:00 |
| Wednesday | 691,379 | 439,668 | 251,711 | 36.41% | 2017-07-05 01:00:00 | 2017-07-05 12:59:00 |
| Thursday-Afternoon-Infilteration | 288,217 | 288,217 | 0 | 0.0% | 2017-07-06 01:00:00 | 2017-07-06 05:04:00 |
| Thursday-Morning-WebAttacks | 170,209 | 168,050 | 2,159 | 1.27% | 2017-07-06 08:59:00 | 2017-07-06 12:59:00 |
| Friday-Afternoon-PortScan | 286,095 | 127,291 | 158,804 | 55.51% | 2017-07-07 01:00:00 | 2017-07-07 03:29:00 |
| Friday-Afternoon-DDos | 225,709 | 97,684 | 128,025 | 56.72% | 2017-07-07 03:30:00 | 2017-07-07 05:02:00 |
| Friday-Morning | 190,909 | 188,953 | 1,956 | 1.02% | 2017-07-07 08:59:00 | 2017-07-07 12:59:00 |

## 3. Attack Family Mapping
| Raw Attack Label | Mapped Attack Family | Flow Count | Share of Attacks |
| :--- | :--- | :--- | :--- |
| DoS Hulk | `dos` | 230,123 | 41.35% |
| PortScan | `portscan` | 158,804 | 28.54% |
| DDoS | `ddos` | 128,025 | 23.01% |
| DoS GoldenEye | `dos` | 10,293 | 1.85% |
| FTP-Patator | `brute_force` | 7,935 | 1.43% |
| SSH-Patator | `brute_force` | 5,897 | 1.06% |
| DoS slowloris | `dos` | 5,796 | 1.04% |
| DoS Slowhttptest | `dos` | 5,499 | 0.99% |
| Bot | `bot` | 1,956 | 0.35% |
| Web Attack - Brute Force | `web_attack` | 1,507 | 0.27% |
| Web Attack - XSS | `web_attack` | 652 | 0.12% |

## 4. Ground-Truth Attack Episodes (Consecutive Flow Runs)
| Episode # | Day | Family | Detailed Attacks | Start Time | End Time | Duration (min) | Flow Count |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Tuesday | `brute_force` | SSH-Patator | 2017-07-04 02:09:00 | 2017-07-04 03:11:12.052436 | 62.2 | 5,897 |
| 2 | Tuesday | `brute_force` | FTP-Patator | 2017-07-04 09:17:00 | 2017-07-04 10:30:05.216127 | 73.1 | 7,935 |
| 3 | Wednesday | `dos` | DoS slowloris | 2017-07-05 02:24:00 | 2017-07-05 02:25:00.000214 | 1.0 | 5 |
| 4 | Wednesday | `dos` | DoS slowloris | 2017-07-05 09:01:00 | 2017-07-05 09:01:05.001683 | 0.1 | 1 |
| 5 | Wednesday | `dos` | DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris | 2017-07-05 09:48:00 | 2017-07-05 11:19:47.822010 | 91.8 | 251,705 |
| 6 | Thursday-Morning-WebAttacks | `web_attack` | Web Attack - Brute Force, Web Attack - XSS | 2017-07-06 09:15:00 | 2017-07-06 10:35:06.553104 | 80.1 | 2,159 |
| 7 | Friday-Afternoon-PortScan | `portscan` | PortScan | 2017-07-07 01:05:00 | 2017-07-07 01:06:05.018079 | 1.1 | 7 |
| 8 | Friday-Afternoon-PortScan | `portscan` | PortScan | 2017-07-07 01:52:00 | 2017-07-07 02:16:03.296671 | 24.1 | 365 |
| 9 | Friday-Afternoon-PortScan | `portscan` | PortScan | 2017-07-07 02:51:00 | 2017-07-07 03:23:27.400152 | 32.5 | 158,432 |
| 10 | Friday-Afternoon-DDos | `ddos` | DDoS | 2017-07-07 03:56:00 | 2017-07-07 04:16:10.146731 | 20.2 | 128,025 |
| 11 | Friday-Morning | `bot` | Bot | 2017-07-07 09:34:00 | 2017-07-07 09:35:00.202640 | 1.0 | 2 |
| 12 | Friday-Morning | `bot` | Bot | 2017-07-07 10:04:00 | 2017-07-07 12:59:01.045087 | 175.0 | 1,954 |

## 5. Audit Conclusions & Windowing Projections
1. **Monday**: 100% Benign baseline (529,450 flows). Critical for learning normal background traffic variance.
2. **Tuesday**: Concentrated brute-force attacks (FTP-Patator, SSH-Patator).
3. **Wednesday**: High-volume DoS attacks (Hulk, GoldenEye, Slowloris, Slowhttptest).
4. **Thursday**: Web attacks (Brute Force, XSS) and Infiltration.
5. **Friday**: Morning Bot attacks, Afternoon PortScan, and Afternoon high-volume DDoS.
6. **Window Projections**:
   - 1-minute windows: ~2,400 windows total (~150-250 surge windows).
   - 5-minute windows: ~480 windows total (~40-60 surge windows).
   - 10-minute windows: ~240 windows total (~20-30 surge windows).
