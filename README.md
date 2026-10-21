# Cybersecurity & XAI Platform — Module 1: Data Ingestion & Preprocessing

This repository contains **Module 1** of our 9-module cybersecurity platform combining Insider Threat Detection, Network Attack Forecasting, and Explainable AI (SHAP). Module 1 ingests two raw public datasets (CERT Insider Threat `r4.2` and `CICIDS2017`), cleans and aggregates them via staging Parquet pipelines, and loads them into two indexed **PostgreSQL 15** tables inside Docker.

---

## 1. Datasets & Exact Sources

1. **CERT Insider Threat Dataset (Version `r4.2`)**
   - **Source:** [CMU Kilthub Insider Threat Dataset](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247)
   - **Files Used:** `logon.csv`, `device.csv`, `file.csv`, `email.csv`, `http.csv`, monthly `LDAP/*.csv` snapshots, and `answers/insiders.csv`.
2. **CICIDS2017 Network Traffic Dataset**
   - **Source:** [UNB Canadian Institute for Cybersecurity (IDS 2017)](https://www.unb.ca/cic/datasets/ids-2017.html)
   - **Version Used:** `GeneratedLabelledFlows.zip` (`TrafficLabelling_` — 8 daily CSV files containing flow features, `Timestamp`, `Source IP`, and `Destination IP`).

---

## 2. Three-Zone Folder Architecture Rule (Section 3)

To guarantee reproducibility and prevent downstream data corruption, the repository enforces a strict three-zone boundary:

1. **Raw Data Zone (`data/raw/`):** Strictly **read-only**. Contains the original extracted CERT `r4.2` and `CICIDS2017` CSV files. No script or teammate ever modifies these files.
2. **Intermediate Working Zone (`data/intermediate/`):** **Disposable** staging area containing `.parquet` files generated during cleaning and daily aggregation. Safe to delete and regenerate at any time.
3. **Final Output Zone (PostgreSQL 15 via Docker):** The **only** source of truth (`user_daily_activity` and `network_flows_clean`) that downstream modules (Modules 2 through 9) are permitted to query.

---

## 3. Pipeline Decisions & Cleaning Methodology

### Pipeline A: CERT `r4.2` (`user_daily_activity`)
- **Timestamp Standardization (Step 4.2):** All raw event timestamps (`%m/%d/%Y %H:%M:%S`) are explicitly parsed and normalized to calendar dates prior to grouping.
- **Event Filtering & Daily Aggregation (Step 4.3):**
  - `logon.csv`: Filtered strictly to `activity == 'Logon'` (excluding `Logoff`). Outside working hours explicitly defined as **before 06:00 AM (`hour < 6`) or after 10:00 PM (`hour >= 22`)**.
  - `device.csv`: Filtered strictly to `activity == 'Connect'` (excluding `Disconnect`).
  - `file.csv`: Aggregated total file events per `(user_id, date)`.
  - `email.csv`: Aggregated `emails_sent`, recipient counts, attachment counts, and large email flags per `(user_id, date)`.
  - `http.csv`: Extracted normalized domain names and counted both distinct `websites_visited` and total `http_visits` per `(user_id, date)`.
- **Outer Join & Zero-Filling (Step 4.4):** Combined all 5 daily tables using an **outer join** on `(user_id, date)` so days with partial activity are never dropped. Missing activity counts are filled with `0`.
- **LDAP Department Fallback (Step 4.5):** Joined organizational metadata from the 18 monthly `LDAP` snapshots. Where `department` is `NaN` in LDAP (e.g., executives), the pipeline falls back to `functional_unit` and `role`, resulting in **0 unassigned departments** across all 1,000 users.
- **Time-Scoped Ground-Truth Labeling (Step 4.6):** Using `answers/insiders.csv` (filtered to `dataset == 4.2`, 70 malicious users), `is_malicious = 1` is applied **only** to `(user_id, date)` rows falling within each insider's documented `[start_date, end_date]` attack window (`1,364` malicious user-days). The remaining `14,080` normal workdays of those 70 users are kept as `is_malicious = 0` to prevent poisoning downstream anomaly detection models.

### Pipeline B: CICIDS2017 (`network_flows_clean`)
- **Source Day Preservation (Step 5.1):** Preserved `source_day` from each of the 8 daily capture filenames to support chronological splitting in Module 4.
- **Defect Removal (Step 5.2 & 5.4):** Stripped leading/trailing whitespace from all ~80 column names, dropped `291,469` blank/`NaN`/`Infinity` artifact rows, and removed `199` duplicate rows.
- **Scope Decision on Ultra-Rare Attack Classes (Step 5.3):** Explicitly excluded 3 ultra-rare classes with insufficient sample counts across the 2.83M row dataset (`Infiltration`: 36 rows, `Web Attack - Sql Injection`: 21 rows, `Heartbleed`: 11 rows — 68 rows total) as a documented limitation. Encoded the remaining 12 well-represented classes (`0` to `11`).
- **Chronological Ordering (Step 5.5):** Parsed `timestamp` (`2017-07-03 01:00:01` to `2017-07-07 12:59:00`), sorted all `2,827,609` clean flows chronologically, and indexed on `timestamp`.

---

## 4. Reproducible Execution Order (From Fresh Clone)

```powershell
# 1. Start PostgreSQL 15 in Docker & verify connection
docker compose up -d
py -3.11 -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python src\verify_setup.py

# 2. Run Pipeline B (CICIDS2017 Cleaning -> 2,827,609 rows)
python src\step5_clean_cicids.py

# 3. Run Pipeline A (CERT r4.2 Daily Aggregations, Outer Join & Time-Scoped Labeling -> 330,285 rows)
python src\logon_agg.py
python src\device_agg.py
python src\file_agg.py
python src\email_agg.py
python src\http_agg.py
python src\cert_merge_ldap.py
python src\cert_label_validate.py

# 4. Stream both validated Parquet tables into PostgreSQL 15 & build indexes
python src\load_to_postgres.py
