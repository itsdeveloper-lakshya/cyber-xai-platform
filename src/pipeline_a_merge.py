import os
import glob
import pandas as pd

INTERMEDIATE_DIR = "data/intermediate/cert"
RAW_CERT_R42 = "data/raw/Cert/r4.2"
INSIDERS_CSV = "data/raw/Cert/answers/insiders.csv"
FINAL_PARQUET = "data/intermediate/user_daily_activity.parquet"

def run_pipeline_a_merge():
    print("=== STEP 4.4: OUTER JOINING ALL 5 CERT DAILY TABLES ===")
    
    files = ["agg_logon.parquet", "agg_device.parquet", "agg_file.parquet", "agg_email.parquet", "agg_http.parquet"]
    dfs = [pd.read_parquet(os.path.join(INTERMEDIATE_DIR, f)) for f in files]
    
    merged = dfs[0]
    for df_next in dfs[1:]:
        merged = pd.merge(merged, df_next, on=["user_id", "date"], how="outer")
        
    # Fill missing values with 0 for all count columns (Step 4.4)
    count_cols = [
        "logon_count", "after_hours_logons", "usb_connects", "files_copied",
        "emails_sent", "total_recipients", "total_attachments", "large_attachment_emails",
        "websites_visited", "http_visits"
    ]
    for col in count_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0).astype("int32")
            
    merged["date"] = pd.to_datetime(merged["date"]).dt.date
    print(f"   -> Outer join complete. Total rows: {len(merged):,}")

    print("\n=== STEP 4.5: ATTACHING LDAP DEPARTMENT METADATA ===")
    ldap_files = sorted(glob.glob(os.path.join(RAW_CERT_R42, "LDAP", "*.csv")))
    if ldap_files:
        ldap_list = [pd.read_csv(f, usecols=lambda c: c in ["user_id", "department"]) for f in ldap_files]
        df_ldap = pd.concat(ldap_list, ignore_index=True).drop_duplicates(subset=["user_id"], keep="last")
        merged = pd.merge(merged, df_ldap, on="user_id", how="left")
        merged["department"] = merged["department"].fillna("Unknown")
        print(f"   -> LDAP department merged successfully.")
    else:
        print("   [!] Warning: No LDAP files found. Setting department='Unknown'")
        merged["department"] = "Unknown"

    print(f"\n=== STEP 4.6: APPLYING TIME-SCOPED MALICIOUS LABELS ===")
    merged["is_malicious"] = 0
    if os.path.exists(INSIDERS_CSV):
        df_ans = pd.read_csv(INSIDERS_CSV)
        if "dataset" in df_ans.columns:
            df_ans = df_ans[df_ans["dataset"].astype(str).str.contains("4.2")].copy()
            
        df_ans["start_date"] = pd.to_datetime(df_ans["start"], errors="coerce").dt.date
        df_ans["end_date"] = pd.to_datetime(df_ans["end"], errors="coerce").dt.date
        
        malicious_windows = 0
        for _, row in df_ans.iterrows():
            u_id = row["user"]
            s_date = row["start_date"]
            e_date = row["end_date"]
            
            # CRITICAL: Mark is_malicious=1 ONLY inside the documented window (Step 4.6)
            mask = (merged["user_id"] == u_id) & (merged["date"] >= s_date) & (merged["date"] <= e_date)
            merged.loc[mask, "is_malicious"] = 1
            malicious_windows += 1
            
        print(f"   -> Applied {malicious_windows} malicious user windows from insiders.csv")
    else:
        print(f"   [!] Warning: {INSIDERS_CSV} not found. All rows set to is_malicious=0")

    merged["is_malicious"] = merged["is_malicious"].astype("int32")

    # Order columns to match Section 6 Postgres Schema exactly
    final_cols = [
        "user_id", "date", "department", "logon_count", "after_hours_logons",
        "usb_connects", "files_copied", "emails_sent", "total_recipients",
        "total_attachments", "large_attachment_emails", "websites_visited",
        "http_visits", "is_malicious"
    ]
    # Keep only columns that exist
    final_cols = [c for c in final_cols if c in merged.columns]
    merged = merged[final_cols].sort_values(["user_id", "date"])

    merged.to_parquet(FINAL_PARQUET, engine="pyarrow", index=False)

    print("\n" + "="*65)
    print("PIPELINE A (CERT r4.2) FINAL VALIDATION SUMMARY (STEP 4.7)")
    print("="*65)
    print(f"Total Clean Rows           : {len(merged):,}")
    print(f"Unique Users               : {merged['user_id'].nunique():,}")
    print(f"Date Range                 : {merged['date'].min()} -> {merged['date'].max()}")
    print(f"Malicious User-Days (=1)   : {merged['is_malicious'].sum():,}")
    print(f"Saved Final Parquet to     : {FINAL_PARQUET}")
    print("\nFirst 5 rows:")
    print(merged.head(5))
    print("="*65)

if __name__ == "__main__":
    run_pipeline_a_merge()