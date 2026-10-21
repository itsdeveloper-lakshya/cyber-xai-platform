import pandas as pd

MERGED_PARQUET = "data/intermediate/cert/merged_with_ldap.parquet"
INSIDERS_CSV = "data/raw/Cert/answers/insiders.csv"
FINAL_PARQUET = "data/intermediate/user_daily_activity.parquet"

def run_label_and_validate():
    print("=== STEP 4.6: APPLYING TIME-SCOPED MALICIOUS LABELS ===")
    df = pd.read_parquet(MERGED_PARQUET)
    df["date"] = pd.to_datetime(df["date"]).dt.date
    df["is_malicious"] = 0

    df_ans = pd.read_csv(INSIDERS_CSV)
    df_ans_42 = df_ans[df_ans["dataset"].astype(str).str.strip() == "4.2"].copy()
    
    df_ans_42["start_date"] = pd.to_datetime(df_ans_42["start"], errors="raise").dt.date
    df_ans_42["end_date"] = pd.to_datetime(df_ans_42["end"], errors="raise").dt.date

    for _, row in df_ans_42.iterrows():
        u_id = row["user"]
        s_date = row["start_date"]
        e_date = row["end_date"]
        
        # CRITICAL (Step 4.6): Mark is_malicious = 1 ONLY within [s_date, e_date]
        mask = (df["user_id"] == u_id) & (df["date"] >= s_date) & (df["date"] <= e_date)
        df.loc[mask, "is_malicious"] = 1

    df["is_malicious"] = df["is_malicious"].astype("int32")

    # Place user_id, date, department first, and is_malicious last (matching Section 6 schema)
    middle_cols = [c for c in df.columns if c not in ("user_id", "date", "department", "is_malicious")]
    final_cols = ["user_id", "date", "department"] + middle_cols + ["is_malicious"]
    df = df[final_cols].sort_values(["user_id", "date"]).reset_index(drop=True)

    df.to_parquet(FINAL_PARQUET, engine="pyarrow", index=False)

    # =========================================================
    # STEP 4.7: SANITY CHECK & SPOT-CHECK KNOWN MALICIOUS USERS
    # =========================================================
    mal_rows = int(df["is_malicious"].sum())
    mal_users_active = df.loc[df["is_malicious"] == 1, "user_id"].nunique()
    total_days_of_mal_users = int(df["user_id"].isin(df_ans_42["user"]).sum())
    unknown_depts = int((df["department"] == "Unknown").sum())

    print("\n" + "="*65)
    print("STEP 4.7: FINAL CERT PIPELINE A VALIDATION SUMMARY")
    print("="*65)
    print(f"Saved Final Parquet          : {FINAL_PARQUET}")
    print(f"Total User-Day Rows          : {len(df):,}")
    print(f"Unique Users                 : {df['user_id'].nunique():,}")
    print(f"Date Range                   : {df['date'].min()} -> {df['date'].max()}")
    print(f"Unassigned ('Unknown') Depts : {unknown_depts} (Target: 0)")
    print(f"Any NaN Values in Table?     : {int(df.isna().sum().sum())}")
    print(f"Any Negative Counts?         : {int((df[middle_cols] < 0).any().any())}")
    print(f"Malicious Insiders in r4.2   : {len(df_ans_42)} users (Active in logs: {mal_users_active})")
    print(f"Total Workdays of those 70   : {total_days_of_mal_users:,} user-days")
    print(f"Time-Scoped Malicious Rows   : {mal_rows:,} user-days ({100*mal_rows/len(df):.3f}% of dataset)")
    print(f"Normal Days of those 70 Kept : {total_days_of_mal_users - mal_rows:,} user-days kept as is_malicious=0!")
    print(f"Final Columns ({len(df.columns)})          : {list(df.columns)}")
    print("="*65)

    # Spot-check 2 specific insiders around their attack windows
    print("\n--- SPOT CHECK 1: Insider AAM0658 (Attack Window: 2010-10-23 to 2010-10-29) ---")
    s1 = df[
        (df["user_id"] == "AAM0658") &
        (df["date"] >= pd.to_datetime("2010-10-20").date()) &
        (df["date"] <= pd.to_datetime("2010-11-02").date())
    ]
    print(s1[["user_id", "date", "department", "logon_count", "after_hours_logons", "usb_connects", "files_copied", "is_malicious"]].to_string(index=False))

    print("\n--- SPOT CHECK 2: Insider BIH0745 (Attack Window: 2010-07-13 to 2010-07-13) ---")
    s2 = df[
        (df["user_id"] == "BIH0745") &
        (df["date"] >= pd.to_datetime("2010-07-09").date()) &
        (df["date"] <= pd.to_datetime("2010-07-16").date())
    ]
    print(s2[["user_id", "date", "department", "logon_count", "emails_sent", "websites_visited", "is_malicious"]].to_string(index=False))

if __name__ == "__main__":
    run_label_and_validate()