import os
import pandas as pd

RAW_LOGON = "data/raw/Cert/r4.2/logon.csv"
OUT_PARQUET = "data/intermediate/cert/agg_logon.parquet"
os.makedirs(os.path.dirname(OUT_PARQUET), exist_ok=True)

def run_logon_aggregation():
    print("=== STEP 4.3a: AGGREGATING logon.csv (FULL FILE) ===")
    
    # Only load needed columns (skip pc, id not needed once counted)
    df = pd.read_csv(RAW_LOGON, usecols=["date", "user", "activity"])
    raw_rows = len(df)
    print(f"1. Total raw rows read      : {raw_rows:,}")
    print(f"   Activity breakdown       : {df['activity'].value_counts().to_dict()}")

    # Keep only actual 'Logon' events (exclude 'Logoff')
    df = df[df["activity"] == "Logon"].copy()
    print(f"2. Rows with activity=Logon : {len(df):,}")

    # Step 4.2: Explicit, fast datetime conversion
    dt = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="raise")
    df["date_only"] = dt.dt.date
    hour = dt.dt.hour

    # Step 4.3: Explicit threshold -> Before 6 AM (hour < 6) or After 10 PM (hour >= 22)
    df["is_after_hours"] = ((hour < 6) | (hour >= 22)).astype("int32")

    # Group by (user, date_only)
    df_agg = df.groupby(["user", "date_only"], as_index=False).agg(
        logon_count=("activity", "count"),
        after_hours_logons=("is_after_hours", "sum")
    )

    df_agg.rename(columns={"user": "user_id", "date_only": "date"}, inplace=True)
    df_agg["logon_count"] = df_agg["logon_count"].astype("int32")
    df_agg["after_hours_logons"] = df_agg["after_hours_logons"].astype("int32")
    df_agg.sort_values(["user_id", "date"], inplace=True)

    df_agg.to_parquet(OUT_PARQUET, engine="pyarrow", index=False)

    print("\n--- SANITY CHECK: agg_logon.parquet ---")
    print(f"Saved Path          : {OUT_PARQUET}")
    print(f"Total (user, date)  : {len(df_agg):,}")
    print(f"Unique Users        : {df_agg['user_id'].nunique():,}")
    print(f"Date Range          : {df_agg['date'].min()} -> {df_agg['date'].max()}")
    print(f"Total Logons Sum    : {df_agg['logon_count'].sum():,}")
    print(f"Total After-Hours   : {df_agg['after_hours_logons'].sum():,}")
    print(f"Any Negative/NaN?   : {df_agg.isna().sum().sum()} NaNs | Min logon_count={df_agg['logon_count'].min()}")
    print("\nFirst 5 rows:")
    print(df_agg.head(5))

if __name__ == "__main__":
    run_logon_aggregation()