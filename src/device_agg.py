import os
import pandas as pd

RAW_DEVICE = "data/raw/Cert/r4.2/device.csv"
OUT_PARQUET = "data/intermediate/cert/agg_device.parquet"
os.makedirs(os.path.dirname(OUT_PARQUET), exist_ok=True)

def run_device_agg():
    print("=== STEP 4.3b: AGGREGATING device.csv (FULL FILE) ===")
    
    df = pd.read_csv(RAW_DEVICE, usecols=["date", "user", "activity"])
    print(f"1. Total raw rows read        : {len(df):,}")
    print(f"   Activity breakdown         : {df['activity'].value_counts().to_dict()}")

    # Keep only 'Connect' events
    df = df[df["activity"] == "Connect"].copy()
    print(f"2. Rows with activity=Connect : {len(df):,}")

    dt = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="raise")
    df["date"] = dt.dt.date

    df_agg = df.groupby(["user", "date"], as_index=False).agg(
        usb_connects=("activity", "count")
    )
    df_agg.rename(columns={"user": "user_id"}, inplace=True)
    df_agg["usb_connects"] = df_agg["usb_connects"].astype("int32")
    df_agg.sort_values(["user_id", "date"], inplace=True)

    df_agg.to_parquet(OUT_PARQUET, engine="pyarrow", index=False)

    print("\n--- SANITY CHECK: agg_device.parquet ---")
    print(f"Total (user, date)  : {len(df_agg):,}")
    print(f"Unique USB Users    : {df_agg['user_id'].nunique():,} (Note: only a subset of employees use USBs!)")
    print(f"Date Range          : {df_agg['date'].min()} -> {df_agg['date'].max()}")
    print(f"Total Connects Sum  : {df_agg['usb_connects'].sum():,}")
    print(df_agg.head(5))

if __name__ == "__main__":
    run_device_agg()