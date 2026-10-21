import os
import pandas as pd

RAW_EMAIL = "data/raw/Cert/r4.2/email.csv"
OUT_PARQUET = "data/intermediate/cert/agg_email.parquet"
os.makedirs(os.path.dirname(OUT_PARQUET), exist_ok=True)

CHUNK_SIZE = 300_000
LARGE_SIZE_THRESHOLD = 1_000_000  # 1 MB threshold for unusually large email/attachment size

def count_semicolon_list(series):
    """Counts semicolon-separated email addresses in to/cc/bcc"""
    filled = series.fillna("").astype(str).str.strip()
    return filled.apply(lambda x: 0 if x == "" else x.count(";") + 1)

def has_external_recipient(df_chunk):
    """Flags if any address in to, cc, or bcc is outside the company domain (@dtaa.com)"""
    combined = (
        df_chunk["to"].fillna("") + ";" +
        df_chunk["cc"].fillna("") + ";" +
        df_chunk["bcc"].fillna("")
    ).str.lower()
    # If there is an '@' symbol and any address is not @dtaa.com
    # Simple fast check: count total '@' vs count of '@dtaa.com'
    total_at = combined.str.count("@")
    internal_at = combined.str.count("@dtaa.com")
    return (total_at > internal_at).astype("int32")

def run_email_agg():
    print("=== STEP 4.3d: AGGREGATING email.csv (WITH RECIPIENTS, SIZE & ATTACHMENTS) ===")
    
    use_cols = ["id", "date", "user", "to", "cc", "bcc", "size", "attachments"]
    chunks = []
    total_raw_emails = 0

    for idx, chunk in enumerate(pd.read_csv(RAW_EMAIL, usecols=use_cols, chunksize=CHUNK_SIZE), 1):
        total_raw_emails += len(chunk)
        
        dt = pd.to_datetime(chunk["date"], format="%m/%d/%Y %H:%M:%S", errors="raise")
        chunk["date"] = dt.dt.date
        
        # 1. Recipient count across to, cc, bcc (Section 1)
        to_cnt = chunk["to"].fillna("").str.count(";") + chunk["to"].notna().astype("int32")
        cc_cnt = chunk["cc"].fillna("").str.count(";") + chunk["cc"].notna().astype("int32")
        bcc_cnt = chunk["bcc"].fillna("").str.count(";") + chunk["bcc"].notna().astype("int32")
        chunk["recipient_count"] = (to_cnt + cc_cnt + bcc_cnt).astype("int32")

        # 2. Attachment count & unusually large email/attachment flag (Section 4.3)
        chunk["attachments"] = pd.to_numeric(chunk["attachments"], errors="coerce").fillna(0).astype("int32")
        chunk["size"] = pd.to_numeric(chunk["size"], errors="coerce").fillna(0).astype("int64")
        chunk["is_large_email"] = ((chunk["size"] >= LARGE_SIZE_THRESHOLD) | (chunk["attachments"] > 2)).astype("int32")

        # 3. External recipient flag (exfiltration indicator)
        chunk["is_external"] = has_external_recipient(chunk)

        agg = chunk.groupby(["user", "date"], as_index=False).agg(
            emails_sent=("id", "count"),
            total_recipients=("recipient_count", "sum"),
            total_attachments=("attachments", "sum"),
            large_email_count=("is_large_email", "sum"),
            external_emails_sent=("is_external", "sum"),
            total_email_bytes=("size", "sum")
        )
        chunks.append(agg)
        print(f"   Chunk {idx:2d}: {total_raw_emails:,} emails processed...")

    df_agg = pd.concat(chunks, ignore_index=True).groupby(["user", "date"], as_index=False).sum()
    df_agg.rename(columns={"user": "user_id"}, inplace=True)

    int_cols = ["emails_sent", "total_recipients", "total_attachments", "large_email_count", "external_emails_sent"]
    for c in int_cols:
        df_agg[c] = df_agg[c].astype("int32")

    df_agg.sort_values(["user_id", "date"], inplace=True)
    df_agg.to_parquet(OUT_PARQUET, engine="pyarrow", index=False)

    print("\n--- SANITY CHECK: agg_email.parquet ---")
    print(f"Total Raw Emails Read : {total_raw_emails:,}")
    print(f"Total (user, date)    : {len(df_agg):,}")
    print(f"Unique Email Users    : {df_agg['user_id'].nunique():,}")
    print(f"Date Range            : {df_agg['date'].min()} -> {df_agg['date'].max()}")
    print(f"Total Emails Sent     : {df_agg['emails_sent'].sum():,}")
    print(f"Total Attachments     : {df_agg['total_attachments'].sum():,}")
    print(f"Large Emails Flagged  : {df_agg['large_email_count'].sum():,}")
    print(f"External Emails Sent  : {df_agg['external_emails_sent'].sum():,}")
    print(df_agg.head(5))

if __name__ == "__main__":
    run_email_agg()