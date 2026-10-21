import os
import csv
import time
from io import StringIO
import pyarrow.parquet as pq
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

db_url = (
    f"postgresql+psycopg2://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
    f"@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
)
engine = create_engine(db_url)

CERT_PARQUET = "data/intermediate/user_daily_activity.parquet"
CICIDS_PARQUET = "data/intermediate/network_flows_clean.parquet"

def psql_insert_copy(table, conn, keys, data_iter):
    """Fast native PostgreSQL COPY loader for SQLAlchemy + pandas.to_sql()"""
    dbapi_conn = conn.connection
    with dbapi_conn.cursor() as cur:
        s_buf = StringIO()
        writer = csv.writer(s_buf)
        writer.writerows(data_iter)
        s_buf.seek(0)
        columns = ", ".join([f'"{k}"' for k in keys])
        table_name = f'"{table.name}"'
        sql = f"COPY {table_name} ({columns}) FROM STDIN WITH CSV"
        cur.copy_expert(sql=sql, file=s_buf)

def stream_parquet_to_postgres(parquet_path, table_name, batch_size=100_000):
    print(f"\n=== LOADING '{table_name}' FROM {parquet_path} ===")
    t0 = time.time()
    
    # Section 9 Rule: Drop existing table cleanly before loading
    with engine.begin() as conn:
        conn.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE;"))

    parquet_file = pq.ParquetFile(parquet_path)
    total_rows = parquet_file.metadata.num_rows
    loaded_rows = 0

    for idx, batch in enumerate(parquet_file.iter_batches(batch_size=batch_size), 1):
        df_chunk = batch.to_pandas()
        df_chunk.to_sql(
            table_name,
            engine,
            if_exists="append",
            index=False,
            method=psql_insert_copy
        )
        loaded_rows += len(df_chunk)
        elapsed = time.time() - t0
        print(f"   Batch {idx:2d}: {loaded_rows:>9,} / {total_rows:,} rows written ({elapsed:.1f}s)")
        del df_chunk

    print(f"   -> Finished writing {loaded_rows:,} rows to '{table_name}' in {time.time() - t0:.1f}s!")

def build_indexes_and_verify():
    print("\n=== SECTION 6: CREATING COMPOSITE & TIMESTAMP INDEXES ===")
    with engine.begin() as conn:
        print("   -> Creating index idx_user_daily_user_date ON user_daily_activity (user_id, date)...")
        conn.execute(text("CREATE INDEX idx_user_daily_user_date ON user_daily_activity (user_id, date);"))
        
        print("   -> Creating index idx_network_flows_timestamp ON network_flows_clean (timestamp)...")
        conn.execute(text("CREATE INDEX idx_network_flows_timestamp ON network_flows_clean (timestamp);"))

    print("\n" + "="*65)
    print("SECTION 8: DEFINITION OF 'DONE' — POSTGRES VERIFICATION")
    print("="*65)
    with engine.connect() as conn:
        cert_count = conn.execute(text("SELECT COUNT(*) FROM user_daily_activity;")).scalar()
        cert_users = conn.execute(text("SELECT COUNT(DISTINCT user_id) FROM user_daily_activity;")).scalar()
        cert_mal = conn.execute(text("SELECT COUNT(*) FROM user_daily_activity WHERE is_malicious = 1;")).scalar()
        
        cicids_count = conn.execute(text("SELECT COUNT(*) FROM network_flows_clean;")).scalar()
        cicids_days = conn.execute(text("SELECT COUNT(DISTINCT source_day) FROM network_flows_clean;")).scalar()
        cicids_min_ts = conn.execute(text("SELECT MIN(timestamp) FROM network_flows_clean;")).scalar()
        cicids_max_ts = conn.execute(text("SELECT MAX(timestamp) FROM network_flows_clean;")).scalar()

        print(f"1. Table 'user_daily_activity':")
        print(f"   - Total Rows in Postgres : {cert_count:,} (Expected: 330,285)")
        print(f"   - Distinct Users         : {cert_users:,} (Expected: 1,000)")
        print(f"   - Malicious User-Days    : {cert_mal:,} (Expected: 1,364)")
        
        print(f"\n2. Table 'network_flows_clean':")
        print(f"   - Total Rows in Postgres : {cicids_count:,} (Expected: 2,827,609)")
        print(f"   - Distinct Source Days   : {cicids_days} (Expected: 8 files)")
        print(f"   - Timestamp Range        : {cicids_min_ts} -> {cicids_max_ts}")
    print("="*65)

if __name__ == "__main__":
    stream_parquet_to_postgres(CERT_PARQUET, "user_daily_activity", batch_size=100_000)
    stream_parquet_to_postgres(CICIDS_PARQUET, "network_flows_clean", batch_size=100_000)
    build_indexes_and_verify()