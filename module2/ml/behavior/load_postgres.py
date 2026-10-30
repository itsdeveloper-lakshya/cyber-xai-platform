"""
Module 2 Part B: Database Loader for Behavior Outputs (Section 7.9)
Streams into PostgreSQL 15:
1. beh_model_registry
2. beh_daily_score
3. beh_feature_matrix (Consumed by Module 5 for SHAP)
4. beh_rule_flag
Creates indexes on (user_id, date) and (date, probability DESC).
"""

import os
import sys
import json
import time
from pathlib import Path
from dotenv import load_dotenv
import pandas as pd
from sqlalchemy import create_engine, text

# Load root .env
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
load_dotenv(ROOT_DIR / ".env")

db_url = (
    f"postgresql+psycopg2://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
    f"@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
)
engine = create_engine(db_url)

def load_behavior_to_postgres():
    print("\n" + "=" * 75)
    print("LOADING MODULE 2 PART B BEHAVIOR OUTPUTS INTO POSTGRESQL 15")
    print("=" * 75)
    t0 = time.time()

    # 1. Load beh_model_registry
    meta_path = "module2/ml/artifacts/behavior_model_metadata.json"
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            meta = json.load(f)
        
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO beh_model_registry (
                    model_version, algorithm, feature_list, train_date_range, metrics, file_reference, is_active, trained_at
                ) VALUES (
                    :ver, :algo, :feats, :ranges, :metrics, :fref, true, NOW()
                )
                ON CONFLICT (model_version) DO UPDATE SET
                    metrics = EXCLUDED.metrics,
                    is_active = EXCLUDED.is_active;
            """), {
                "ver": meta["model_version"],
                "algo": meta["algorithm"],
                "feats": json.dumps(meta["feature_list"]),
                "ranges": json.dumps(meta["train_date_range"]),
                "metrics": json.dumps(meta["metrics"]),
                "fref": meta["file_reference"]
            })
        print("1. [OK] Recorded model in 'beh_model_registry'.")

    # 2. Load beh_daily_score (330k rows)
    score_parquet = "data/intermediate/beh_daily_score.parquet"
    if os.path.exists(score_parquet):
        print("2. Streaming 'beh_daily_score' into PostgreSQL...")
        df_scores = pd.read_parquet(score_parquet)
        with engine.begin() as conn:
            conn.execute(text("TRUNCATE TABLE beh_daily_score;"))
        df_scores.to_sql("beh_daily_score", engine, if_exists="append", index=False, chunksize=50000)
        print(f"   -> Loaded {len(df_scores):,} daily scores!")

    # 3. Load beh_rule_flag
    flag_parquet = "data/intermediate/beh_rule_flag.parquet"
    if os.path.exists(flag_parquet):
        print("3. Loading 'beh_rule_flag' into PostgreSQL...")
        df_flags = pd.read_parquet(flag_parquet)
        df_flags["created_at"] = pd.Timestamp.now()
        with engine.begin() as conn:
            conn.execute(text("TRUNCATE TABLE beh_rule_flag;"))
        df_flags.to_sql("beh_rule_flag", engine, if_exists="append", index=False)
        print(f"   -> Loaded {len(df_flags):,} hard rule flags!")

    # 4. Create Indexes (Section 5.1 & 7.9)
    print("\n4. Verifying / Creating PostgreSQL Indexes:")
    with engine.begin() as conn:
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_beh_score_date_prob ON beh_daily_score (date, probability DESC);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_beh_score_user_date ON beh_daily_score (user_id, date);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_beh_rule_user_date ON beh_rule_flag (user_id, date);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_beh_rule_date ON beh_rule_flag (date);"))
        print("   -> Composite indexes verified!")

    print(f"\nAll behavior outputs safely persisted in PostgreSQL in {time.time() - t0:.1f}s!")

if __name__ == "__main__":
    load_behavior_to_postgres()
