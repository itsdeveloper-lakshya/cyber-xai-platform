"""
Module 4 Database Table Initialization (Section 5.1 Exact Schemas)
Creates:
1. net_window_base (PK: window_size_sec, window_start)
2. net_feature_matrix (PK: model_version, window_end)
3. net_surge_episode (PK: episode_id)
4. net_experiment_run (PK: run_id)
5. net_model_registry (PK: model_version)
6. net_forecast (PK: replay_run_id, model_version, window_end)
7. net_alert_episode (PK: episode_id)
8. net_feature_dictionary (PK: feature_name)
"""

import sys
from pathlib import Path
import psycopg2
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = REPO_ROOT / "module4" / "config.yaml"

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

DB_URL = config["database"]["connection_url"]

SCHEMA_SQL = """
-- 1. net_window_base: Base traffic windows
CREATE TABLE IF NOT EXISTS net_window_base (
    window_size_sec INT NOT NULL,
    window_start TIMESTAMP NOT NULL,
    window_end TIMESTAMP NOT NULL,
    source_day VARCHAR(64) NOT NULL,
    segment_id INT NOT NULL DEFAULT 1,
    flow_count INT NOT NULL DEFAULT 0,
    attack_flow_count INT NOT NULL DEFAULT 0,
    attack_share REAL NOT NULL DEFAULT 0.0,
    family_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Base features f_* (Section 7.3)
    f_total_packets REAL DEFAULT 0.0,
    f_total_bytes REAL DEFAULT 0.0,
    f_mean_flow_duration REAL DEFAULT 0.0,
    f_median_flow_duration REAL DEFAULT 0.0,
    f_unique_src_ips REAL DEFAULT 0.0,
    f_unique_dst_ips REAL DEFAULT 0.0,
    f_unique_dst_ports REAL DEFAULT 0.0,
    f_unique_src_dst_pairs REAL DEFAULT 0.0,
    f_entropy_src_ip REAL DEFAULT 0.0,
    f_entropy_dst_ip REAL DEFAULT 0.0,
    f_entropy_dst_port REAL DEFAULT 0.0,
    f_top_src_ip_share REAL DEFAULT 0.0,
    f_top_dst_port_share REAL DEFAULT 0.0,
    f_share_tcp REAL DEFAULT 0.0,
    f_share_udp REAL DEFAULT 0.0,
    f_share_other REAL DEFAULT 0.0,
    f_syn_count_per_flow REAL DEFAULT 0.0,
    f_rst_count_per_flow REAL DEFAULT 0.0,
    f_fin_count_per_flow REAL DEFAULT 0.0,
    f_ack_count_per_flow REAL DEFAULT 0.0,
    f_psh_count_per_flow REAL DEFAULT 0.0,
    f_urg_count_per_flow REAL DEFAULT 0.0,
    f_share_very_short_flows REAL DEFAULT 0.0,
    f_share_tiny_packet_flows REAL DEFAULT 0.0,
    f_share_zero_bwd_packets REAL DEFAULT 0.0,
    f_mean_packet_length REAL DEFAULT 0.0,
    f_fwd_bwd_packet_ratio REAL DEFAULT 0.0,
    f_novel_src_ip_share REAL DEFAULT 0.0,
    f_per_sec_arrival_std REAL DEFAULT 0.0,
    
    PRIMARY KEY (window_size_sec, window_start)
);
CREATE INDEX IF NOT EXISTS idx_net_window_base_day ON net_window_base(window_size_sec, source_day);

-- 2. net_feature_matrix: Pre-computed features with target and onset flag for Module 5
CREATE TABLE IF NOT EXISTS net_feature_matrix (
    model_version VARCHAR(32) NOT NULL,
    window_end TIMESTAMP NOT NULL,
    y INT NOT NULL,
    onset_flag BOOLEAN NOT NULL DEFAULT FALSE,
    features JSONB NOT NULL,
    PRIMARY KEY (model_version, window_end)
);

-- 3. net_surge_episode: Ground-truth surge episodes
CREATE TABLE IF NOT EXISTS net_surge_episode (
    episode_id VARCHAR(64) PRIMARY KEY,
    config_id VARCHAR(32) NOT NULL,
    window_size_sec INT NOT NULL,
    start_window TIMESTAMP NOT NULL,
    end_window TIMESTAMP NOT NULL,
    n_windows INT NOT NULL,
    peak_attack_share REAL NOT NULL,
    families JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- 4. net_experiment_run: Log of all model training runs
CREATE TABLE IF NOT EXISTS net_experiment_run (
    run_id VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    git_commit VARCHAR(64) DEFAULT '',
    seed INT NOT NULL,
    window_size_sec INT NOT NULL,
    horizon_k INT NOT NULL,
    share_threshold REAL NOT NULL,
    flow_floor INT NOT NULL,
    split_scheme VARCHAR(32) NOT NULL,
    training_regime VARCHAR(32) NOT NULL,
    feature_set VARCHAR(32) NOT NULL,
    model_type VARCHAR(32) NOT NULL,
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    library_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
    train_range VARCHAR(64) DEFAULT '',
    val_range VARCHAR(64) DEFAULT '',
    test_range VARCHAR(64) DEFAULT '',
    val_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    test_metrics JSONB,
    notes TEXT DEFAULT ''
);

-- 5. net_model_registry: Versioned trained models
CREATE TABLE IF NOT EXISTS net_model_registry (
    model_version VARCHAR(32) PRIMARY KEY,
    run_id VARCHAR(64) REFERENCES net_experiment_run(run_id) ON DELETE SET NULL,
    model_type VARCHAR(32) NOT NULL,
    file_ref TEXT NOT NULL,
    feature_list JSONB NOT NULL,
    window_size_sec INT NOT NULL,
    horizon_k INT NOT NULL,
    calibrator JSONB NOT NULL DEFAULT '{}'::jsonb,
    thresholds JSONB NOT NULL DEFAULT '{}'::jsonb,
    hysteresis JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. net_forecast: Time-ordered simulated forecast stream
CREATE TABLE IF NOT EXISTS net_forecast (
    replay_run_id VARCHAR(64) NOT NULL,
    model_version VARCHAR(32) NOT NULL,
    window_end TIMESTAMP NOT NULL,
    raw_score REAL NOT NULL,
    calibrated_prob REAL NOT NULL,
    level SMALLINT NOT NULL CHECK (level BETWEEN 0 AND 3),
    level_reason TEXT NOT NULL DEFAULT '',
    horizon_k SMALLINT NOT NULL,
    actual_surge_in_horizon BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (replay_run_id, model_version, window_end)
);
CREATE INDEX IF NOT EXISTS idx_net_forecast_query ON net_forecast(replay_run_id, window_end);

-- 7. net_alert_episode: Alert episodes produced during replay
CREATE TABLE IF NOT EXISTS net_alert_episode (
    episode_id VARCHAR(64) PRIMARY KEY,
    replay_run_id VARCHAR(64) NOT NULL,
    model_version VARCHAR(32) NOT NULL,
    max_level SMALLINT NOT NULL,
    start_window TIMESTAMP NOT NULL,
    end_window TIMESTAMP NOT NULL,
    peak_prob REAL NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    matched_surge_episode_id VARCHAR(64)
);

-- 8. net_feature_dictionary: Readable metadata for Modules 5 & 6
CREATE TABLE IF NOT EXISTS net_feature_dictionary (
    feature_name VARCHAR(64) PRIMARY KEY,
    display_name VARCHAR(128) NOT NULL,
    feature_group VARCHAR(32) NOT NULL,
    description TEXT NOT NULL,
    direction_hint TEXT NOT NULL
);
"""

def init_tables():
    print("=" * 70)
    print(" >>> INITIALIZING MODULE 4 DATABASE SCHEMAS IN POSTGRESQL")
    print("=" * 70)
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute(SCHEMA_SQL)
    conn.commit()
    print("[PASS] Successfully created or verified all 8 net_* database tables.")
    cur.close()
    conn.close()

if __name__ == "__main__":
    init_tables()
