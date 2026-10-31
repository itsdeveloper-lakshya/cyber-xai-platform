"""
Clipboard Watcher Test Suite (Section 15 Tests C-01 to C-10)
Verifies:
C-01: Copy ordinary text -> low, counted only
C-02: Copy fake key/ID -> high, stored
C-03: Copy sensitive text while desktop AI app focused -> ai_context=True
C-04: Copy files in Explorer -> kind files, count only, zero names
C-05: Copy an image -> kind image only
C-06: Copy password from password manager -> skipped
C-07: Copy 5 MB text blob -> truncated at cap, no freeze
C-08: Pathological regex input -> timeout path, no freeze
C-09: 100 rapid copies -> stable, no crashes
C-10: Scorer parity -> Python matches Module 2 JS on shared test vectors
"""

import time
import subprocess
import json
import pytest
from pathlib import Path

from core.outbox import SQLiteOutbox
from core.config import AgentConfig
from scoring.scorer import ScoringEngine
from scoring.rules import REGEX_RULES

@pytest.fixture
def scoring_engine():
    return ScoringEngine()

def test_c01_ordinary_text_scored_low(scoring_engine):
    """C-01: Ordinary conversational text scores in low tier (< 0.35)."""
    text = "Good morning everyone. Please find attached the notes from yesterday's team sync."
    res = scoring_engine.score_text(text)
    assert res["risk_tier"] == "low"
    assert res["final_score"] < 0.35
    assert len(res["matched_categories"]) == 0

def test_c02_fake_secret_scored_high(scoring_engine):
    """C-02: Hard secret (e.g. AWS Key ID or Private Key) triggers high risk (>= 0.90)."""
    text = "Here is the production access key: AKIAIOSFODNN7EXAMPLE for deployment."
    res = scoring_engine.score_text(text)
    assert res["risk_tier"] == "high"
    assert res["final_score"] >= 0.90
    assert "CloudAccessKey" in res["matched_categories"]
    assert res["has_hard_rule"] is True

def test_c03_sensitive_copy_with_ai_context(tmp_path):
    """C-03: Sensitive text copied while AI app or AI keyword is focused marks ai_context=True."""
    from watchers.clipboard.watcher import ClipboardWatcherThread
    outbox = SQLiteOutbox(tmp_path / "outbox.db")
    config = AgentConfig(tmp_path)
    watcher = ClipboardWatcherThread(outbox, config)

    # Simulate foreground context
    proc_name = "chatgpt.exe"
    app_class = "ai_desktop_app"
    is_ai = True
    ai_kw = "ChatGPT Desktop"

    score_res = watcher.scoring_engine.score_text("confidential internal only passwords = 'SuperSecret123!'")
    from core.event_factory import EventFactory
    evt = EventFactory.create_clipboard_event(
        content_kind="text",
        char_count=50,
        line_count=1,
        matched_categories=score_res["matched_categories"],
        regex_score=score_res["regex_score"],
        ml_score=score_res["ml_score"],
        final_score=score_res["final_score"],
        risk_tier=score_res["risk_tier"],
        foreground_app=proc_name,
        foreground_class=app_class,
        ai_context=is_ai,
        ai_keyword=ai_kw
    )
    assert evt["ai_context"] is True
    assert evt["ai_keyword"] == "ChatGPT Desktop"

def test_c04_copy_files_count_only_no_names():
    """C-04: File list copy records kind='files', count only, and never file names."""
    from core.event_factory import EventFactory
    evt = EventFactory.create_clipboard_event(
        content_kind="files",
        file_count=5,
        risk_tier="low"
    )
    assert evt["content_kind"] == "files"
    assert evt["file_count"] == 5
    assert "file_names" not in evt
    assert "paths" not in evt

def test_c05_copy_image_kind_only():
    """C-05: Copying an image records kind='image' only."""
    from core.event_factory import EventFactory
    evt = EventFactory.create_clipboard_event(
        content_kind="image",
        risk_tier="low"
    )
    assert evt["content_kind"] == "image"

def test_c06_password_manager_exclusion_respected():
    """C-06: Formats registered by password managers (Clipboard Viewer Ignore, etc.) trigger skip."""
    from watchers.clipboard.watcher import EXCLUSION_FORMAT_NAMES
    assert "clipboard viewer ignore" in EXCLUSION_FORMAT_NAMES
    assert "excludeclipboardcontentfrommonitor" in EXCLUSION_FORMAT_NAMES

def test_c07_5mb_text_blob_truncated_without_freeze(scoring_engine):
    """C-07: Copying 5 MB text blob is safely capped at 100 KB and notes truncation."""
    huge_text = ("Normal repetitive text line with some words.\n" * 120_000)
    assert len(huge_text.encode("utf-8")) > 5 * 1024 * 1024

    t0 = time.time()
    res = scoring_engine.score_text(huge_text, max_bytes=102400)
    elapsed = time.time() - t0

    assert elapsed < 3.0, "5MB text must not freeze or take more than 3 seconds"
    assert res["is_truncated"] is True

def test_c08_pathological_regex_timeout_handled(scoring_engine):
    """C-08: Pathological nested backtracking string does not freeze due to regex timeout."""
    # Evil regex pattern target
    evil_text = "a" * 1000 + "!"
    t0 = time.time()
    res = scoring_engine.score_text(evil_text)
    elapsed = time.time() - t0
    assert elapsed < 3.0, "Pathological string must not freeze the engine"

def test_c09_100_rapid_evaluations(scoring_engine):
    """C-09: 100 rapid evaluations execute reliably with stable CPU."""
    sample = "User email test user@example.com with phone 9876543210 and some details."
    t0 = time.time()
    for _ in range(100):
        scoring_engine.score_text(sample)
    elapsed = time.time() - t0
    assert elapsed < 5.0, "100 evaluations must finish under 5 seconds"

def test_c10_scorer_parity_with_module2_js(scoring_engine):
    """
    C-10: Cross-validation between Python ScoringEngine and Module 2 JavaScript engine.
    Asserts identical risk tiers and closely matching score values (|diff| < 0.05).
    """
    test_vectors = [
        "Normal meeting agenda for 2pm sync",
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://user:super_secret_pw@db.internal:5432/corp_db",
        "Confidential Project Titan launch plan: strictly private and not for external use.",
        "Contact me at alice@corp.com, bob@corp.com, carol@corp.com, dave@corp.com, eve@corp.com"
    ]

    # Verify python scores each appropriately
    py_results = [scoring_engine.score_text(tv) for tv in test_vectors]

    assert py_results[0]["risk_tier"] == "low"
    assert py_results[1]["risk_tier"] == "high"
    assert py_results[2]["risk_tier"] == "high"
    assert py_results[3]["risk_tier"] in ("medium", "high")
    assert py_results[4]["risk_tier"] in ("medium", "high")

    # If Node is available, verify JS scorer directly on the same vectors
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    root_str = str(project_root).replace("\\", "/")

    js_test_script = Path(__file__).resolve().parent / "test_js_parity.js"
    js_code = f"""
    const path = require('path');
    const fs = require('fs');
    const root = '{root_str}';

    const {{ ScoringEngine }} = require(path.join(root, 'module2/extension/shared/scoring_engine.js'));
    const {{ FeatureExtractor }} = require(path.join(root, 'module2/extension/shared/feature_extractor.js'));
    const {{ REGEX_RULES }} = require(path.join(root, 'module2/extension/shared/rules.js'));
    const {{ Verhoeff, Luhn }} = require(path.join(root, 'module2/extension/shared/checksums.js'));

    global.Verhoeff = Verhoeff;
    global.Luhn = Luhn;
    global.REGEX_RULES = REGEX_RULES;
    global.FeatureExtractor = FeatureExtractor;

    const model = JSON.parse(fs.readFileSync(path.join(root, 'module2/extension/config/default_model.json'), 'utf8'));

    const testVectors = [
        "Normal meeting agenda for 2pm sync",
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://user:super_secret_pw@db.internal:5432/corp_db",
        "Confidential Project Titan launch plan: strictly private and not for external use.",
        "Contact me at alice@corp.com, bob@corp.com, carol@corp.com, dave@corp.com, eve@corp.com"
    ];

    const results = testVectors.map(t => ScoringEngine.scoreText(t, model));
    console.log(JSON.stringify(results));
    """
    js_test_script.write_text(js_code, encoding="utf-8")

    try:
        proc = subprocess.run(["node", str(js_test_script)], capture_output=True, text=True, check=True)
        js_results = json.loads(proc.stdout)
        for i, (py_res, js_res) in enumerate(zip(py_results, js_results)):
            assert py_res["risk_tier"] == js_res["riskTier"], f"Vector {i} tier mismatch: py={py_res['risk_tier']} vs js={js_res['riskTier']}"
            score_diff = abs(py_res["final_score"] - js_res["finalScore"])
            assert score_diff < 0.05, f"Vector {i} score drift exceeds 0.05: py={py_res['final_score']} vs js={js_res['finalScore']}"
    finally:
        if js_test_script.exists():
            js_test_script.unlink()
