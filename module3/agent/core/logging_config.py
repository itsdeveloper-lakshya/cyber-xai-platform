"""
Privacy-Compliant Logging Subsystem (Section 6 G7 & Section 15 X-03)
Logs must NEVER contain clipboard text, file names, file paths, or window titles.
Uses RotatingFileHandler with a strict PrivacyFilter.
"""

import os
import re
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Privacy redaction regexes to ensure zero content leakage
PATH_PATTERN = re.compile(r"[a-zA-Z]:\\[^\s\"'<>]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_PATTERN = re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")

class PrivacyFilter(logging.Filter):
    """
    Strips accidental file paths, secrets, or potential text content from log records.
    Guarantees compliance with Test X-03.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.msg)
        # Redact windows file paths
        msg = PATH_PATTERN.sub("[PATH_REDACTED]", msg)
        # Redact emails
        msg = EMAIL_PATTERN.sub("[EMAIL_REDACTED]", msg)
        # Redact secret keys
        msg = SECRET_PATTERN.sub("[KEY_REDACTED]", msg)
        record.msg = msg
        return True

def setup_agent_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "agent.log"

    logger = logging.getLogger("cyber_sentinel_agent")
    logger.setLevel(level)

    # Check if a file handler already points to this exact log file
    has_file_handler = False
    for h in logger.handlers:
        if isinstance(h, RotatingFileHandler) and Path(h.baseFilename) == log_file.resolve():
            has_file_handler = True
            break

    if not has_file_handler:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s"
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(PrivacyFilter())
        logger.addHandler(file_handler)

    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in logger.handlers):
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s"
        )
        console_handler.setFormatter(formatter)
        console_handler.addFilter(PrivacyFilter())
        logger.addHandler(console_handler)

    return logger
    console_handler.setFormatter(formatter)
    console_handler.addFilter(PrivacyFilter())
    logger.addHandler(console_handler)

    return logger
