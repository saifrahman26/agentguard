"""
AgentGuard Structured Logging System

Provides JSON-formatted, timestamped logging.
Every log line is valid JSON — machine-readable and dashboardable.
Uses Python's stdlib logging module — no extra dependencies.
"""
import logging
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """
    Custom log formatter that outputs each log record as a JSON object.
    
    Output example:
        {"timestamp": "2024-...", "level": "INFO", "module": "main",
         "function": "health_check", "message": "Server started"}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        # Attach exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    app_name: str = "agentguard",
) -> logging.Logger:
    """
    Configure and return the root AgentGuard logger.
    
    Outputs to:
      - stdout (always)
      - log_file (if specified)
    
    Args:
        level:    Logging level string (DEBUG | INFO | WARNING | ERROR)
        log_file: Optional path to write logs to disk
        app_name: Logger namespace
    
    Returns:
        Configured Logger instance
    """
    logger = logging.getLogger(app_name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers on re-import
    if logger.handlers:
        return logger

    formatter = JSONFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger under the agentguard namespace.
    
    Usage:
        from app.core.logging_setup import get_logger
        logger = get_logger(__name__)
        logger.info("Something happened")
    """
    return logging.getLogger(f"agentguard.{name}")
