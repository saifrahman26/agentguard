"""
Tests for AgentGuard Structured Logging System
"""
import json
import logging
import pytest


def test_setup_logging_returns_logger():
    """setup_logging should return a Logger instance."""
    from app.core.logging_setup import setup_logging
    logger = setup_logging(level="DEBUG", app_name="agentguard_test_setup")
    assert isinstance(logger, logging.Logger)


def test_get_logger_returns_child_logger():
    """get_logger should return a logger under the agentguard namespace."""
    from app.core.logging_setup import get_logger
    logger = get_logger("test_module")
    assert "agentguard" in logger.name


def test_json_formatter_output_is_valid_json(capsys):
    """JSONFormatter must produce valid JSON on every log line."""
    from app.core.logging_setup import JSONFormatter
    import io

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter())

    test_logger = logging.getLogger("agentguard_json_test")
    test_logger.handlers.clear()
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.DEBUG)
    test_logger.propagate = False

    test_logger.info("Test message from JSON formatter")

    output = stream.getvalue().strip()
    assert output, "Logger produced no output"

    parsed = json.loads(output)
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert parsed["level"] == "INFO"
    assert "Test message" in parsed["message"]


def test_json_formatter_includes_module_info(capsys):
    """JSON log output must include module and function name."""
    from app.core.logging_setup import JSONFormatter
    import io

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter())

    test_logger = logging.getLogger("agentguard_module_test")
    test_logger.handlers.clear()
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.DEBUG)
    test_logger.propagate = False

    test_logger.warning("Module info test")

    output = stream.getvalue().strip()
    parsed = json.loads(output)
    assert "module" in parsed
    assert "function" in parsed
    assert "line" in parsed
