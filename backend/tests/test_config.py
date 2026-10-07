"""
Tests for AgentGuard Configuration System
"""
import pytest


def test_default_config_loads():
    """Settings should load with defaults without any .env file."""
    from app.config import get_settings
    s = get_settings()
    assert s.app_name == "AgentGuard"
    assert s.app_version == "0.1.0"


def test_thresholds_are_sensible():
    """Review threshold must be below block threshold, both within 0-100."""
    from app.config import get_settings
    s = get_settings()
    assert 0 < s.review_threshold < s.block_threshold <= s.max_risk_score


def test_default_network_policy_is_deny():
    """Network policy should default to deny (fail closed)."""
    from app.config import get_settings
    s = get_settings()
    assert s.default_network_policy == "deny"


def test_llm_is_optional():
    """LLM fields should be None by default — system works without them."""
    from app.config import get_settings
    s = get_settings()
    assert s.llm_provider is None
    assert s.llm_api_key is None
    assert s.llm_model is None


def test_settings_singleton():
    """get_settings() should return the same instance on repeated calls."""
    from app.config import get_settings
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
