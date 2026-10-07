"""
Tests for AgentGuard Pydantic Domain Models
"""
import pytest
from datetime import datetime, timezone


def test_agent_action_creates_with_defaults():
    """AgentAction should auto-generate id, session_id, and timestamp."""
    from app.core.models import AgentAction, ActionType
    action = AgentAction(
        agent_id="coding-agent-01",
        action=ActionType.READ_FILE,
        target="./src/main.py",
    )
    assert action.id is not None
    assert action.session_id is not None
    assert action.timestamp is not None
    assert action.parameters == {}


def test_agent_action_rejects_empty_agent_id():
    """agent_id must not be empty."""
    from app.core.models import AgentAction, ActionType
    with pytest.raises(Exception):
        AgentAction(
            agent_id="  ",
            action=ActionType.READ_FILE,
            target="./src/main.py",
        )


def test_agent_action_rejects_empty_target():
    """target must not be empty."""
    from app.core.models import AgentAction, ActionType
    with pytest.raises(Exception):
        AgentAction(
            agent_id="agent-01",
            action=ActionType.READ_FILE,
            target="  ",
        )


def test_decision_enum_values():
    """Decision enum must have exactly ALLOW, REVIEW, BLOCK."""
    from app.core.models import Decision
    assert Decision.ALLOW == "ALLOW"
    assert Decision.REVIEW == "REVIEW"
    assert Decision.BLOCK == "BLOCK"


def test_risk_score_to_level_mapping():
    """Risk score to level conversion must follow defined thresholds."""
    from app.core.models import SecurityDecision, RiskLevel
    assert SecurityDecision.risk_score_to_level(0) == RiskLevel.LOW
    assert SecurityDecision.risk_score_to_level(39) == RiskLevel.LOW
    assert SecurityDecision.risk_score_to_level(40) == RiskLevel.MEDIUM
    assert SecurityDecision.risk_score_to_level(59) == RiskLevel.MEDIUM
    assert SecurityDecision.risk_score_to_level(60) == RiskLevel.HIGH
    assert SecurityDecision.risk_score_to_level(79) == RiskLevel.HIGH
    assert SecurityDecision.risk_score_to_level(80) == RiskLevel.CRITICAL
    assert SecurityDecision.risk_score_to_level(100) == RiskLevel.CRITICAL


def test_action_type_enum_values():
    """All 7 tool action types must be present."""
    from app.core.models import ActionType
    assert ActionType.READ_FILE == "read_file"
    assert ActionType.WRITE_FILE == "write_file"
    assert ActionType.DELETE_FILE == "delete_file"
    assert ActionType.RUN_COMMAND == "run_command"
    assert ActionType.NETWORK_REQUEST == "network_request"
    assert ActionType.INSTALL_PACKAGE == "install_package"
    assert ActionType.LIST_DIRECTORY == "list_directory"
