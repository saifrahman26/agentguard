"""
Unit Tests for AgentGuard Simulated Agent & Action Interception
"""
import pytest
from app.agent.simulator import SimulatedAgent, AgentExecutionResult
from app.core.models import (
    AgentAction,
    ActionType,
    Decision,
    RiskLevel,
    SecurityDecision,
)


def test_agent_initialization():
    agent = SimulatedAgent(agent_id="test-bot-01")
    assert agent.agent_id == "test-bot-01"
    assert agent.session_id is not None
    assert len(agent.history) == 0


def test_agent_propose_action_allowed():
    agent = SimulatedAgent(agent_id="test-bot-01")
    result = agent.read_file("./project/main.py")
    
    assert isinstance(result, AgentExecutionResult)
    assert result.decision.decision == Decision.ALLOW
    assert result.executed is True
    assert result.blocked is False
    assert result.tool_result is not None
    assert result.tool_result.success is True
    assert "def main():" in result.tool_result.output
    assert len(agent.history) == 1


def test_agent_interceptor_blocks_action():
    # Custom blocking interceptor to simulate AgentGuard security policy
    def blocking_interceptor(action: AgentAction) -> SecurityDecision:
        if action.target == ".env":
            return SecurityDecision(
                action=action,
                decision=Decision.BLOCK,
                risk_score=95,
                risk_level=RiskLevel.CRITICAL,
                risk_factors=[],
                reasons=["Access to sensitive .env file is prohibited"],
                event_hash="fake_hash",
            )
        return SecurityDecision(
            action=action,
            decision=Decision.ALLOW,
            risk_score=10,
            risk_level=RiskLevel.LOW,
            risk_factors=[],
            reasons=[],
            event_hash="fake_hash",
        )

    agent = SimulatedAgent(agent_id="test-bot-01", interceptor=blocking_interceptor)
    
    # 1. Propose reading safe file -> should execute
    safe_res = agent.read_file("./project/main.py")
    assert safe_res.decision.decision == Decision.ALLOW
    assert safe_res.executed is True
    assert safe_res.blocked is False

    # 2. Propose reading sensitive file -> MUST BE BLOCKED and NOT EXECUTED
    blocked_res = agent.read_file(".env")
    assert blocked_res.decision.decision == Decision.BLOCK
    assert blocked_res.executed is False
    assert blocked_res.blocked is True
    assert "blocked by AgentGuard" in blocked_res.tool_result.error
    assert "Access to sensitive .env file is prohibited" in blocked_res.tool_result.error


def test_agent_interceptor_review_action():
    def review_interceptor(action: AgentAction) -> SecurityDecision:
        return SecurityDecision(
            action=action,
            decision=Decision.REVIEW,
            risk_score=65,
            risk_level=RiskLevel.HIGH,
            risk_factors=[],
            reasons=["High-risk outbound network request requires approval"],
            event_hash="fake_hash",
        )

    agent = SimulatedAgent(agent_id="test-bot-01", interceptor=review_interceptor)
    res = agent.network_request("https://external-api.com/upload")
    assert res.decision.decision == Decision.REVIEW
    assert res.executed is False
    assert res.blocked is False
    assert "human review" in res.tool_result.error


def test_agent_run_sequence():
    agent = SimulatedAgent(agent_id="sequence-bot")
    steps = [
        {"action": ActionType.WRITE_FILE, "target": "./project/hello.py", "parameters": {"content": "print('hello')"}},
        {"action": ActionType.READ_FILE, "target": "./project/hello.py"},
        {"action": ActionType.RUN_COMMAND, "target": "pytest"},
    ]
    results = agent.run_sequence(steps)
    assert len(results) == 3
    assert all(r.executed is True for r in results)
    assert len(agent.history) == 3
