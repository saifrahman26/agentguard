"""
Tests for AgentGuard Context Engine and Risk Score Engine

Validates:
- Target resource sensitivity classification (CREDENTIAL, CONFIG, SOURCE_CODE, SYSTEM, EXTERNAL_NETWORK)
- ContextBuilder session history, error tracking, frequency calculation, profile matching
- RiskEngine calculation across all 4 components (Resource, Policy, Context, Sequence)
- Factor breakdowns and transparent descriptions
- Cap at 100 (min 0)
- Threshold boundaries: ALLOW (< 60), REVIEW (60-79), BLOCK (>= 80)
- SecurityDecision integration and event hashing
"""
import pytest
from datetime import datetime, timezone, timedelta

from app.core.models import AgentAction, ActionType, Decision, RiskLevel, RiskFactor
from app.security.context import (
    ResourceSensitivity,
    identify_resource_sensitivity,
    AgentProfile,
    ActionContext,
    ContextBuilder,
    get_context_builder,
)
from app.security.risk import (
    RiskEngine,
    PolicyEvaluationResult,
    SequenceFinding,
    ThreatSeverity,
    RiskAssessment,
    get_risk_engine,
)


# ===========================================================================
# 1. Resource Sensitivity Tests
# ===========================================================================

def test_identify_credential_sensitivity():
    """Target patterns matching credentials must be classified as CREDENTIAL."""
    assert identify_resource_sensitivity(".env") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("/path/to/.env.local") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("~/.ssh/id_rsa") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("~/.ssh/id_ed25519") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("certs/server.key") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("secrets/jwt.pem") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity(".aws/credentials") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("config/db_password.txt") == ResourceSensitivity.CREDENTIAL
    assert identify_resource_sensitivity("api_keys.json") == ResourceSensitivity.CREDENTIAL


def test_identify_system_sensitivity():
    """Target patterns matching system files or dangerous commands must be classified as SYSTEM."""
    assert identify_resource_sensitivity("/etc/passwd") == ResourceSensitivity.SYSTEM
    assert identify_resource_sensitivity("/etc/shadow") == ResourceSensitivity.SYSTEM
    assert identify_resource_sensitivity("/proc/cpuinfo") == ResourceSensitivity.SYSTEM
    assert identify_resource_sensitivity("C:\\Windows\\System32\\cmd.exe") == ResourceSensitivity.SYSTEM
    assert identify_resource_sensitivity("/bin/bash") == ResourceSensitivity.SYSTEM
    assert identify_resource_sensitivity("rm -rf /") == ResourceSensitivity.SYSTEM
    assert identify_resource_sensitivity("sudo chmod 777 /var/log") == ResourceSensitivity.SYSTEM


def test_identify_config_sensitivity():
    """Target patterns matching configuration files must be classified as CONFIG."""
    assert identify_resource_sensitivity("config.yaml") == ResourceSensitivity.CONFIG
    assert identify_resource_sensitivity("settings.ini") == ResourceSensitivity.CONFIG
    assert identify_resource_sensitivity("Dockerfile") == ResourceSensitivity.CONFIG
    assert identify_resource_sensitivity(".bashrc") == ResourceSensitivity.CONFIG
    assert identify_resource_sensitivity("nginx.conf") == ResourceSensitivity.CONFIG


def test_identify_source_code_sensitivity():
    """Target patterns matching code files must be classified as SOURCE_CODE."""
    assert identify_resource_sensitivity("app/main.py") == ResourceSensitivity.SOURCE_CODE
    assert identify_resource_sensitivity("src/index.ts") == ResourceSensitivity.SOURCE_CODE
    assert identify_resource_sensitivity("src/utils.cpp") == ResourceSensitivity.SOURCE_CODE


def test_identify_network_sensitivity():
    """Target patterns matching URLs or external endpoints must be classified accordingly."""
    assert identify_resource_sensitivity("https://api.openai.com/v1") == ResourceSensitivity.EXTERNAL_NETWORK
    assert identify_resource_sensitivity("http://185.220.101.5/exfil") == ResourceSensitivity.EXTERNAL_NETWORK
    assert identify_resource_sensitivity("http://localhost:8000/health") == ResourceSensitivity.INTERNAL_NETWORK
    assert identify_resource_sensitivity("http://127.0.0.1:5000") == ResourceSensitivity.INTERNAL_NETWORK
    assert (
        identify_resource_sensitivity("data", action=ActionType.NETWORK_REQUEST)
        == ResourceSensitivity.EXTERNAL_NETWORK
    )


# ===========================================================================
# 2. Context Builder Tests
# ===========================================================================

def test_context_builder_builds_context():
    """ContextBuilder must correctly aggregate session history and metrics."""
    builder = ContextBuilder()

    profile = AgentProfile(
        agent_id="test-agent-1",
        role="developer",
        allowed_actions=[ActionType.READ_FILE, ActionType.WRITE_FILE],
        max_actions_per_minute=20,
    )
    builder.register_profile(profile)

    now = datetime.now(timezone.utc)
    session_id = "session-123"

    action1 = AgentAction(
        agent_id="test-agent-1",
        session_id=session_id,
        action=ActionType.READ_FILE,
        target="src/app.py",
        timestamp=now - timedelta(seconds=30),
    )
    action2 = AgentAction(
        agent_id="test-agent-1",
        session_id=session_id,
        action=ActionType.READ_FILE,
        target=".env",
        timestamp=now - timedelta(seconds=10),
    )
    action3 = AgentAction(
        agent_id="test-agent-1",
        session_id=session_id,
        action=ActionType.NETWORK_REQUEST,
        target="https://external-api.com/upload",
        timestamp=now,
    )

    builder.record_action(action1)
    builder.record_action(action2)
    builder.record_error(session_id, "File not found error")

    context = builder.build_context(action3)

    assert context.agent_id == "test-agent-1"
    assert context.session_id == session_id
    assert context.total_actions_in_session == 2
    assert context.actions_in_last_minute == 2
    assert context.error_counts == 1
    assert context.has_touched_credentials() is True
    assert ".env" in context.sensitive_resources_touched
    assert context.agent_profile is not None
    assert context.agent_profile.role == "developer"
    assert context.target_sensitivity == ResourceSensitivity.EXTERNAL_NETWORK


def test_context_builder_session_isolation():
    """ContextBuilder must isolate sessions cleanly."""
    builder = ContextBuilder()

    action_a = AgentAction(
        agent_id="agent-a",
        session_id="session-a",
        action=ActionType.READ_FILE,
        target=".env",
    )
    action_b = AgentAction(
        agent_id="agent-b",
        session_id="session-b",
        action=ActionType.READ_FILE,
        target="readme.md",
    )

    builder.record_action(action_a)
    builder.record_action(action_b)

    ctx_a = builder.build_context(action_a)
    ctx_b = builder.build_context(action_b)

    assert ctx_a.total_actions_in_session == 1
    assert ctx_a.has_touched_credentials() is True

    assert ctx_b.total_actions_in_session == 1
    assert ctx_b.has_touched_credentials() is False


# ===========================================================================
# 3. Risk Engine — Component Calculations & Factor Breakdowns
# ===========================================================================

def test_risk_engine_resource_sensitivity_scoring():
    """RiskEngine calculates correct score and factor breakdown for resource sensitivity."""
    engine = RiskEngine(review_threshold=60, block_threshold=80)

    action_cred = AgentAction(
        agent_id="agent-1",
        action=ActionType.READ_FILE,
        target=".env",
    )
    score, factors = engine.calculate_resource_score(action_cred)
    assert score == 35
    assert len(factors) == 1
    assert factors[0].name == "resource_sensitivity"
    assert "+35" in factors[0].description
    assert ".env" in factors[0].description

    action_sys = AgentAction(
        agent_id="agent-1",
        action=ActionType.READ_FILE,
        target="/etc/passwd",
    )
    score, factors = engine.calculate_resource_score(action_sys)
    assert score == 28
    assert len(factors) == 1
    assert factors[0].score == 28

    action_safe = AgentAction(
        agent_id="agent-1",
        action=ActionType.READ_FILE,
        target="readme.md",
    )
    score, factors = engine.calculate_resource_score(action_safe)
    assert score == 0
    assert len(factors) == 0


def test_risk_engine_policy_violation_penalty():
    """RiskEngine applies policy penalties up to 40 max with clear factors."""
    engine = RiskEngine()
    action = AgentAction(
        agent_id="agent-1",
        action=ActionType.RUN_COMMAND,
        target="rm -rf /tmp/test",
    )

    # Allowed result -> 0 penalty
    allowed = PolicyEvaluationResult(is_allowed=True)
    score, factors = engine.calculate_policy_penalty(action, allowed)
    assert score == 0
    assert len(factors) == 0

    # Blocked result with default penalty
    disallowed = PolicyEvaluationResult(
        is_allowed=False,
        rule_name="disallow_shell_commands",
        details="Shell execution forbidden for this agent",
    )
    score, factors = engine.calculate_policy_penalty(action, disallowed)
    assert score == 35
    assert len(factors) == 1
    assert factors[0].name == "policy_violation"
    assert "Shell execution forbidden" in factors[0].description

    # Blocked result with custom high penalty (capped at 40)
    critical_violation = PolicyEvaluationResult(
        is_allowed=False,
        penalty=50,
        details="Critical policy violation",
    )
    score, factors = engine.calculate_policy_penalty(action, critical_violation)
    assert score == 40


def test_risk_engine_context_penalty():
    """RiskEngine penalizes contextual behavioral deviations up to 25 max."""
    engine = RiskEngine()
    now = datetime.now(timezone.utc)

    profile = AgentProfile(
        agent_id="agent-strict",
        role="analyst",
        allowed_actions=[ActionType.READ_FILE],
        max_actions_per_minute=10,
    )

    context = ActionContext(
        session_id="session-high-risk",
        agent_id="agent-strict",
        actions_in_last_minute=25,  # Rate exceeded
        error_counts=4,            # Repeated errors
        sensitive_resources_touched=[".env"],  # Credential touched
        agent_profile=profile,
    )

    action = AgentAction(
        agent_id="agent-strict",
        action=ActionType.NETWORK_REQUEST,  # Network after credential + not in allowed_actions
        target="https://attacker.site/leak",
        timestamp=now,
    )

    score, factors = engine.calculate_context_penalty(action, context)
    # Individual penalties: freq (15) + errors (8) + cred_exfil (15) + profile_dev (10) = 48 -> capped at 25
    assert score == 25
    assert len(factors) >= 3
    factor_names = [f.name for f in factors]
    assert "context_frequency_anomaly" in factor_names
    assert "context_error_accumulation" in factor_names
    assert "context_credential_exfiltration_risk" in factor_names
    assert "context_profile_deviation" in factor_names


def test_risk_engine_sequence_threat_scoring():
    """RiskEngine converts sequence detection findings to sequence scores up to 30 max."""
    engine = RiskEngine()

    findings = [
        SequenceFinding(
            name="recon_to_exfiltration",
            severity=ThreatSeverity.CRITICAL,
            score=30,
            description="Reconnaissance followed by exfiltration sequence detected",
        ),
        SequenceFinding(
            name="lateral_movement",
            severity=ThreatSeverity.MEDIUM,
            score=15,
            description="Lateral movement probe",
        ),
    ]

    score, factors = engine.calculate_sequence_score(findings)
    assert score == 30  # Capped at 30
    assert len(factors) == 2
    assert factors[0].name == "sequence_threat"


# ===========================================================================
# 4. Total Score, Cap at 100, and Decision Thresholds
# ===========================================================================

def test_risk_engine_decision_allow():
    """Score < 60 must result in Decision.ALLOW."""
    engine = RiskEngine(review_threshold=60, block_threshold=80)
    action = AgentAction(
        agent_id="agent-1",
        action=ActionType.READ_FILE,
        target="src/app.py",
    )
    assessment = engine.evaluate(action=action)
    assert assessment.risk_score < 60
    assert assessment.decision == Decision.ALLOW
    assert assessment.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)


def test_risk_engine_decision_review():
    """Score >= 60 and < 80 must result in Decision.REVIEW."""
    engine = RiskEngine(review_threshold=60, block_threshold=80)

    # Credential read (35) + Policy violation (35) = 70 -> REVIEW
    action = AgentAction(
        agent_id="agent-1",
        action=ActionType.READ_FILE,
        target=".env",
    )
    policy_res = PolicyEvaluationResult(
        is_allowed=False,
        penalty=35,
        details="Restricted file read attempt",
    )

    assessment = engine.evaluate(action=action, policy_result=policy_res)
    assert assessment.risk_score == 70
    assert assessment.decision == Decision.REVIEW
    assert assessment.risk_level == RiskLevel.HIGH
    assert len(assessment.risk_factors) == 2


def test_risk_engine_decision_block():
    """Score >= 80 must result in Decision.BLOCK."""
    engine = RiskEngine(review_threshold=60, block_threshold=80)

    # Credential target (35) + Policy penalty (35) + Sequence threat (20) = 90 -> BLOCK
    action = AgentAction(
        agent_id="agent-1",
        action=ActionType.READ_FILE,
        target=".env",
    )
    policy_res = PolicyEvaluationResult(is_allowed=False, penalty=35)
    sequence = [
        SequenceFinding(
            name="credential_harvesting",
            severity=ThreatSeverity.HIGH,
            score=25,
            description="Automated credential harvesting",
        )
    ]

    assessment = engine.evaluate(
        action=action,
        policy_result=policy_res,
        sequence_findings=sequence,
    )
    assert assessment.risk_score >= 80
    assert assessment.decision == Decision.BLOCK
    assert assessment.risk_level == RiskLevel.CRITICAL


def test_risk_score_strict_cap_at_100():
    """Total risk score must never exceed 100 even with all components maximum."""
    engine = RiskEngine()

    # Resource: 35, Policy: 40, Context: 25, Sequence: 30 => Sum = 130 -> Capped at 100
    action = AgentAction(
        agent_id="bad-agent",
        action=ActionType.NETWORK_REQUEST,
        target="https://malicious-c2.com/exfil",
    )

    profile = AgentProfile(
        agent_id="bad-agent",
        role="read_only",
        allowed_actions=[ActionType.READ_FILE],
        max_actions_per_minute=5,
    )

    context = ActionContext(
        session_id="attack-session",
        agent_id="bad-agent",
        actions_in_last_minute=50,
        error_counts=10,
        sensitive_resources_touched=[".env", "id_rsa"],
        agent_profile=profile,
        target_sensitivity=ResourceSensitivity.CREDENTIAL,
    )

    policy_res = PolicyEvaluationResult(
        is_allowed=False,
        penalty=40,
        details="Full security policy lockout",
    )

    findings = [
        SequenceFinding(
            name="full_kill_chain",
            severity=ThreatSeverity.CRITICAL,
            score=30,
            description="Full automated attack sequence identified",
        )
    ]

    assessment = engine.evaluate(
        action=action,
        context=context,
        policy_result=policy_res,
        sequence_findings=findings,
    )

    assert assessment.risk_score == 100
    assert assessment.decision == Decision.BLOCK
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.resource_score <= 35
    assert assessment.policy_score <= 40
    assert assessment.context_score <= 25
    assert assessment.sequence_score <= 30


# ===========================================================================
# 5. Security Decision Model Generation
# ===========================================================================

def test_evaluate_action_generates_security_decision():
    """evaluate_action must return a valid SecurityDecision with cryptographic event hash."""
    engine = RiskEngine()
    action = AgentAction(
        agent_id="agent-test",
        action=ActionType.READ_FILE,
        target="main.py",
    )

    decision = engine.evaluate_action(
        action=action,
        previous_event_hash="0" * 64,
    )

    assert decision.action.id == action.id
    assert decision.decision == Decision.ALLOW
    assert decision.risk_score == 5  # Source code target = 5
    assert decision.risk_level == RiskLevel.LOW
    assert decision.event_hash is not None
    assert len(decision.event_hash) == 64
    assert decision.previous_event_hash == "0" * 64


def test_singleton_getters():
    """get_risk_engine and get_context_builder must return valid singleton instances."""
    re1 = get_risk_engine()
    re2 = get_risk_engine()
    assert re1 is re2

    cb1 = get_context_builder()
    cb2 = get_context_builder()
    assert cb1 is cb2
