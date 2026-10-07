"""
AgentGuard Risk Engine

Calculates transparent, explainable risk scores (0-100) by evaluating:
1. Resource sensitivity score (0-35)
2. Policy violation penalty (0-40)
3. Behavioral deviation / context penalty (0-25)
4. Sequence threat indicator (0-30)

Caps total score at 100 and produces human-readable RiskFactor breakdowns
to derive security decisions: ALLOW (< review_threshold),
REVIEW (>= review_threshold and < block_threshold), BLOCK (>= block_threshold).
"""
from typing import Optional, Any, Union
from enum import Enum
import hashlib
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.core.models import (
    AgentAction,
    ActionType,
    Decision,
    RiskLevel,
    RiskFactor,
    SecurityDecision,
)
from app.security.context import (
    ActionContext,
    ResourceSensitivity,
    identify_resource_sensitivity,
)
from app.config import get_settings


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyEvaluationResult(BaseModel):
    """Result from policy evaluation passed into the risk engine."""
    is_allowed: bool = True
    rule_name: Optional[str] = None
    violation_type: Optional[str] = None
    penalty: Optional[int] = None
    details: Optional[str] = None
    reasons: list[str] = Field(default_factory=list)

    @property
    def is_violation(self) -> bool:
        return not self.is_allowed or (self.penalty is not None and self.penalty > 0)


class SequenceFinding(BaseModel):
    """Finding from behavioral sequence detection."""
    name: str
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    score: Optional[int] = None
    description: str = ""
    matched_actions: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Comprehensive explainable risk assessment output."""
    action_id: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    decision: Decision
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    resource_score: int = Field(ge=0, le=35)
    policy_score: int = Field(ge=0, le=40)
    context_score: int = Field(ge=0, le=25)
    sequence_score: int = Field(ge=0, le=30)


class RiskEngine:
    """
    Transparent, explainable risk scoring engine.
    Combines target resource sensitivity, policy violations,
    session context deviations, and sequence threat indicators.
    """

    # Sensitivity weights (capped at 35)
    SENSITIVITY_SCORES = {
        ResourceSensitivity.CREDENTIAL: 35,
        ResourceSensitivity.SYSTEM: 28,
        ResourceSensitivity.EXTERNAL_NETWORK: 20,
        ResourceSensitivity.CONFIG: 15,
        ResourceSensitivity.SOURCE_CODE: 5,
        ResourceSensitivity.INTERNAL_NETWORK: 0,
        ResourceSensitivity.NORMAL: 0,
        ResourceSensitivity.NONE: 0,
    }

    def __init__(
        self,
        review_threshold: Optional[int] = None,
        block_threshold: Optional[int] = None,
        max_risk_score: Optional[int] = None,
    ) -> None:
        try:
            settings = get_settings()
            self.review_threshold = review_threshold if review_threshold is not None else settings.review_threshold
            self.block_threshold = block_threshold if block_threshold is not None else settings.block_threshold
            self.max_risk_score = max_risk_score if max_risk_score is not None else settings.max_risk_score
        except Exception:
            self.review_threshold = review_threshold if review_threshold is not None else 60
            self.block_threshold = block_threshold if block_threshold is not None else 80
            self.max_risk_score = max_risk_score if max_risk_score is not None else 100

    def calculate_resource_score(
        self,
        action: AgentAction,
        context: Optional[ActionContext] = None,
    ) -> tuple[int, list[RiskFactor]]:
        """
        Calculate resource sensitivity score (0-35) and factors.
        """
        if context and context.target_sensitivity:
            sensitivity = context.target_sensitivity
        else:
            sensitivity = identify_resource_sensitivity(
                action.target, action.action, action.parameters
            )

        base_score = self.SENSITIVITY_SCORES.get(sensitivity, 0)
        score = min(35, max(0, base_score))
        factors: list[RiskFactor] = []

        if score > 0:
            if sensitivity == ResourceSensitivity.CREDENTIAL:
                desc = f"+{score} Sensitive credential access ({action.target})"
            elif sensitivity == ResourceSensitivity.SYSTEM:
                desc = f"+{score} System-level resource or binary access ({action.target})"
            elif sensitivity == ResourceSensitivity.EXTERNAL_NETWORK:
                desc = f"+{score} External network communication ({action.target})"
            elif sensitivity == ResourceSensitivity.CONFIG:
                desc = f"+{score} Configuration resource access ({action.target})"
            elif sensitivity == ResourceSensitivity.SOURCE_CODE:
                desc = f"+{score} Source code modification or inspection ({action.target})"
            else:
                desc = f"+{score} Resource sensitivity level: {sensitivity.value}"

            factors.append(
                RiskFactor(
                    name="resource_sensitivity",
                    score=score,
                    description=desc,
                )
            )

        return score, factors

    def calculate_policy_penalty(
        self,
        action: AgentAction,
        policy_result: Optional[PolicyEvaluationResult] = None,
    ) -> tuple[int, list[RiskFactor]]:
        """
        Calculate policy violation penalty (0-40) and factors.
        """
        if policy_result is None or not policy_result.is_violation:
            return 0, []

        if policy_result.penalty is not None and policy_result.penalty > 0:
            penalty = min(40, max(0, policy_result.penalty))
        else:
            penalty = 35

        desc_detail = policy_result.details or policy_result.rule_name or f"Unauthorized action '{action.action.value}'"
        desc = f"+{penalty} Policy violation: {desc_detail}"

        factor = RiskFactor(
            name="policy_violation",
            score=penalty,
            description=desc,
        )
        return penalty, [factor]

    def calculate_context_penalty(
        self,
        action: AgentAction,
        context: Optional[ActionContext] = None,
    ) -> tuple[int, list[RiskFactor]]:
        """
        Calculate behavioral deviation / session context penalty (0-25) and factors.
        """
        if context is None:
            return 0, []

        factors: list[RiskFactor] = []
        raw_score = 0

        # 1. Action frequency anomaly
        frequency_threshold = 30
        if context.agent_profile and context.agent_profile.max_actions_per_minute:
            frequency_threshold = context.agent_profile.max_actions_per_minute

        if context.actions_in_last_minute > frequency_threshold:
            freq_score = 15 if context.actions_in_last_minute >= frequency_threshold * 2 else 10
            raw_score += freq_score
            factors.append(
                RiskFactor(
                    name="context_frequency_anomaly",
                    score=freq_score,
                    description=f"+{freq_score} High action frequency ({context.actions_in_last_minute} actions/min)",
                )
            )

        # 2. Accumulated error rate in session
        if context.error_counts >= 3:
            err_score = min(10, context.error_counts * 2)
            raw_score += err_score
            factors.append(
                RiskFactor(
                    name="context_error_accumulation",
                    score=err_score,
                    description=f"+{err_score} Repeated failures in session ({context.error_counts} errors)",
                )
            )

        # 3. Contextual cross-resource threat (credential touched + outbound egress / execution)
        if context.has_touched_credentials() and action.action in (
            ActionType.NETWORK_REQUEST,
            ActionType.RUN_COMMAND,
        ):
            cred_score = 15
            raw_score += cred_score
            factors.append(
                RiskFactor(
                    name="context_credential_exfiltration_risk",
                    score=cred_score,
                    description=f"+{cred_score} Network or command execution following credential access in session",
                )
            )
        elif context.sensitive_resource_count >= 2:
            sens_score = 8
            raw_score += sens_score
            factors.append(
                RiskFactor(
                    name="context_sensitive_accumulation",
                    score=sens_score,
                    description=f"+{sens_score} Multiple sensitive resources touched in session ({context.sensitive_resource_count})",
                )
            )

        # 4. Agent profile role deviation
        if context.agent_profile and context.agent_profile.allowed_actions:
            if action.action not in context.agent_profile.allowed_actions:
                prof_score = 10
                raw_score += prof_score
                factors.append(
                    RiskFactor(
                        name="context_profile_deviation",
                        score=prof_score,
                        description=f"+{prof_score} Action '{action.action.value}' deviates from profile role '{context.agent_profile.role}'",
                    )
                )

        capped_score = min(25, max(0, raw_score))
        return capped_score, factors

    def calculate_sequence_score(
        self,
        sequence_findings: Optional[list[Union[SequenceFinding, dict, str]]] = None,
    ) -> tuple[int, list[RiskFactor]]:
        """
        Calculate sequence threat indicator score (0-30) and factors.
        """
        if not sequence_findings:
            return 0, []

        factors: list[RiskFactor] = []
        raw_score = 0

        for item in sequence_findings:
            if isinstance(item, SequenceFinding):
                if item.score is not None:
                    item_score = item.score
                elif item.severity == ThreatSeverity.CRITICAL:
                    item_score = 30
                elif item.severity == ThreatSeverity.HIGH:
                    item_score = 25
                elif item.severity == ThreatSeverity.MEDIUM:
                    item_score = 15
                else:
                    item_score = 10

                desc = item.description or item.name
            elif isinstance(item, dict):
                item_score = item.get("score", 20)
                desc = item.get("description", item.get("name", "Sequence anomaly detected"))
            elif isinstance(item, str):
                item_score = 20
                desc = item
            else:
                item_score = 15
                desc = str(item)

            raw_score += item_score
            factors.append(
                RiskFactor(
                    name="sequence_threat",
                    score=min(30, item_score),
                    description=f"+{min(30, item_score)} Sequence threat: {desc}",
                )
            )

        capped_score = min(30, max(0, raw_score))
        return capped_score, factors

    def evaluate(
        self,
        action: AgentAction,
        context: Optional[ActionContext] = None,
        policy_result: Optional[PolicyEvaluationResult] = None,
        sequence_findings: Optional[list[Any]] = None,
    ) -> RiskAssessment:
        """
        Perform a full risk assessment calculation and factor breakdown.
        """
        res_score, res_factors = self.calculate_resource_score(action, context)
        pol_score, pol_factors = self.calculate_policy_penalty(action, policy_result)
        ctx_score, ctx_factors = self.calculate_context_penalty(action, context)
        seq_score, seq_factors = self.calculate_sequence_score(sequence_findings)

        total_raw = res_score + pol_score + ctx_score + seq_score
        total_score = min(self.max_risk_score, max(0, total_raw))

        all_factors = res_factors + pol_factors + ctx_factors + seq_factors
        reasons = [f.description for f in all_factors if f.score > 0]

        # Determine decision based on thresholds
        if total_score >= self.block_threshold:
            decision = Decision.BLOCK
        elif total_score >= self.review_threshold:
            decision = Decision.REVIEW
        else:
            decision = Decision.ALLOW

        risk_level = SecurityDecision.risk_score_to_level(total_score)

        return RiskAssessment(
            action_id=action.id,
            risk_score=total_score,
            risk_level=risk_level,
            decision=decision,
            risk_factors=all_factors,
            reasons=reasons,
            resource_score=res_score,
            policy_score=pol_score,
            context_score=ctx_score,
            sequence_score=seq_score,
        )

    def evaluate_action(
        self,
        action: AgentAction,
        context: Optional[ActionContext] = None,
        policy_result: Optional[PolicyEvaluationResult] = None,
        sequence_findings: Optional[list[Any]] = None,
        previous_event_hash: Optional[str] = None,
    ) -> SecurityDecision:
        """
        Evaluate an action and return a complete SecurityDecision model.
        """
        assessment = self.evaluate(
            action=action,
            context=context,
            policy_result=policy_result,
            sequence_findings=sequence_findings,
        )

        now = datetime.now(timezone.utc)
        # Compute event hash for audit integrity
        payload = (
            f"{action.id}:{action.agent_id}:{action.action.value}:{action.target}:"
            f"{assessment.risk_score}:{assessment.decision.value}:{now.isoformat()}:"
            f"{previous_event_hash or '0'*64}"
        )
        event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        return SecurityDecision(
            action=action,
            decision=assessment.decision,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            risk_factors=assessment.risk_factors,
            reasons=assessment.reasons,
            event_hash=event_hash,
            previous_event_hash=previous_event_hash,
            evaluated_at=now,
        )


_risk_engine_instance: Optional[RiskEngine] = None


def get_risk_engine() -> RiskEngine:
    """Return singleton RiskEngine instance."""
    global _risk_engine_instance
    if _risk_engine_instance is None:
        _risk_engine_instance = RiskEngine()
    return _risk_engine_instance
