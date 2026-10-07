"""
AgentGuard Threat Detector

Unified threat detection coordinator combining:
- Deterministic Rule Engine (rules.py)
- Dynamic Behavioral Sequence Engine (sequences.py)

Produces comprehensive SecurityDecision objects with explainable risk scores,
risk factors, and tamper-evident audit hash chaining.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from app.core.models import (
    AgentAction,
    SecurityDecision,
    Decision,
    RiskLevel,
    RiskFactor,
)
from app.config import get_settings
from app.detection.rules import RuleEngine, RuleMatch, get_default_rules
from app.security.sequences import BehavioralSequenceEngine, SequenceThreat
from app.audit.integrity import compute_event_hash


class ThreatDetector:
    """
    Coordinates static detection rules and behavioral sequence analysis
    to produce authoritative security decisions for agent actions.
    """

    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        sequence_engine: Optional[BehavioralSequenceEngine] = None,
        review_threshold: Optional[int] = None,
        block_threshold: Optional[int] = None,
    ):
        settings = get_settings()
        self.rule_engine = rule_engine or RuleEngine(get_default_rules())
        self.sequence_engine = sequence_engine or BehavioralSequenceEngine()
        self.review_threshold = review_threshold if review_threshold is not None else settings.review_threshold
        self.block_threshold = block_threshold if block_threshold is not None else settings.block_threshold
        
        # Session hash tracker for tamper-evident event hash chaining
        self._last_event_hashes: Dict[str, str] = {}

    def evaluate_action(
        self,
        action: AgentAction,
        context: Optional[Dict[str, Any]] = None,
    ) -> SecurityDecision:
        """
        Evaluate an incoming agent action against both static rules and sequence chains.
        
        Args:
            action: Proposed AgentAction to inspect.
            context: Optional contextual parameters.
            
        Returns:
            Complete SecurityDecision with decision status, risk score, factors, and hash chain.
        """
        # 1. Run deterministic static detection rules
        rule_matches: List[RuleMatch] = self.rule_engine.evaluate(action, context)
        
        # 2. Run dynamic behavioral sequence analysis
        sequence_threats: List[SequenceThreat] = self.sequence_engine.process_action(action)

        # 3. Aggregate risk factors and calculate composite risk score
        risk_factors: List[RiskFactor] = []
        reasons: List[str] = []
        max_score = 0

        for match in rule_matches:
            risk_factors.append(
                RiskFactor(
                    name=match.rule_name,
                    score=match.risk_score,
                    description=match.description,
                )
            )
            reasons.append(f"[Rule Violation] {match.description}")
            if match.risk_score > max_score:
                max_score = match.risk_score

        for seq_threat in sequence_threats:
            risk_factors.append(
                RiskFactor(
                    name=f"Sequence: {seq_threat.name}",
                    score=seq_threat.risk_score,
                    description=seq_threat.description,
                )
            )
            reasons.append(f"[Sequence Threat] {seq_threat.description}")
            if seq_threat.risk_score > max_score:
                max_score = seq_threat.risk_score

        # Default benign baseline
        final_risk_score = min(max(max_score, 0), 100)
        risk_level = SecurityDecision.risk_score_to_level(final_risk_score)

        # 4. Determine authorization decision
        if final_risk_score >= self.block_threshold:
            decision = Decision.BLOCK
        elif final_risk_score >= self.review_threshold:
            decision = Decision.REVIEW
        else:
            decision = Decision.ALLOW
            if not reasons:
                reasons.append("Action passed all security rules and behavioral checks")

        # 5. Compute audit event hash chain
        session_id = action.session_id
        prev_hash = self._last_event_hashes.get(session_id)
        
        event_payload = {
            "action_id": action.id,
            "agent_id": action.agent_id,
            "session_id": action.session_id,
            "action": action.action.value,
            "target": action.target,
            "risk_score": final_risk_score,
            "decision": decision.value,
            "timestamp": action.timestamp.isoformat(),
        }
        event_hash = compute_event_hash(event_payload, prev_hash)
        self._last_event_hashes[session_id] = event_hash

        return SecurityDecision(
            action=action,
            decision=decision,
            risk_score=final_risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            reasons=reasons,
            event_hash=event_hash,
            previous_event_hash=prev_hash,
            evaluated_at=datetime.now(timezone.utc),
        )

    def detect(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> SecurityDecision:
        """Alias for evaluate_action."""
        return self.evaluate_action(action, context)

    def __call__(self, action: AgentAction) -> SecurityDecision:
        """Enables ThreatDetector instance to be used directly as a SecurityInterceptor callable."""
        return self.evaluate_action(action)

    def reset_session(self, session_id: str) -> None:
        """Reset session tracking state."""
        self.sequence_engine.reset_session(session_id)
        if session_id in self._last_event_hashes:
            del self._last_event_hashes[session_id]
