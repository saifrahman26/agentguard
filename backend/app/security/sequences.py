"""
AgentGuard Behavioral Sequence Engine

Implements sliding window and graph-based sequence detection across an agent's session history.
Detects multi-step attack chains such as:
- Credential Access -> Outbound Exfiltration
- Prompt Injection -> Weaponized Execution
- Reconnaissance -> Privilege Escalation
- Discovery -> Mass Destruction
- Package Poisoning -> Malicious Activity
- Data Staging -> Exfiltration
"""
import uuid
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Set, Tuple
from pydantic import BaseModel, Field

from app.core.models import AgentAction, ActionType, RiskLevel
from app.detection.rules import (
    CredentialTheftRule,
    DestructiveActionRule,
    PrivilegeEscalationRule,
    PromptInjectionRule,
    PackageAttackRule,
    DataExfiltrationRule,
)


class SequenceThreat(BaseModel):
    """A detected multi-step behavioral attack sequence."""
    threat_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern_id: str
    name: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    evidence_chain: List[AgentAction]
    step_descriptions: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActionNode:
    """Graph node representing an agent action with semantic behavioral tags."""
    def __init__(self, action: AgentAction, tags: Set[str]):
        self.id = action.id
        self.action = action
        self.tags = tags
        self.timestamp = action.timestamp


class TransitionEdge:
    """Directed edge representing temporal and causal flow between actions."""
    def __init__(self, source_id: str, target_id: str, relation: str):
        self.source_id = source_id
        self.target_id = target_id
        self.relation = relation


class SessionBehaviorGraph:
    """Maintains an in-memory directed graph of actions and transitions for a single session."""

    def __init__(self, session_id: str, window_size: int = 20):
        self.session_id = session_id
        self.window_size = window_size
        self.nodes: List[ActionNode] = []
        self.edges: List[TransitionEdge] = []

    def add_node(self, action: AgentAction, tags: Set[str]) -> ActionNode:
        node = ActionNode(action, tags)
        if self.nodes:
            prev_node = self.nodes[-1]
            self.edges.append(TransitionEdge(prev_node.id, node.id, "TEMPORAL_SEQUENCE"))
        self.nodes.append(node)
        
        # Enforce sliding window
        if len(self.nodes) > self.window_size:
            excess = len(self.nodes) - self.window_size
            removed_ids = {n.id for n in self.nodes[:excess]}
            self.nodes = self.nodes[excess:]
            self.edges = [e for e in self.edges if e.source_id not in removed_ids and e.target_id not in removed_ids]
        
        return node

    def get_actions(self) -> List[AgentAction]:
        return [n.action for n in self.nodes]


class BehavioralSequenceEngine:
    """
    Sliding window & behavioral graph correlation engine for multi-step attack chains.
    """

    def __init__(self, window_size: int = 20, max_time_window_seconds: float = 3600.0):
        self.window_size = window_size
        self.max_time_window_seconds = max_time_window_seconds
        self.sessions: Dict[str, SessionBehaviorGraph] = {}
        
        # Rule helpers for semantic tagging
        self.cred_rule = CredentialTheftRule()
        self.destruct_rule = DestructiveActionRule()
        self.priv_rule = PrivilegeEscalationRule()
        self.inj_rule = PromptInjectionRule()
        self.pkg_rule = PackageAttackRule()
        self.exfil_rule = DataExfiltrationRule()

    def _tag_action(self, action: AgentAction) -> Set[str]:
        """Categorize an action with behavioral capability tags."""
        tags: Set[str] = set()
        target = action.target.strip()
        params = action.parameters or {}

        # 1. Credential access
        if self.cred_rule.evaluate(action):
            tags.add("CREDENTIAL_ACCESS")

        # 2. Network egress
        if action.action == ActionType.NETWORK_REQUEST:
            tags.add("NETWORK_EGRESS")
        elif action.action == ActionType.RUN_COMMAND:
            if re.search(r"(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat)\b", target):
                tags.add("NETWORK_EGRESS")

        # 3. Prompt injection
        if self.inj_rule.evaluate(action):
            tags.add("PROMPT_INJECTION")

        # 4. Privilege escalation
        if self.priv_rule.evaluate(action):
            tags.add("PRIVILEGE_ESCALATION")

        # 5. Destructive action
        if self.destruct_rule.evaluate(action):
            tags.add("DESTRUCTIVE_ACTION")

        # 6. Discovery / Reconnaissance
        if action.action == ActionType.LIST_DIRECTORY:
            tags.add("DISCOVERY")
        elif action.action == ActionType.RUN_COMMAND:
            if re.search(r"(?i)\b(whoami|id|ls|dir|find|uname|hostname|ipconfig|ifconfig|net\s+user)\b", target):
                tags.add("RECONNAISSANCE")

        # 7. Package installation
        if action.action == ActionType.INSTALL_PACKAGE:
            tags.add("PACKAGE_INSTALL")
        elif action.action == ActionType.RUN_COMMAND and re.search(r"(?i)\b(pip|npm|gem|cargo)\s+install\b", target):
            tags.add("PACKAGE_INSTALL")
        if self.pkg_rule.evaluate(action):
            tags.add("SUSPICIOUS_PACKAGE")

        # 8. Data Staging / Archiving
        if action.action == ActionType.RUN_COMMAND and re.search(r"(?i)\b(tar|zip|gzip|7z|rar)\b", target):
            tags.add("DATA_STAGING")
        elif action.action == ActionType.WRITE_FILE and any(p in target.lower() for p in ["/tmp/", "\\temp\\", "staging", "dump"]):
            tags.add("DATA_STAGING")

        return tags

    def process_action(self, action: AgentAction) -> List[SequenceThreat]:
        """
        Ingest a new action into the session graph and evaluate active multi-step attack patterns.
        
        Args:
            action: Newly proposed AgentAction.
            
        Returns:
            List of detected SequenceThreat instances.
        """
        session_id = action.session_id
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionBehaviorGraph(session_id, self.window_size)
        
        graph = self.sessions[session_id]
        tags = self._tag_action(action)
        graph.add_node(action, tags)

        return self._detect_patterns(graph.nodes)

    def analyze_history(self, history: List[AgentAction]) -> List[SequenceThreat]:
        """
        Analyze a complete list of historical actions independently of session state.
        
        Args:
            history: List of AgentActions in chronological order.
            
        Returns:
            List of detected SequenceThreat instances.
        """
        nodes: List[ActionNode] = []
        # Slice to sliding window
        window = history[-self.window_size:] if len(history) > self.window_size else history
        for act in window:
            tags = self._tag_action(act)
            nodes.append(ActionNode(act, tags))
        return self._detect_patterns(nodes)

    def _detect_patterns(self, nodes: List[ActionNode]) -> List[SequenceThreat]:
        """Core pattern matching across tagged action sequence nodes."""
        threats: List[SequenceThreat] = []
        if len(nodes) < 2:
            return threats

        current_node = nodes[-1]
        prior_nodes = nodes[:-1]

        # -------------------------------------------------------------------
        # Pattern 1: Credential Access -> Outbound Exfiltration Chain
        # -------------------------------------------------------------------
        if "NETWORK_EGRESS" in current_node.tags:
            for prior in reversed(prior_nodes):
                if "CREDENTIAL_ACCESS" in prior.tags:
                    threats.append(
                        SequenceThreat(
                            pattern_id="CHAIN_CREDENTIAL_EXFILTRATION",
                            name="Credential Exfiltration Sequence",
                            risk_score=95,
                            risk_level=RiskLevel.CRITICAL,
                            confidence=0.95,
                            description=(
                                f"Multi-step attack chain detected: Credential access targeting '{prior.action.target}' "
                                f"followed by outbound network egress to '{current_node.action.target}'."
                            ),
                            evidence_chain=[prior.action, current_node.action],
                            step_descriptions=[
                                f"Step 1: Access sensitive credential resource '{prior.action.target}'",
                                f"Step 2: Initiate outbound network transmission to '{current_node.action.target}'",
                            ],
                            mitre_tactics=["Credential Access (TA0006)", "Exfiltration (TA0010)"],
                        )
                    )
                    break

        # -------------------------------------------------------------------
        # Pattern 2: Prompt Injection -> Weaponized Malicious Execution Chain
        # -------------------------------------------------------------------
        dangerous_tags = {"CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION", "DESTRUCTIVE_ACTION", "NETWORK_EGRESS", "SUSPICIOUS_PACKAGE"}
        if current_node.tags.intersection(dangerous_tags):
            for prior in reversed(prior_nodes):
                if "PROMPT_INJECTION" in prior.tags:
                    threats.append(
                        SequenceThreat(
                            pattern_id="CHAIN_INJECTION_TO_EXECUTION",
                            name="Prompt Injection Exploitation Sequence",
                            risk_score=95,
                            risk_level=RiskLevel.CRITICAL,
                            confidence=0.92,
                            description=(
                                f"Prompt injection instruction followed by unauthorized weaponized action: "
                                f"{current_node.action.action.value} targeting '{current_node.action.target}'."
                            ),
                            evidence_chain=[prior.action, current_node.action],
                            step_descriptions=[
                                f"Step 1: Ingest prompt injection payload '{prior.action.target}'",
                                f"Step 2: Execute high-risk action '{current_node.action.target}'",
                            ],
                            mitre_tactics=["Initial Access (TA0001)", "Execution (TA0002)"],
                        )
                    )
                    break

        # -------------------------------------------------------------------
        # Pattern 3: Discovery -> Destructive Mass Wipe Chain
        # -------------------------------------------------------------------
        if "DESTRUCTIVE_ACTION" in current_node.tags:
            for prior in reversed(prior_nodes):
                if "DISCOVERY" in prior.tags or "RECONNAISSANCE" in prior.tags:
                    threats.append(
                        SequenceThreat(
                            pattern_id="CHAIN_DISCOVERY_TO_DESTRUCTION",
                            name="Discovery to Destructive Wipe Sequence",
                            risk_score=95,
                            risk_level=RiskLevel.CRITICAL,
                            confidence=0.90,
                            description=(
                                f"System discovery followed by destructive filesystem command: "
                                f"'{current_node.action.target}' after inspecting '{prior.action.target}'."
                            ),
                            evidence_chain=[prior.action, current_node.action],
                            step_descriptions=[
                                f"Step 1: Discover filesystem layout via '{prior.action.target}'",
                                f"Step 2: Execute destructive deletion/wipe '{current_node.action.target}'",
                            ],
                            mitre_tactics=["Discovery (TA0007)", "Impact (TA0040)"],
                        )
                    )
                    break

        # -------------------------------------------------------------------
        # Pattern 4: Reconnaissance -> Privilege Escalation Chain
        # -------------------------------------------------------------------
        if "PRIVILEGE_ESCALATION" in current_node.tags:
            for prior in reversed(prior_nodes):
                if "RECONNAISSANCE" in prior.tags:
                    threats.append(
                        SequenceThreat(
                            pattern_id="CHAIN_RECON_TO_PRIVILEGE_ESCALATION",
                            name="Reconnaissance to Privilege Escalation Sequence",
                            risk_score=85,
                            risk_level=RiskLevel.CRITICAL,
                            confidence=0.88,
                            description=(
                                f"Identity/reconnaissance command '{prior.action.target}' followed by "
                                f"privilege elevation command '{current_node.action.target}'."
                            ),
                            evidence_chain=[prior.action, current_node.action],
                            step_descriptions=[
                                f"Step 1: Reconnaissance '{prior.action.target}'",
                                f"Step 2: Elevate privileges '{current_node.action.target}'",
                            ],
                            mitre_tactics=["Discovery (TA0007)", "Privilege Escalation (TA0004)"],
                        )
                    )
                    break

        # -------------------------------------------------------------------
        # Pattern 5: Malicious Package -> Execution / Outbound Egress Chain
        # -------------------------------------------------------------------
        if current_node.tags.intersection({"NETWORK_EGRESS", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION"}):
            for prior in reversed(prior_nodes):
                if "PACKAGE_INSTALL" in prior.tags and ("SUSPICIOUS_PACKAGE" in prior.tags or "PACKAGE_INSTALL" in prior.tags):
                    threats.append(
                        SequenceThreat(
                            pattern_id="CHAIN_PACKAGE_SUPPLY_CHAIN_ATTACK",
                            name="Supply Chain Package Attack Sequence",
                            risk_score=85,
                            risk_level=RiskLevel.HIGH,
                            confidence=0.85,
                            description=(
                                f"Package installation '{prior.action.target}' followed by subsequent "
                                f"sensitive action '{current_node.action.target}'."
                            ),
                            evidence_chain=[prior.action, current_node.action],
                            step_descriptions=[
                                f"Step 1: Install package '{prior.action.target}'",
                                f"Step 2: Trigger action '{current_node.action.target}'",
                            ],
                            mitre_tactics=["Initial Access (TA0001)", "Execution (TA0002)"],
                        )
                    )
                    break

        # -------------------------------------------------------------------
        # Pattern 6: Data Staging -> Exfiltration Chain
        # -------------------------------------------------------------------
        if "NETWORK_EGRESS" in current_node.tags:
            for prior in reversed(prior_nodes):
                if "DATA_STAGING" in prior.tags:
                    threats.append(
                        SequenceThreat(
                            pattern_id="CHAIN_DATA_STAGING_EXFILTRATION",
                            name="Data Staging to Exfiltration Sequence",
                            risk_score=85,
                            risk_level=RiskLevel.HIGH,
                            confidence=0.85,
                            description=(
                                f"Data staging/archive operation '{prior.action.target}' followed by "
                                f"outbound transmission '{current_node.action.target}'."
                            ),
                            evidence_chain=[prior.action, current_node.action],
                            step_descriptions=[
                                f"Step 1: Stage/compress data via '{prior.action.target}'",
                                f"Step 2: Exfiltrate staged data via '{current_node.action.target}'",
                            ],
                            mitre_tactics=["Collection (TA0009)", "Exfiltration (TA0010)"],
                        )
                    )
                    break

        return threats

    def reset_session(self, session_id: str) -> None:
        """Clear graph state for a specific session."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def reset_all(self) -> None:
        """Clear all active session states."""
        self.sessions.clear()
