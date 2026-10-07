"""
AgentGuard Context Engine

Builds rich contextual awareness for agent actions across sessions.
Tracks session history, frequency of actions, error rates, sensitive resources
touched, and external destination endpoints to detect contextual risk factors.
"""
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Any
import re
from pydantic import BaseModel, Field

from app.core.models import AgentAction, ActionType


class ResourceSensitivity(str, Enum):
    """Classification of target resource sensitivity."""
    CREDENTIAL = "CREDENTIAL"
    CONFIG = "CONFIG"
    SOURCE_CODE = "SOURCE_CODE"
    SYSTEM = "SYSTEM"
    EXTERNAL_NETWORK = "EXTERNAL_NETWORK"
    INTERNAL_NETWORK = "INTERNAL_NETWORK"
    NORMAL = "NORMAL"
    NONE = "NONE"


# ---------------------------------------------------------------------------
# Sensitivity Classification Patterns
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = [
    r"(?i)\.env(\..+)?$",
    r"(?i)id_rsa(\.pub)?$",
    r"(?i)id_ecdsa(\.pub)?$",
    r"(?i)id_ed25519(\.pub)?$",
    r"(?i)\.ssh(/|\\).+",
    r"(?i).*credential.*",
    r"(?i).*secret.*",
    r"(?i).*token.*",
    r"(?i).*password.*",
    r"(?i).*\.pem$",
    r"(?i).*\.key$",
    r"(?i).*\.p12$",
    r"(?i).*\.pfx$",
    r"(?i)\.aws(/|\\)(credentials|config)",
    r"(?i)\.netrc$",
    r"(?i)kubeconfig",
    r"(?i).*api[-_]?key.*",
    r"(?i).*auth[-_]?token.*",
]

SYSTEM_PATTERNS = [
    r"(?i)^/etc/(passwd|shadow|sudoers|pam\.d|security).*",
    r"^/(proc|sys|dev)(/.*)?$",
    r"(?i)^[a-z]:\\windows\\system32.*",
    r"(?i)^[a-z]:\\windows.*",
    r"(?i)^/(bin|sbin|usr/bin|usr/sbin)/.*",
    r"(?i)(reg\.exe|regedit|systemctl|service|journalctl)",
    r"(?i)(rm\s+-rf|mkfs|dd\s+if=|shutdown|reboot|init\s+0)",
    r"(?i)(sudo\b|chmod\s+777|chown\s+root)",
]

CONFIG_PATTERNS = [
    r"(?i).*\.(ya?ml|toml|ini|conf|cfg)$",
    r"(?i)nginx\.conf$",
    r"(?i)settings\.py$",
    r"(?i)config\.py$",
    r"(?i)\.(bashrc|zshrc|profile|bash_profile)$",
    r"(?i)Dockerfile$",
    r"(?i)docker-compose\.(ya?ml)$",
    r"(?i)\.git(/|\\)config$",
]

SOURCE_CODE_PATTERNS = [
    r"(?i).*\.(py|js|ts|jsx|tsx|cpp|c|h|hpp|go|rs|java|rb|php|sh|sql|html|css|vue|svelte)$",
    r"(?i)^(src|app|backend|frontend|lib|pkg|tests|components)(/|\\).*",
]

PRIVATE_IP_REGEX = re.compile(
    r"^(https?://)?(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?(/.*)?$"
)

URL_REGEX = re.compile(r"^(https?://|ftp://|wss?://)", re.IGNORECASE)


def identify_resource_sensitivity(
    target: str,
    action: Optional[ActionType] = None,
    parameters: Optional[dict] = None,
) -> ResourceSensitivity:
    """
    Classify the target resource into a ResourceSensitivity level.
    Analyzes target path, command strings, URLs, and action parameters.
    """
    if not target or not target.strip():
        return ResourceSensitivity.NONE

    target_clean = target.strip()

    # Network action inspection
    if action == ActionType.NETWORK_REQUEST or URL_REGEX.match(target_clean):
        if PRIVATE_IP_REGEX.match(target_clean):
            return ResourceSensitivity.INTERNAL_NETWORK
        return ResourceSensitivity.EXTERNAL_NETWORK

    # Check for parameters containing commands or urls
    command_text = target_clean
    if parameters and isinstance(parameters, dict):
        if "command" in parameters and isinstance(parameters["command"], str):
            command_text = f"{target_clean} {parameters['command']}"
        if "url" in parameters and isinstance(parameters["url"], str):
            if not PRIVATE_IP_REGEX.match(parameters["url"]):
                return ResourceSensitivity.EXTERNAL_NETWORK

    # Check credentials
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, target_clean) or re.search(pattern, command_text):
            return ResourceSensitivity.CREDENTIAL

    # Check system resources / destructive commands
    for pattern in SYSTEM_PATTERNS:
        if re.search(pattern, target_clean) or re.search(pattern, command_text):
            return ResourceSensitivity.SYSTEM

    # Check config
    for pattern in CONFIG_PATTERNS:
        if re.search(pattern, target_clean):
            return ResourceSensitivity.CONFIG

    # Check source code
    for pattern in SOURCE_CODE_PATTERNS:
        if re.search(pattern, target_clean):
            return ResourceSensitivity.SOURCE_CODE

    # Check directory listing or file action with non-sensitive paths
    if action in (ActionType.READ_FILE, ActionType.WRITE_FILE, ActionType.DELETE_FILE, ActionType.LIST_DIRECTORY):
        return ResourceSensitivity.NORMAL

    return ResourceSensitivity.NORMAL


# ---------------------------------------------------------------------------
# Profile and Context Models
# ---------------------------------------------------------------------------

class AgentProfile(BaseModel):
    """Profile defining expected behavior and authorization boundaries for an agent."""
    agent_id: str
    name: str = ""
    role: str = "assistant"
    allowed_actions: list[ActionType] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    max_actions_per_minute: int = 30
    trust_level: str = "standard"  # e.g., low, standard, trusted
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionContext(BaseModel):
    """
    Rich context of an agent's current state and historical behavior in the session.
    """
    session_id: str
    agent_id: str
    history: list[AgentAction] = Field(default_factory=list)
    previous_actions: list[ActionType] = Field(default_factory=list)
    total_actions_in_session: int = 0
    actions_in_last_minute: int = 0
    action_frequency: float = 0.0  # actions per minute
    sensitive_resources_touched: list[str] = Field(default_factory=list)
    sensitive_resource_count: int = 0
    error_counts: int = 0
    recent_errors: list[str] = Field(default_factory=list)
    destination_endpoints: list[str] = Field(default_factory=list)
    target_sensitivity: ResourceSensitivity = ResourceSensitivity.NORMAL
    agent_profile: Optional[AgentProfile] = None

    def has_touched_credentials(self) -> bool:
        """Check if any credential resources have been touched in this session."""
        for res in self.sensitive_resources_touched:
            if identify_resource_sensitivity(res) == ResourceSensitivity.CREDENTIAL:
                return True
        return False

    def has_touched_sensitive_resources(self) -> bool:
        """Check if any sensitive resources (credential, system, config) were touched."""
        return len(self.sensitive_resources_touched) > 0

    def is_high_frequency(self, threshold: int = 30) -> bool:
        """Check if action frequency exceeds the threshold."""
        return self.actions_in_last_minute > threshold

    def has_external_network(self) -> bool:
        """Check if session has initiated any external network calls."""
        return len(self.destination_endpoints) > 0


# ---------------------------------------------------------------------------
# Context Builder
# ---------------------------------------------------------------------------

class ContextBuilder:
    """
    Assembles `ActionContext` from in-memory session history and agent profiles.
    Tracks session state, recent actions, rates, and historical errors.
    """

    def __init__(self) -> None:
        # session_id -> list of AgentAction
        self._sessions: dict[str, list[AgentAction]] = {}
        # session_id -> list of error message strings
        self._session_errors: dict[str, list[str]] = {}
        # agent_id -> AgentProfile
        self._profiles: dict[str, AgentProfile] = {}

    def register_profile(self, profile: AgentProfile) -> None:
        """Register or update an agent profile."""
        self._profiles[profile.agent_id] = profile

    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Retrieve the profile for an agent ID."""
        return self._profiles.get(agent_id)

    def record_action(
        self,
        action: AgentAction,
        is_error: bool = False,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Record an action in session history.
        Optionally records if the action resulted in an execution error.
        """
        if action.session_id not in self._sessions:
            self._sessions[action.session_id] = []
            self._session_errors[action.session_id] = []

        self._sessions[action.session_id].append(action)

        if is_error:
            msg = error_message or f"Error executing {action.action.value} on {action.target}"
            self._session_errors[action.session_id].append(msg)

    def record_error(self, session_id: str, error_message: str) -> None:
        """Record an error event in the session."""
        if session_id not in self._session_errors:
            self._session_errors[session_id] = []
        self._session_errors[session_id].append(error_message)

    def build_context(self, action: AgentAction) -> ActionContext:
        """
        Build an `ActionContext` for the given action using historical session records.
        """
        session_id = action.session_id
        agent_id = action.agent_id

        history = self._sessions.get(session_id, [])
        errors = self._session_errors.get(session_id, [])
        profile = self._profiles.get(agent_id)

        # Classify current target
        target_sensitivity = identify_resource_sensitivity(
            target=action.target,
            action=action.action,
            parameters=action.parameters,
        )

        # Historical metrics
        previous_actions: list[ActionType] = [a.action for a in history]
        total_actions = len(history)

        # Actions in the last 60 seconds relative to action timestamp
        now = action.timestamp if action.timestamp else datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(seconds=60)
        recent_actions = [
            a for a in history
            if a.timestamp and a.timestamp >= one_minute_ago
        ]
        actions_in_last_minute = len(recent_actions)
        action_frequency = float(actions_in_last_minute)

        # Sensitive resources touched across the session
        sensitive_touched: list[str] = []
        destination_endpoints: list[str] = []

        for h in history:
            h_sens = identify_resource_sensitivity(h.target, h.action, h.parameters)
            if h_sens in (
                ResourceSensitivity.CREDENTIAL,
                ResourceSensitivity.CONFIG,
                ResourceSensitivity.SYSTEM,
            ):
                if h.target not in sensitive_touched:
                    sensitive_touched.append(h.target)

            if h.action == ActionType.NETWORK_REQUEST or h_sens == ResourceSensitivity.EXTERNAL_NETWORK:
                if h.target not in destination_endpoints:
                    destination_endpoints.append(h.target)

        return ActionContext(
            session_id=session_id,
            agent_id=agent_id,
            history=list(history),
            previous_actions=previous_actions,
            total_actions_in_session=total_actions,
            actions_in_last_minute=actions_in_last_minute,
            action_frequency=action_frequency,
            sensitive_resources_touched=sensitive_touched,
            sensitive_resource_count=len(sensitive_touched),
            error_counts=len(errors),
            recent_errors=list(errors),
            destination_endpoints=destination_endpoints,
            target_sensitivity=target_sensitivity,
            agent_profile=profile,
        )

    def get_session_history(self, session_id: str) -> list[AgentAction]:
        """Return full action history for a session."""
        return list(self._sessions.get(session_id, []))

    def clear_session(self, session_id: str) -> None:
        """Clear history and errors for a specific session."""
        self._sessions.pop(session_id, None)
        self._session_errors.pop(session_id, None)

    def reset(self) -> None:
        """Reset all in-memory sessions and errors."""
        self._sessions = {}
        self._session_errors = {}
        self._profiles = {}


_context_builder_instance: Optional[ContextBuilder] = None


def get_context_builder() -> ContextBuilder:
    """Return singleton ContextBuilder instance."""
    global _context_builder_instance
    if _context_builder_instance is None:
        _context_builder_instance = ContextBuilder()
    return _context_builder_instance
