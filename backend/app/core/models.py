"""
AgentGuard Pydantic Domain Models

These are the data structures that flow through the security pipeline.
Separate from SQLAlchemy ORM models (app/database/models.py).

Flow:
    AgentAction -> SecurityMiddleware -> SecurityDecision -> AuditEntry
"""
from pydantic import BaseModel, Field, field_validator
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
import uuid


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    """All tool actions an agent can request."""
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    DELETE_FILE = "delete_file"
    RUN_COMMAND = "run_command"
    NETWORK_REQUEST = "network_request"
    INSTALL_PACKAGE = "install_package"
    LIST_DIRECTORY = "list_directory"


class Decision(str, Enum):
    """Possible outcomes from AgentGuard's security evaluation."""
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"   # Human review recommended; action may be paused
    BLOCK = "BLOCK"     # Action refused entirely


class RiskLevel(str, Enum):
    """Categorical risk levels derived from numeric risk score."""
    LOW = "LOW"         # 0-39
    MEDIUM = "MEDIUM"   # 40-59
    HIGH = "HIGH"       # 60-79
    CRITICAL = "CRITICAL"  # 80-100


# ---------------------------------------------------------------------------
# Domain Models
# ---------------------------------------------------------------------------

class AgentAction(BaseModel):
    """
    An action proposed by an agent, BEFORE security evaluation.
    
    This is the input to the AgentGuard security pipeline.
    The action has NOT been executed when this model is created.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = Field(..., description="Unique identifier for the agent")
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Groups related actions into a session",
    )
    action: ActionType
    target: str = Field(..., description="The resource the action targets")
    parameters: dict = Field(default_factory=dict)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("agent_id")
    @classmethod
    def agent_id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("agent_id must not be empty")
        return v.strip()

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target must not be empty")
        return v.strip()


class RiskFactor(BaseModel):
    """A single scored factor contributing to the overall risk score."""
    name: str
    score: int = Field(ge=0, le=100)
    description: str


class SecurityDecision(BaseModel):
    """
    The result of AgentGuard evaluating an AgentAction.
    
    This is the OUTPUT of the security pipeline.
    It includes the decision, risk score, reasons, and audit hashes.
    """
    action: AgentAction
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    event_hash: str
    previous_event_hash: Optional[str] = None
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    llm_explanation: Optional[str] = None  # Populated only if LLM is configured

    @classmethod
    def risk_score_to_level(cls, score: int) -> RiskLevel:
        """Convert numeric risk score to categorical risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW


class AuditEntry(BaseModel):
    """
    An audit trail record.
    Mirrors AuditRecord ORM model but as a Pydantic model for API responses.
    """
    id: str
    event_id: str
    agent_id: str
    action: str
    target: str
    risk_score: Optional[int]
    decision: Decision
    reasons: list[str]
    timestamp: datetime
    event_hash: str
    previous_event_hash: Optional[str]
    chain_valid: bool
