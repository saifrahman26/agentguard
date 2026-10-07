"""
AgentGuard Agent Simulator

Simulates autonomous AI agents attempting tool actions.
Crucial Security Invariant:
    The agent NEVER directly executes a tool.
    Every proposed action MUST pass through the security interceptor first.
    Only if the decision is ALLOW will the tool execute in the virtual sandbox.
"""
from typing import Dict, Any, List, Optional, Callable
import uuid
import time
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.core.models import (
    AgentAction,
    ActionType,
    Decision,
    RiskLevel,
    SecurityDecision,
)
from app.agent.tools import VirtualSandbox, ToolRegistry, ToolResult


class AgentExecutionResult(BaseModel):
    """The complete result of an agent proposing and executing an action."""
    action: AgentAction
    decision: SecurityDecision
    tool_result: Optional[ToolResult] = None
    executed: bool = False
    blocked: bool = False


# Type definition for security interceptor function
SecurityInterceptor = Callable[[AgentAction], SecurityDecision]


def default_pass_through_interceptor(action: AgentAction) -> SecurityDecision:
    """
    Default stub interceptor for Milestone 2 testing.
    Used before Milestone 3-6 full security pipeline is wired in.
    """
    from app.audit.integrity import hash_event

    event_data = {
        "agent_id": action.agent_id,
        "action": action.action.value,
        "target": action.target,
        "session_id": action.session_id,
        "timestamp": action.timestamp.isoformat(),
    }
    digest = hash_event(event_data)

    return SecurityDecision(
        action=action,
        decision=Decision.ALLOW,
        risk_score=0,
        risk_level=RiskLevel.LOW,
        risk_factors=[],
        reasons=["Milestone 2 default pass-through interceptor"],
        event_hash=digest,
        previous_event_hash=None,
    )


class SimulatedAgent:
    """
    Simulated autonomous AI agent.
    
    Attributes:
        agent_id: Unique identifier for the agent (e.g. 'coding-assistant-01')
        session_id: UUID for the current agent session
        sandbox: In-memory virtual environment
        tool_registry: Available tools
        interceptor: Security layer callable (SecurityMiddleware)
    """

    def __init__(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
        sandbox: Optional[VirtualSandbox] = None,
        interceptor: Optional[SecurityInterceptor] = None,
    ):
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.sandbox = sandbox or VirtualSandbox()
        self.tool_registry = ToolRegistry()
        self.interceptor: SecurityInterceptor = interceptor or default_pass_through_interceptor
        self.history: List[AgentExecutionResult] = []

    def set_interceptor(self, interceptor: SecurityInterceptor) -> None:
        """Update the security middleware interceptor."""
        self.interceptor = interceptor

    def propose_action(
        self,
        action_type: ActionType,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> AgentExecutionResult:
        """
        Core AgentGuard action flow:
          1. Construct AgentAction
          2. Send to Security Interceptor
          3. Inspect Decision:
             - ALLOW: Execute in VirtualSandbox
             - BLOCK: Abort execution, return refusal with reasons
             - REVIEW: Halt execution pending review
        """
        params = parameters or {}
        action = AgentAction(
            agent_id=self.agent_id,
            session_id=self.session_id,
            action=action_type,
            target=target,
            parameters=params,
            timestamp=datetime.now(timezone.utc),
        )

        # 1. Intercept BEFORE execution
        decision = self.interceptor(action)

        # 2. Enforce decision
        if decision.decision == Decision.ALLOW:
            tool = self.tool_registry.get_tool(action_type)
            if not tool:
                tool_res = ToolResult(
                    success=False,
                    error=f"No tool registered for action: {action_type.value}",
                )
            else:
                start_time = time.perf_counter()
                tool_res = tool.execute(self.sandbox, target, params)
                tool_res.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

            result = AgentExecutionResult(
                action=action,
                decision=decision,
                tool_result=tool_res,
                executed=tool_res.success,
                blocked=False,
            )
        elif decision.decision == Decision.BLOCK:
            reasons_summary = "; ".join(decision.reasons) or "Blocked by security policy"
            result = AgentExecutionResult(
                action=action,
                decision=decision,
                tool_result=ToolResult(
                    success=False,
                    error=f"Action blocked by AgentGuard: {reasons_summary}",
                ),
                executed=False,
                blocked=True,
            )
        else:  # REVIEW
            reasons_summary = "; ".join(decision.reasons) or "Flagged for security review"
            result = AgentExecutionResult(
                action=action,
                decision=decision,
                tool_result=ToolResult(
                    success=False,
                    error=f"Action held for human review: {reasons_summary}",
                ),
                executed=False,
                blocked=False,
            )

        self.history.append(result)
        return result

    # Convenience helper methods
    def read_file(self, path: str) -> AgentExecutionResult:
        return self.propose_action(ActionType.READ_FILE, path)

    def write_file(self, path: str, content: str) -> AgentExecutionResult:
        return self.propose_action(ActionType.WRITE_FILE, path, {"content": content})

    def delete_file(self, path: str) -> AgentExecutionResult:
        return self.propose_action(ActionType.DELETE_FILE, path)

    def run_command(self, command: str) -> AgentExecutionResult:
        return self.propose_action(ActionType.RUN_COMMAND, command)

    def network_request(self, url: str, method: str = "GET", data: Any = None) -> AgentExecutionResult:
        return self.propose_action(ActionType.NETWORK_REQUEST, url, {"method": method, "data": data})

    def install_package(self, package_name: str) -> AgentExecutionResult:
        return self.propose_action(ActionType.INSTALL_PACKAGE, package_name)

    def list_directory(self, path: str = ".") -> AgentExecutionResult:
        return self.propose_action(ActionType.LIST_DIRECTORY, path)

    def run_sequence(self, steps: List[Dict[str, Any]]) -> List[AgentExecutionResult]:
        """
        Execute a scripted sequence of actions.
        
        Each step format:
          {"action": ActionType.READ_FILE, "target": ".env", "parameters": {...}}
        """
        results = []
        for step in steps:
            action_type = step["action"]
            if isinstance(action_type, str):
                action_type = ActionType(action_type)
            target = step["target"]
            params = step.get("parameters", {})
            res = self.propose_action(action_type, target, params)
            results.append(res)
        return results
