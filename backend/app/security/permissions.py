"""
AgentGuard Permissions System

Manages per-agent permission levels and granular access control.
Enforces baseline capability bounds (read, write, network, shell, delete)
prior to granular policy rule evaluation.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union
from pydantic import BaseModel, Field

from app.core.models import ActionType


class PermissionLevel(str, Enum):
    """Standard permission tiers for agents."""
    LOW = "LOW"         # Read-only, no network, no shell, no delete
    MEDIUM = "MEDIUM"   # Read, write, network permitted; no shell, no delete
    HIGH = "HIGH"       # Full capabilities: read, write, network, shell, delete


class PermissionSet(BaseModel):
    """
    Granular permissions configured for an agent.
    Controls whether broad categories of actions are authorized.
    """
    read_allowed: bool = Field(default=True, description="Allow reading files and directory listing")
    write_allowed: bool = Field(default=False, description="Allow creating and modifying files")
    network_allowed: bool = Field(default=False, description="Allow outbound network connections")
    shell_allowed: bool = Field(default=False, description="Allow execution of shell commands")
    delete_allowed: bool = Field(default=False, description="Allow deleting files and directories")
    level: Optional[PermissionLevel] = Field(default=None, description="Optional associated permission level tier")

    @classmethod
    def for_level(cls, level: Union[PermissionLevel, str]) -> PermissionSet:
        """Create a standard PermissionSet configuration for a given level tier."""
        if isinstance(level, str):
            try:
                level = PermissionLevel(level.upper())
            except ValueError:
                raise ValueError(f"Unknown permission level: {level}. Valid levels: {[e.value for e in PermissionLevel]}")

        if level == PermissionLevel.LOW:
            return cls(
                read_allowed=True,
                write_allowed=False,
                network_allowed=False,
                shell_allowed=False,
                delete_allowed=False,
                level=PermissionLevel.LOW,
            )
        elif level == PermissionLevel.MEDIUM:
            return cls(
                read_allowed=True,
                write_allowed=True,
                network_allowed=True,
                shell_allowed=False,
                delete_allowed=False,
                level=PermissionLevel.MEDIUM,
            )
        elif level == PermissionLevel.HIGH:
            return cls(
                read_allowed=True,
                write_allowed=True,
                network_allowed=True,
                shell_allowed=True,
                delete_allowed=True,
                level=PermissionLevel.HIGH,
            )
        else:
            raise ValueError(f"Unsupported permission level: {level}")

    def is_action_allowed(self, action: Union[ActionType, str]) -> bool:
        """
        Check if a given action type is permitted by this permission set.
        """
        action_val = action.value if isinstance(action, ActionType) else str(action).lower().strip()

        if action_val in (ActionType.READ_FILE.value, ActionType.LIST_DIRECTORY.value, "read", "read_file", "list_directory"):
            return self.read_allowed
        elif action_val in (ActionType.WRITE_FILE.value, "write", "write_file", "create_file", "edit_file"):
            return self.write_allowed
        elif action_val in (ActionType.DELETE_FILE.value, "delete", "delete_file", "remove_file"):
            return self.delete_allowed
        elif action_val in (ActionType.RUN_COMMAND.value, "shell", "run_command", "exec", "execute"):
            return self.shell_allowed
        elif action_val in (ActionType.NETWORK_REQUEST.value, "network", "network_request", "http", "fetch"):
            return self.network_allowed
        elif action_val in (ActionType.INSTALL_PACKAGE.value, "install_package", "package_install"):
            # Package installation requires shell/write capability
            return self.shell_allowed and self.write_allowed
        else:
            # Unknown actions default to denied for security
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert permission set to dictionary representation."""
        return {
            "read_allowed": self.read_allowed,
            "write_allowed": self.write_allowed,
            "network_allowed": self.network_allowed,
            "shell_allowed": self.shell_allowed,
            "delete_allowed": self.delete_allowed,
            "level": self.level.value if self.level else None,
        }


class AgentPermissionManager:
    """
    Manages and enforces permissions for individual agents.
    Tracks assigned permission sets per agent_id and falls back to default level.
    """

    def __init__(self, default_level: Union[PermissionLevel, str] = PermissionLevel.LOW) -> None:
        if isinstance(default_level, str):
            default_level = PermissionLevel(default_level.upper())
        self.default_level: PermissionLevel = default_level
        self._agent_permissions: Dict[str, PermissionSet] = {}

    def set_permissions(self, agent_id: str, permissions: PermissionSet) -> None:
        """Assign an explicit PermissionSet to an agent."""
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")
        self._agent_permissions[agent_id.strip()] = permissions

    def set_agent_level(self, agent_id: str, level: Union[PermissionLevel, str]) -> PermissionSet:
        """Assign a standard permission tier to an agent."""
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")
        perm_set = PermissionSet.for_level(level)
        self._agent_permissions[agent_id.strip()] = perm_set
        return perm_set

    def get_permissions(self, agent_id: str) -> PermissionSet:
        """
        Get the active PermissionSet for an agent.
        If not explicitly set, returns the default level's PermissionSet.
        """
        clean_id = agent_id.strip() if agent_id else ""
        if clean_id in self._agent_permissions:
            return self._agent_permissions[clean_id]
        return PermissionSet.for_level(self.default_level)

    def is_action_permitted(self, agent_id: str, action: Union[ActionType, str]) -> bool:
        """Check if an agent is permitted to execute an action."""
        perms = self.get_permissions(agent_id)
        return perms.is_action_allowed(action)

    def check_permission(self, agent_id: str, action: Union[ActionType, str]) -> Tuple[bool, str]:
        """
        Evaluate permission for an agent action and return structured status and reason.
        """
        action_name = action.value if isinstance(action, ActionType) else str(action)
        perms = self.get_permissions(agent_id)
        allowed = perms.is_action_allowed(action)
        
        if allowed:
            return True, f"Action '{action_name}' is permitted for agent '{agent_id}' under {perms.level or 'CUSTOM'} permissions."
        else:
            return False, f"Permission denied: Agent '{agent_id}' is not authorized to perform '{action_name}'."

    def revoke_permissions(self, agent_id: str) -> bool:
        """Remove custom permissions for an agent, reverting to default."""
        clean_id = agent_id.strip() if agent_id else ""
        if clean_id in self._agent_permissions:
            del self._agent_permissions[clean_id]
            return True
        return False

    def list_agents(self) -> Dict[str, PermissionSet]:
        """Return a copy of all explicitly assigned agent permissions."""
        return dict(self._agent_permissions)

    def reset(self) -> None:
        """Clear all assigned agent permissions."""
        self._agent_permissions.clear()


# Alias for backward compatibility / alternative naming
PermissionManager = AgentPermissionManager

# Singleton instance
_permission_manager_instance: Optional[AgentPermissionManager] = None


def get_permission_manager() -> AgentPermissionManager:
    """Return the global singleton PermissionManager instance."""
    global _permission_manager_instance
    if _permission_manager_instance is None:
        _permission_manager_instance = AgentPermissionManager()
    return _permission_manager_instance
