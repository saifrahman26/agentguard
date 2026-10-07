"""
AgentGuard Detection Package
"""
from app.detection.rules import (
    DetectionRule,
    RuleMatch,
    RuleEngine,
    CredentialTheftRule,
    DataExfiltrationRule,
    DestructiveActionRule,
    PrivilegeEscalationRule,
    PromptInjectionRule,
    PackageAttackRule,
    get_default_rules,
)

__all__ = [
    "DetectionRule",
    "RuleMatch",
    "RuleEngine",
    "CredentialTheftRule",
    "DataExfiltrationRule",
    "DestructiveActionRule",
    "PrivilegeEscalationRule",
    "PromptInjectionRule",
    "PackageAttackRule",
    "get_default_rules",
]
