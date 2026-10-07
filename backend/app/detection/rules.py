"""
AgentGuard Detection Rules

Deterministic rule-based threat detection for LLM agent actions.
Defines security rules to detect single-action threats including:
- Credential theft
- Data exfiltration
- Destructive actions
- Privilege escalation
- Prompt injection
- Malicious package attacks
"""
import re
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.core.models import AgentAction, ActionType, RiskLevel


class RuleMatch(BaseModel):
    """Result of a matched threat detection rule."""
    rule_id: str
    rule_name: str
    matched: bool
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    description: str
    pattern_matched: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DetectionRule(ABC):
    """Abstract base class for all deterministic security detection rules."""
    
    rule_id: str
    name: str
    description: str
    category: str
    base_score: int
    risk_level: RiskLevel

    @abstractmethod
    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        """
        Evaluate an action against this detection rule.
        
        Args:
            action: The proposed AgentAction to inspect.
            context: Optional contextual dictionary.
            
        Returns:
            RuleMatch if the action violates the rule, None otherwise.
        """
        pass


class CredentialTheftRule(DetectionRule):
    """
    Detects unauthorized attempts to access or steal sensitive credentials,
    cryptographic keys, environment files, or secret stores.
    """
    rule_id = "RULE_CREDENTIAL_THEFT"
    name = "Credential Theft Detection"
    description = "Detects access to sensitive secrets, private keys, environment files, and credentials."
    category = "Credential Access"
    base_score = 90
    risk_level = RiskLevel.CRITICAL

    # Sensitive filenames and path patterns
    SENSITIVE_TARGET_PATTERNS = [
        r"(^|[/\\])\.env(\.[a-zA-Z0-9_-]+)?$",
        r"(^|[/\\])\.ssh[/\\](id_rsa|id_ed25519|id_dsa|id_ecdsa|authorized_keys|known_hosts|config)$",
        r"(^|[/\\])id_(rsa|ed25519|dsa|ecdsa)(\.pub)?$",
        r"(^|[/\\])\.aws[/\\](credentials|config)$",
        r"\.(key|pem|crt|pfx|p12|pkcs12|kdbx)$",
        r"(^|[/\\])(/etc/shadow|/etc/master\.passwd|/etc/security/opasswd)$",
        r"(^|[/\\])(\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|kubeconfig)$",
        r"(^|[/\\])(credentials\.json|service[-_]account.*\.json|client[-_]secret.*\.json)$",
        r"(^|[/\\])(secret[s]?\.(json|ya?ml|env)|vault[-_]token)$",
    ]

    # Command line patterns attempting credential discovery or access
    CREDENTIAL_COMMAND_PATTERNS = [
        r"(?i)\b(cat|type|more|less|head|tail|get-content)\s+.*(\.env|\.ssh|id_rsa|id_ed25519|\.aws/credentials|/etc/shadow)",
        r"(?i)\b(grep|findstr|select-string)\s+.*(api[-_]?key|secret|password|auth[-_]?token|aws[-_]secret)",
        r"(?i)\b(mimikatz|vault\s+read|security\s+find-generic-password|lazagne)",
        r"(?i)\bexport\s+.*(AWS_SECRET|OPENAI_API_KEY|GITHUB_TOKEN)",
    ]

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        target = action.target.strip()
        
        # 1. Inspect target path for file actions
        for pattern in self.SENSITIVE_TARGET_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    matched=True,
                    risk_score=self.base_score,
                    risk_level=self.risk_level,
                    description=f"Sensitive credential target detected: '{target}'",
                    pattern_matched=pattern,
                    confidence=0.95,
                    metadata={"target": target, "action_type": action.action.value},
                )

        # 2. Inspect command executions
        if action.action == ActionType.RUN_COMMAND:
            cmd = target
            for pattern in self.CREDENTIAL_COMMAND_PATTERNS:
                if re.search(pattern, cmd):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=self.base_score,
                        risk_level=self.risk_level,
                        description=f"Credential theft command pattern detected: '{cmd}'",
                        pattern_matched=pattern,
                        confidence=0.95,
                        metadata={"command": cmd},
                    )

        # 3. Inspect parameters for file paths
        params = action.parameters or {}
        for param_key, param_val in params.items():
            if isinstance(param_val, str):
                for pattern in self.SENSITIVE_TARGET_PATTERNS:
                    if re.search(pattern, param_val, re.IGNORECASE):
                        return RuleMatch(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            matched=True,
                            risk_score=self.base_score,
                            risk_level=self.risk_level,
                            description=f"Sensitive credential parameter '{param_key}' detected: '{param_val}'",
                            pattern_matched=pattern,
                            confidence=0.90,
                            metadata={"parameter": param_key, "value": param_val},
                        )
        return None


class DataExfiltrationRule(DetectionRule):
    """
    Detects outbound data exfiltration attempts through network requests
    or command-line data transfer utilities.
    """
    rule_id = "RULE_DATA_EXFILTRATION"
    name = "Data Exfiltration Detection"
    description = "Detects suspicious outbound requests, tunneling endpoints, and data exfiltration utilities."
    category = "Exfiltration"
    base_score = 85
    risk_level = RiskLevel.CRITICAL

    # Suspicious / exfiltration endpoints & domains
    SUSPICIOUS_DOMAINS = [
        r"webhook\.site",
        r"requestbin\.(net|com)",
        r"ngrok(-free)?\.app",
        r"ngrok\.io",
        r"pastebin\.com",
        r"burpcollaborator\.net",
        r"oastify\.com",
        r"pipedream\.net",
        r"beeceptor\.com",
        r"transfer\.sh",
        r"file\.io",
        r"anonfiles\.com",
        r"attacker\.(com|org|net|io)",
        r"evil\.(com|org|net|io)",
    ]

    # Command line patterns attempting data exfiltration
    EXFIL_COMMAND_PATTERNS = [
        r"(?i)\bcurl\s+.*(-d\s*@|--data\s*@|-F\s*.*@|--upload-file)",
        r"(?i)\bwget\s+.*(--post-file|--post-data)",
        r"(?i)\b(invoke-webrequest|iwr|invoke-restmethod|irm)\s+.*(-infile|-body)",
        r"(?i)\b(nc|ncat|netcat)\s+.*(-e|\d+\.\d+\.\d+\.\d+)",
        r"(?i)/dev/tcp/\d+\.\d+\.\d+\.\d+",
    ]

    # Direct raw IP regex (excluding loopback / RFC 1918 private space)
    RAW_PUBLIC_IP_PATTERN = r"https?://(?!(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.))(\d{1,3}\.){3}\d{1,3}"

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        target = action.target.strip()

        # 1. Network request target inspection
        if action.action == ActionType.NETWORK_REQUEST:
            for domain_pat in self.SUSPICIOUS_DOMAINS:
                if re.search(domain_pat, target, re.IGNORECASE):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=self.base_score,
                        risk_level=self.risk_level,
                        description=f"Outbound network request to known exfiltration/tunneling domain: '{target}'",
                        pattern_matched=domain_pat,
                        confidence=0.95,
                        metadata={"endpoint": target},
                    )

            if re.search(self.RAW_PUBLIC_IP_PATTERN, target):
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    matched=True,
                    risk_score=75,
                    risk_level=RiskLevel.HIGH,
                    description=f"Outbound network request to raw public IP endpoint: '{target}'",
                    pattern_matched=self.RAW_PUBLIC_IP_PATTERN,
                    confidence=0.80,
                    metadata={"endpoint": target},
                )

        # 2. Command execution inspection
        if action.action == ActionType.RUN_COMMAND:
            cmd = target
            for domain_pat in self.SUSPICIOUS_DOMAINS:
                if re.search(domain_pat, cmd, re.IGNORECASE):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=self.base_score,
                        risk_level=self.risk_level,
                        description=f"Command sending data to known exfiltration domain: '{cmd}'",
                        pattern_matched=domain_pat,
                        confidence=0.95,
                        metadata={"command": cmd},
                    )

            for exfil_pat in self.EXFIL_COMMAND_PATTERNS:
                if re.search(exfil_pat, cmd):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=self.base_score,
                        risk_level=self.risk_level,
                        description=f"Data exfiltration command pattern detected: '{cmd}'",
                        pattern_matched=exfil_pat,
                        confidence=0.90,
                        metadata={"command": cmd},
                    )

        return None


class DestructiveActionRule(DetectionRule):
    """
    Detects destructive operations including mass file deletion, filesystem formatting,
    recursive wipes, disk partition manipulation, and destructive SQL drops.
    """
    rule_id = "RULE_DESTRUCTIVE_ACTION"
    name = "Destructive Action Detection"
    description = "Detects recursive deletions, filesystem formatting, and system-wide wipe commands."
    category = "Impact"
    base_score = 95
    risk_level = RiskLevel.CRITICAL

    # High-impact destructive commands
    DESTRUCTIVE_COMMAND_PATTERNS = [
        r"(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive)\s+([/~.]|\*|/[a-zA-Z0-9_-]+)",
        r"(?i)\b(rmdir|rd)\s+/[sq]\s+([a-zA-Z]:\\|/|\*)",
        r"(?i)\bdel\s+(/[sfq]\s+)+([a-zA-Z]:\\|\*|/\*)",
        r"(?i)\b(format\s+[a-zA-Z]:|mkfs(\.[a-z0-9]+)?\s+/dev/)",
        r"(?i)\bdd\s+if=/dev/(zero|urandom|null)\s+of=/dev/",
        r"(?i)\b(shred|wipefs|fdisk|diskpart|parted)\b",
        r"(?i)\b(drop\s+database|truncate\s+table|drop\s+table\s+users)\b",
    ]

    # Sensitive root/system paths for file deletion
    CRITICAL_SYSTEM_PATHS = [
        r"^(/|/etc|/usr|/var|/bin|/sbin|/boot|/root|/sys|/dev)($|[/\\])",
        r"^([a-zA-Z]:\\|[a-zA-Z]:/|C:\\Windows|C:\\Program Files)($|[/\\])",
    ]

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        target = action.target.strip()

        # 1. Inspect direct delete file action
        if action.action == ActionType.DELETE_FILE:
            # Check critical paths or wildcards
            if target in ("/", "/*", "*", "C:\\", "C:/", "~", ""):
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    matched=True,
                    risk_score=100,
                    risk_level=self.risk_level,
                    description=f"Attempted root/wildcard file deletion targeting '{target}'",
                    pattern_matched="root_or_wildcard_delete",
                    confidence=1.0,
                    metadata={"target": target},
                )
            for path_pat in self.CRITICAL_SYSTEM_PATHS:
                if re.search(path_pat, target, re.IGNORECASE):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=95,
                        risk_level=self.risk_level,
                        description=f"Attempted deletion of critical system path: '{target}'",
                        pattern_matched=path_pat,
                        confidence=0.95,
                        metadata={"target": target},
                    )

        # 2. Inspect command execution
        if action.action == ActionType.RUN_COMMAND:
            cmd = target
            for cmd_pat in self.DESTRUCTIVE_COMMAND_PATTERNS:
                if re.search(cmd_pat, cmd):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=self.base_score,
                        risk_level=self.risk_level,
                        description=f"Destructive wipe/format command detected: '{cmd}'",
                        pattern_matched=cmd_pat,
                        confidence=0.95,
                        metadata={"command": cmd},
                    )

        return None


class PrivilegeEscalationRule(DetectionRule):
    """
    Detects unauthorized privilege escalation, sudo abuse, setuid manipulation,
    and user rights elevation attempts.
    """
    rule_id = "RULE_PRIVILEGE_ESCALATION"
    name = "Privilege Escalation Detection"
    description = "Detects sudo execution, setuid permission alterations, and administrative elevation."
    category = "Privilege Escalation"
    base_score = 85
    risk_level = RiskLevel.CRITICAL

    PRIV_ESC_COMMAND_PATTERNS = [
        r"(?i)\b(sudo\s+(-[a-zA-Z]+\s+)?|su\s+-\s*|su\s+root\b|pkexec|doas\b)",
        r"(?i)\bchmod\s+([0-7]*[4-7][0-7]{3}|\+s|u\+s|g\+s|777)\b",
        r"(?i)\b(chown|chgrp)\s+.*root\b",
        r"(?i)\b(usermod|useradd|gpasswd)\s+.*(sudo|wheel|admin|root)",
        r"(?i)\b(visudo|setcap)\b",
        r"(?i)\brunas\s+/user:(administrator|root)",
        r"(?i)\bnet\s+localgroup\s+administrators\s+.*(/add|\+)",
        r"(?i)\bpowershell.*-verb\s+runas\b",
        r"(?i)\bwhoami\s+/priv\b",
    ]

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        if action.action == ActionType.RUN_COMMAND:
            cmd = action.target.strip()
            for priv_pat in self.PRIV_ESC_COMMAND_PATTERNS:
                if re.search(priv_pat, cmd):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=self.base_score,
                        risk_level=self.risk_level,
                        description=f"Privilege escalation attempt detected in command: '{cmd}'",
                        pattern_matched=priv_pat,
                        confidence=0.90,
                        metadata={"command": cmd},
                    )
        return None


class PromptInjectionRule(DetectionRule):
    """
    Detects prompt injection payloads and adversarial directives embedded
    in file content, tool parameters, or agent commands.
    """
    rule_id = "RULE_PROMPT_INJECTION"
    name = "Prompt Injection Detection"
    description = "Detects adversarial prompt override phrases, jailbreaks, and token exfiltration directives."
    category = "Adversarial Robustness"
    base_score = 90
    risk_level = RiskLevel.CRITICAL

    INJECTION_PATTERNS = [
        r"(?i)\b(ignore|disregard|forget)\s+((all|any)\s+)?((previous|prior|above|other)\s+)?(instructions|prompts|rules|commands|directives)",
        r"(?i)\b(system\s+override|admin\s+override|developer\s+mode\s+enabled)",
        r"(?i)\b(upload\s+tokens|exfiltrate\s+tokens|steal\s+api_key|send\s+api\s*key|leak\s+secrets)",
        r"(?i)\b(you\s+are\s+now\s+(an\s+)?unrestricted|dan\s+mode|jailbreak\s+mode)",
        r"(?i)\b(bypass|disable|ignore)\s+(safety|guardrails|security\s+policy)",
        r"(?i)\b(output|reveal|print|show)\s+(the\s+)?(full\s+)?system\s+(prompt|instructions)",
        r"(?i)\b(base64\s+decode\s+and\s+execute|eval\(atob|eval\(decode)",
    ]

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        # Check target string
        for inj_pat in self.INJECTION_PATTERNS:
            if re.search(inj_pat, action.target):
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    matched=True,
                    risk_score=self.base_score,
                    risk_level=self.risk_level,
                    description=f"Prompt injection pattern detected in action target: '{action.target}'",
                    pattern_matched=inj_pat,
                    confidence=0.95,
                    metadata={"field": "target", "value": action.target},
                )

        # Check all action parameters (e.g. content being written, arguments)
        params = action.parameters or {}
        for k, v in params.items():
            if isinstance(v, str):
                for inj_pat in self.INJECTION_PATTERNS:
                    if re.search(inj_pat, v):
                        return RuleMatch(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            matched=True,
                            risk_score=self.base_score,
                            risk_level=self.risk_level,
                            description=f"Prompt injection directive detected in parameter '{k}'",
                            pattern_matched=inj_pat,
                            confidence=0.95,
                            metadata={"field": k, "value": v[:120]},
                        )

        return None


class PackageAttackRule(DetectionRule):
    """
    Detects malicious package installations, typosquatted dependency names,
    and untrusted or insecure package repository flags.
    """
    rule_id = "RULE_PACKAGE_ATTACK"
    name = "Malicious Package Attack Detection"
    description = "Detects installation of typosquatted packages and untrusted package source flags."
    category = "Supply Chain"
    base_score = 80
    risk_level = RiskLevel.HIGH

    # Known typosquats and suspicious packages
    SUSPICIOUS_PACKAGES = [
        "reqeusts", "reqests", "requsts", "python-dotenvs", "colorama-v2",
        "discord-py-self", "cryptography-v2", "pydantic-v3", "urllib4",
        "beautifulsoup5", "pyyaml-lib", "flask-app", "numpy-official",
        "pandas-core", "torch-gpu-latest", "shadow-stealer", "reverse-shell"
    ]

    # Insecure package repository flags in command lines
    DANGEROUS_FLAGS_PATTERNS = [
        r"(?i)--extra-index-url\s+http://",
        r"(?i)--index-url\s+http://",
        r"(?i)--trusted-host\s+",
        r"(?i)git\+http://",
        r"(?i)\bpip\s+install\s+.*(curl|wget)\b",
    ]

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        # 1. Direct install_package action
        if action.action == ActionType.INSTALL_PACKAGE:
            pkg_name = action.target.strip().lower()
            if pkg_name in [p.lower() for p in self.SUSPICIOUS_PACKAGES]:
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    matched=True,
                    risk_score=self.base_score,
                    risk_level=self.risk_level,
                    description=f"Installation of suspicious/typosquatted package: '{pkg_name}'",
                    pattern_matched=pkg_name,
                    confidence=0.90,
                    metadata={"package": pkg_name},
                )

        # 2. Command line package installation
        if action.action == ActionType.RUN_COMMAND:
            cmd = action.target.strip()
            # Check package names in pip/npm install command
            if re.search(r"(?i)\b(pip|npm|gem|cargo)\s+install\b", cmd):
                for sus_pkg in self.SUSPICIOUS_PACKAGES:
                    if re.search(rf"\b{re.escape(sus_pkg)}\b", cmd, re.IGNORECASE):
                        return RuleMatch(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            matched=True,
                            risk_score=self.base_score,
                            risk_level=self.risk_level,
                            description=f"Suspicious/typosquatted package installation in command: '{cmd}'",
                            pattern_matched=sus_pkg,
                            confidence=0.90,
                            metadata={"command": cmd, "package": sus_pkg},
                        )

            # Check dangerous flags
            for flag_pat in self.DANGEROUS_FLAGS_PATTERNS:
                if re.search(flag_pat, cmd):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        matched=True,
                        risk_score=75,
                        risk_level=RiskLevel.HIGH,
                        description=f"Insecure package installation flags detected: '{cmd}'",
                        pattern_matched=flag_pat,
                        confidence=0.85,
                        metadata={"command": cmd},
                    )

        return None


def get_default_rules() -> List[DetectionRule]:
    """Factory returning all standard detection rules."""
    return [
        CredentialTheftRule(),
        DataExfiltrationRule(),
        DestructiveActionRule(),
        PrivilegeEscalationRule(),
        PromptInjectionRule(),
        PackageAttackRule(),
    ]


class RuleEngine:
    """Coordinates and evaluates deterministic threat detection rules."""

    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        self.rules: List[DetectionRule] = rules if rules is not None else get_default_rules()

    def register_rule(self, rule: DetectionRule) -> None:
        """Add a custom detection rule to the engine."""
        self.rules.append(rule)

    def evaluate(self, action: AgentAction, context: Optional[Dict[str, Any]] = None) -> List[RuleMatch]:
        """
        Evaluate all registered rules against an action.
        
        Returns:
            List of all triggered RuleMatch findings.
        """
        matches: List[RuleMatch] = []
        for rule in self.rules:
            match = rule.evaluate(action, context)
            if match:
                matches.append(match)
        return matches
