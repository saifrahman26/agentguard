"""
AgentGuard Policy Engine

Loads, manages, and deterministically evaluates security policies for:
- Filesystem access (allowed/blocked path globs, sensitive path protection, traversal prevention)
- Outbound network requests (allowed/blocked domain filtering, default deny/allow)
- Shell command execution (allowed/blocked command tokens and dangerous patterns)
- Package installation (allowed/blocked package names and wildcard specifications)
"""
from __future__ import annotations

import json
import os
import re
import shlex
import urllib.parse
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from app.core.models import ActionType, AgentAction
from app.security.permissions import PermissionSet


class PolicyEvaluationResult(BaseModel):
    """
    Structured outcome of evaluating an action or resource against security policies.
    """
    allowed: bool = Field(..., description="Whether the evaluated action is permitted by policy")
    policy_name: str = Field(..., description="Name of the active policy configuration")
    rule_matched: str = Field(..., description="The specific rule or pattern that matched, or fallback reason")
    reason: str = Field(..., description="Human-readable explanation of why the action was allowed or denied")
    penalty_score: int = Field(default=0, ge=0, le=100, description="Penalty risk score incurred (0 for allowed, >0 for violations)")


def _normalize_path_str(path: str) -> str:
    """Normalize path separators and eliminate redundant components."""
    if not path:
        return ""
    # Replace backslashes with forward slashes
    norm = path.replace("\\", "/").strip()
    return norm


def match_path_pattern(pattern: str, target_path: str) -> bool:
    """
    Determine if a target path matches a policy glob pattern.
    Supports:
      - `**` for arbitrary recursive directories
      - `*` for single path segment wildcards
      - `~` for user home directory expansion
      - `./` relative prefix normalization
    """
    if not pattern or not target_path:
        return False

    pattern_norm = _normalize_path_str(pattern)
    target_norm = _normalize_path_str(target_path)

    # Fast equality check
    if pattern_norm == target_norm:
        return True

    # Strip redundant leading ./
    p_clean = pattern_norm[2:] if pattern_norm.startswith("./") else pattern_norm
    t_clean = target_norm[2:] if target_norm.startswith("./") else target_norm

    if p_clean == t_clean:
        return True

    # User home expansion
    try:
        user_home = _normalize_path_str(str(Path.home()))
    except Exception:
        user_home = ""

    # Generate candidate variations for matching
    pattern_variants = [p_clean, pattern_norm]
    if user_home:
        if p_clean.startswith("~"):
            pattern_variants.append(p_clean.replace("~", user_home, 1))
        if pattern_norm.startswith("~"):
            pattern_variants.append(pattern_norm.replace("~", user_home, 1))

    target_variants = [t_clean, target_norm]
    if user_home:
        if t_clean.startswith("~"):
            target_variants.append(t_clean.replace("~", user_home, 1))
        if target_norm.startswith("~"):
            target_variants.append(target_norm.replace("~", user_home, 1))
        # If target is absolute and starts with user_home, add ~ version
        if user_home and target_norm.startswith(user_home):
            tilde_target = "~" + target_norm[len(user_home):]
            target_variants.append(tilde_target)

    # Check each pattern variant against each target variant
    for p in pattern_variants:
        regex = _glob_to_regex(p)
        for t in target_variants:
            if regex.match(t):
                return True
            # Secondary check with case-insensitive / fnmatch
            if fnmatchcase(t.lower(), p.lower()):
                return True

    return False


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Convert glob pattern with ** and * into a compiled regex."""
    i, n = 0, len(pattern)
    res: List[str] = []
    
    # Optional leading ./ matching
    if pattern.startswith("./"):
        res.append(r"(?:\./)?")
        i = 2

    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                i += 2
                if i < n and pattern[i] == "/":
                    i += 1
                    res.append(r"(?:.*/)?")
                elif i == n:
                    res.append(r".*")
                else:
                    res.append(r".*")
            else:
                i += 1
                res.append(r"[^/]*")
        elif c == "?":
            res.append(r"[^/]")
            i += 1
        else:
            res.append(re.escape(c))
            i += 1

    pattern_str = f"^{''.join(res)}$"
    return re.compile(pattern_str, re.IGNORECASE)


class PolicyEngine:
    """
    Policy evaluation engine for AgentGuard.
    Enforces security boundaries across filesystem, network, shell, and package domains.
    """

    DEFAULT_POLICY_DICT: Dict[str, Any] = {
        "name": "default_policy",
        "version": "1.0.0",
        "description": "AgentGuard Default Security Policy",
        "filesystem": {
            "allowed_paths": [
                "./project/**",
                "./src/**",
                "./tests/**",
                "project/**",
                "src/**",
                "tests/**",
            ],
            "blocked_paths": [
                "~/.ssh/**",
                "~/.aws/**",
                "~/.gnupg/**",
                "/etc/**",
                "/var/**",
                "/root/**",
                "C:/Windows/**",
                "C:/Program Files/**",
                "**/.env*",
                "**/*.key",
                "**/*.pem",
                "**/*.id_rsa*",
                "**/id_rsa*",
                "**/.git/**",
                "**/credentials*",
                "**/id_ed25519*",
            ],
        },
        "network": {
            "default": "deny",
            "allowed_domains": [
                "api.github.com",
                "pypi.org",
                "files.pythonhosted.org",
                "registry.npmjs.org",
                "cdn.jsdelivr.net",
                "raw.githubusercontent.com",
            ],
            "blocked_domains": [
                "*",
            ],
        },
        "shell": {
            "allowed_commands": [
                "python",
                "pytest",
                "git",
                "pip",
                "npm",
                "echo",
                "ls",
                "dir",
                "cat",
                "node",
                "pnpm",
                "yarn",
                "ruff",
                "mypy",
                "black",
            ],
            "blocked_commands": [
                "sudo",
                "rm -rf",
                "chmod 777",
                "curl",
                "wget",
                "nc",
                "bash -i",
                "sh -i",
                "mkfs",
                "dd",
                "shutdown",
                "reboot",
                ":(){ :|:& };:",
            ],
        },
        "packages": {
            "allowed_packages": [
                "pytest*",
                "requests*",
                "pydantic*",
                "fastapi*",
                "sqlalchemy*",
                "uvicorn*",
                "httpx*",
                "numpy*",
                "pandas*",
                "python-*",
                "*",
            ],
            "blocked_packages": [
                "malware*",
                "crypto-miner*",
                "evil-package*",
                "keylogger*",
            ],
        },
    }

    def __init__(
        self,
        policy_path: Optional[Union[str, Path]] = None,
        policy_dict: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._policy_data: Dict[str, Any] = {}
        self.name: str = "default_policy"

        if policy_dict is not None:
            self.load_from_dict(policy_dict)
        elif policy_path is not None:
            self.load_from_file(policy_path)
        else:
            # Try finding default policy file or fallback to DEFAULT_POLICY_DICT
            default_locations = [
                Path("./policies/default_policy.json"),
                Path("../policies/default_policy.json"),
                Path(__file__).parent.parent.parent / "policies" / "default_policy.json",
                Path(__file__).parent.parent.parent.parent / "policies" / "default_policy.json",
            ]
            loaded = False
            for loc in default_locations:
                if loc.is_file():
                    try:
                        self.load_from_file(loc)
                        loaded = True
                        break
                    except Exception:
                        pass
            if not loaded:
                self.load_from_dict(self.DEFAULT_POLICY_DICT)

    def load_from_dict(self, policy_dict: Dict[str, Any]) -> None:
        """Load policy configuration directly from dictionary."""
        if not isinstance(policy_dict, dict):
            raise ValueError("Policy configuration must be a dictionary")
        self._policy_data = policy_dict
        self.name = policy_dict.get("name", "custom_policy")

    def load_from_file(self, policy_path: Union[str, Path]) -> None:
        """Load and parse policy configuration from a JSON file."""
        path_obj = Path(policy_path)
        if not path_obj.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        with open(path_obj, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.load_from_dict(data)

    def get_policy_data(self) -> Dict[str, Any]:
        """Return a copy of the active policy configuration dictionary."""
        return dict(self._policy_data)

    # -----------------------------------------------------------------------
    # Filesystem Evaluation
    # -----------------------------------------------------------------------

    def evaluate_filesystem(
        self,
        path: str,
        action_type: Union[ActionType, str] = ActionType.READ_FILE,
    ) -> PolicyEvaluationResult:
        """
        Evaluate a filesystem target path against allowed and blocked path policies.
        Includes traversal detection and sensitive file protection.
        """
        if not path or not str(path).strip():
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="empty_target",
                reason="Target path is empty or invalid.",
                penalty_score=80,
            )

        target_path = str(path).strip()
        norm_path = _normalize_path_str(target_path)
        fs_config = self._policy_data.get("filesystem", {})
        blocked_paths: List[str] = fs_config.get("blocked_paths", [])
        allowed_paths: List[str] = fs_config.get("allowed_paths", [])

        # Check for directory traversal attempts
        # e.g., ../../etc/passwd or /src/../../.env
        parts = norm_path.split("/")
        if ".." in parts:
            # Check normalized resolution and strip relative traversal prefixes
            resolved_norm = _normalize_path_str(os.path.normpath(target_path))
            stripped_traversal = "/" + re.sub(r"^(?:\.\./)+", "", resolved_norm).lstrip("/")
            rel_stripped = re.sub(r"^(?:\.\./)+", "", resolved_norm)
            
            for pattern in blocked_paths:
                if (
                    match_path_pattern(pattern, resolved_norm)
                    or match_path_pattern(pattern, target_path)
                    or match_path_pattern(pattern, stripped_traversal)
                    or match_path_pattern(pattern, rel_stripped)
                ):
                    return PolicyEvaluationResult(
                        allowed=False,
                        policy_name=self.name,
                        rule_matched=pattern,
                        reason=f"Path traversal access to sensitive target '{target_path}' is blocked by rule '{pattern}'.",
                        penalty_score=100,
                    )
            
            # If path traversal does not match a specific blocked path, it is still a high-risk violation
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="path_traversal_prohibited",
                reason=f"Directory traversal detected in path '{target_path}'.",
                penalty_score=100,
            )

        # 1. Evaluate against blocked paths (Blacklist precedence)
        for pattern in blocked_paths:
            if match_path_pattern(pattern, target_path):
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched=pattern,
                    reason=f"Access to path '{target_path}' is blocked by security policy rule '{pattern}'.",
                    penalty_score=100,
                )

        # 2. Evaluate against allowed paths (Whitelist enforcement if configured)
        if allowed_paths:
            matched_allowed = False
            matched_rule = ""
            for pattern in allowed_paths:
                if match_path_pattern(pattern, target_path):
                    matched_allowed = True
                    matched_rule = pattern
                    break

            if matched_allowed:
                return PolicyEvaluationResult(
                    allowed=True,
                    policy_name=self.name,
                    rule_matched=matched_rule,
                    reason=f"Path '{target_path}' is permitted by policy rule '{matched_rule}'.",
                    penalty_score=0,
                )
            else:
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched="filesystem_allowed_paths",
                    reason=f"Path '{target_path}' is not within any allowed filesystem paths.",
                    penalty_score=60,
                )

        # If no allowed_paths whitelist is specified, default to allow if not blocked
        return PolicyEvaluationResult(
            allowed=True,
            policy_name=self.name,
            rule_matched="filesystem_default_allow",
            reason=f"Path '{target_path}' does not violate any filesystem policy rules.",
            penalty_score=0,
        )

    # -----------------------------------------------------------------------
    # Network Evaluation
    # -----------------------------------------------------------------------

    def evaluate_network(self, url: str) -> PolicyEvaluationResult:
        """
        Evaluate an outbound network destination URL or domain against network policies.
        """
        if not url or not str(url).strip():
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="empty_url",
                reason="Network target URL or domain is empty.",
                penalty_score=80,
            )

        raw_target = str(url).strip()
        domain = self._extract_domain(raw_target)

        net_config = self._policy_data.get("network", {})
        default_policy = net_config.get("default", "deny").lower()
        allowed_domains: List[str] = net_config.get("allowed_domains", [])
        blocked_domains: List[str] = net_config.get("blocked_domains", [])

        # 1. Check if domain is explicitly allowed (Whitelist priority)
        for allowed in allowed_domains:
            if self._match_domain_pattern(allowed, domain):
                return PolicyEvaluationResult(
                    allowed=True,
                    policy_name=self.name,
                    rule_matched=allowed,
                    reason=f"Network destination '{domain}' is explicitly permitted by rule '{allowed}'.",
                    penalty_score=0,
                )

        # 2. Check if domain matches blocked domains
        for blocked in blocked_domains:
            if self._match_domain_pattern(blocked, domain):
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched=blocked,
                    reason=f"Network destination '{domain}' is blocked by rule '{blocked}'.",
                    penalty_score=80,
                )

        # 3. Apply default policy
        if default_policy == "allow":
            return PolicyEvaluationResult(
                allowed=True,
                policy_name=self.name,
                rule_matched="network_default_allow",
                reason=f"Network destination '{domain}' is permitted under default allow policy.",
                penalty_score=0,
            )
        else:
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="network_default_deny",
                reason=f"Network destination '{domain}' is blocked by default network deny policy.",
                penalty_score=60,
            )

    @staticmethod
    def _extract_domain(url_or_domain: str) -> str:
        """Extract clean hostname/domain from URL or host string."""
        target = url_or_domain.strip()
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or parsed.netloc or target
        else:
            # Handle forms like host:port/path or host/path
            host = target.split("/")[0].split(":")[0]
        return host.lower().strip()

    @staticmethod
    def _match_domain_pattern(pattern: str, domain: str) -> bool:
        """Match domain against pattern supporting wildcards (*.example.com, *)."""
        pattern_clean = pattern.lower().strip()
        domain_clean = domain.lower().strip()

        if pattern_clean == "*":
            return True
        if pattern_clean == domain_clean:
            return True
        if pattern_clean.startswith("*."):
            suffix = pattern_clean[2:]
            return domain_clean == suffix or domain_clean.endswith("." + suffix)
        return fnmatchcase(domain_clean, pattern_clean)

    # -----------------------------------------------------------------------
    # Shell Evaluation
    # -----------------------------------------------------------------------

    def evaluate_shell(self, command: str) -> PolicyEvaluationResult:
        """
        Evaluate a shell command string against authorized and prohibited command policies.
        Inspects chained subcommands, executable names, and hazardous patterns.
        """
        if not command or not str(command).strip():
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="empty_command",
                reason="Shell command is empty.",
                penalty_score=80,
            )

        cmd_str = str(command).strip()
        shell_config = self._policy_data.get("shell", {})
        allowed_commands: List[str] = shell_config.get("allowed_commands", [])
        blocked_commands: List[str] = shell_config.get("blocked_commands", [])

        # 1. Check blocked commands (both exact tokens and dangerous substrings)
        cmd_lower = cmd_str.lower()
        for blocked in blocked_commands:
            blocked_clean = blocked.lower().strip()
            # Check for substring match (e.g., 'rm -rf', 'chmod 777', 'bash -i', ':(){ :|:& };:')
            if blocked_clean in cmd_lower:
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched=blocked,
                    reason=f"Shell command contains prohibited pattern '{blocked}'.",
                    penalty_score=100,
                )

        # 2. Extract and validate base executable commands
        sub_commands = self._parse_command_segments(cmd_str)
        if not sub_commands:
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="unparseable_command",
                reason="Shell command could not be parsed safely.",
                penalty_score=80,
            )

        # Check each sub-executable against blocked list tokens
        for exe in sub_commands:
            exe_clean = exe.lower()
            for blocked in blocked_commands:
                if exe_clean == blocked.lower().strip():
                    return PolicyEvaluationResult(
                        allowed=False,
                        policy_name=self.name,
                        rule_matched=blocked,
                        reason=f"Shell executable '{exe}' is blocked by security policy.",
                        penalty_score=100,
                    )

        # 3. Check allowed commands whitelist if configured
        if allowed_commands:
            for exe in sub_commands:
                exe_clean = exe.lower()
                allowed_match = False
                for allowed in allowed_commands:
                    allowed_clean = allowed.lower().strip()
                    if allowed_clean == "*" or exe_clean == allowed_clean or fnmatchcase(exe_clean, allowed_clean):
                        allowed_match = True
                        break

                if not allowed_match:
                    return PolicyEvaluationResult(
                        allowed=False,
                        policy_name=self.name,
                        rule_matched=exe,
                        reason=f"Shell command '{exe}' is not in the list of authorized commands.",
                        penalty_score=70,
                    )

            return PolicyEvaluationResult(
                allowed=True,
                policy_name=self.name,
                rule_matched="allowed_commands",
                reason=f"All executable segments in command '{cmd_str}' are authorized.",
                penalty_score=0,
            )

        # If no allowed whitelist is configured, allow by default
        return PolicyEvaluationResult(
            allowed=True,
            policy_name=self.name,
            rule_matched="shell_default_allow",
            reason=f"Command '{cmd_str}' does not violate shell policy.",
            penalty_score=0,
        )

    @staticmethod
    def _parse_command_segments(command_str: str) -> List[str]:
        """
        Split a compound command line (e.g. 'cat f | grep x && python main.py')
        and return the base executable names.
        """
        # Split on command separators |, ;, &&, ||, &
        raw_segments = re.split(r"\|\||&&|[|;&\n]", command_str)
        executables: List[str] = []

        for seg in raw_segments:
            seg_clean = seg.strip()
            if not seg_clean:
                continue
            try:
                tokens = shlex.split(seg_clean, posix=False)
            except Exception:
                tokens = seg_clean.split()

            if not tokens:
                continue

            first_token = tokens[0].strip()
            # Strip path prefixes like /usr/bin/python or .\pytest or python.exe
            base_name = Path(first_token).stem if first_token.endswith(".exe") else Path(first_token).name
            executables.append(base_name)

        return executables

    # -----------------------------------------------------------------------
    # Package Evaluation
    # -----------------------------------------------------------------------

    def evaluate_package(self, package_name: str) -> PolicyEvaluationResult:
        """
        Evaluate a package name against allowed and blocked package policies.
        Normalizes version specifiers (e.g., 'requests>=2.0.0' -> 'requests').
        """
        if not package_name or not str(package_name).strip():
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="empty_package_name",
                reason="Package name is empty.",
                penalty_score=80,
            )

        raw_name = str(package_name).strip()
        clean_name = self._normalize_package_name(raw_name)

        pkg_config = self._policy_data.get("packages", {})
        allowed_packages: List[str] = pkg_config.get("allowed_packages", [])
        blocked_packages: List[str] = pkg_config.get("blocked_packages", [])

        # 1. Check blocked packages
        for pattern in blocked_packages:
            if fnmatchcase(clean_name.lower(), pattern.lower()):
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched=pattern,
                    reason=f"Package '{raw_name}' matches blocked package policy pattern '{pattern}'.",
                    penalty_score=90,
                )

        # 2. Check allowed packages whitelist
        if allowed_packages:
            matched_allowed = False
            matched_rule = ""
            for pattern in allowed_packages:
                if pattern == "*" or fnmatchcase(clean_name.lower(), pattern.lower()):
                    matched_allowed = True
                    matched_rule = pattern
                    break

            if matched_allowed:
                return PolicyEvaluationResult(
                    allowed=True,
                    policy_name=self.name,
                    rule_matched=matched_rule,
                    reason=f"Package '{raw_name}' is authorized by rule '{matched_rule}'.",
                    penalty_score=0,
                )
            else:
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched="package_whitelist",
                    reason=f"Package '{raw_name}' is not in the authorized packages list.",
                    penalty_score=60,
                )

        return PolicyEvaluationResult(
            allowed=True,
            policy_name=self.name,
            rule_matched="package_default_allow",
            reason=f"Package '{raw_name}' is permitted.",
            penalty_score=0,
        )

    @staticmethod
    def _normalize_package_name(package_str: str) -> str:
        """Strip version specifiers, extras, and environment markers."""
        # Remove extras like package[security]
        name = re.sub(r"\[.*?\]", "", package_str)
        # Split on version comparison operators
        name = re.split(r"[><=~!]", name)[0]
        return name.strip().lower()

    # -----------------------------------------------------------------------
    # Comprehensive Action Evaluation
    # -----------------------------------------------------------------------

    def evaluate_action(
        self,
        action: AgentAction,
        agent_permissions: Optional[PermissionSet] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate a complete AgentAction against permissions (if provided) and policy rules.
        """
        # 1. Permission set check
        if agent_permissions is not None:
            if not agent_permissions.is_action_allowed(action.action):
                return PolicyEvaluationResult(
                    allowed=False,
                    policy_name=self.name,
                    rule_matched="permission_denied",
                    reason=f"Agent lacks capability permission for action '{action.action.value}'.",
                    penalty_score=80,
                )

        # 2. Policy rules dispatch
        action_type = action.action
        target = action.target

        if action_type in (ActionType.READ_FILE, ActionType.WRITE_FILE, ActionType.DELETE_FILE, ActionType.LIST_DIRECTORY):
            return self.evaluate_filesystem(target, action_type=action_type)
        elif action_type == ActionType.RUN_COMMAND:
            return self.evaluate_shell(target)
        elif action_type == ActionType.NETWORK_REQUEST:
            return self.evaluate_network(target)
        elif action_type == ActionType.INSTALL_PACKAGE:
            return self.evaluate_package(target)
        else:
            return PolicyEvaluationResult(
                allowed=False,
                policy_name=self.name,
                rule_matched="unsupported_action_type",
                reason=f"Unsupported action type '{action_type}'.",
                penalty_score=80,
            )


# Singleton PolicyEngine accessor
_policy_engine_instance: Optional[PolicyEngine] = None


def get_policy_engine(policy_path: Optional[Union[str, Path]] = None) -> PolicyEngine:
    """Return or initialize the singleton PolicyEngine instance."""
    global _policy_engine_instance
    if _policy_engine_instance is None or policy_path is not None:
        _policy_engine_instance = PolicyEngine(policy_path=policy_path)
    return _policy_engine_instance
