"""Core IAM security analysis engine: effective-permission evaluation, shadow-admin and privesc detection, trust analysis and credential hygiene."""

import json
import re
from collections import defaultdict
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (AccountAnalysis, CrossAccountTrust, Edge, EscalationPath,
                     Finding, Policy, PolicyStatement, Principal)
from .knowledge import (AWS_MANAGED_PATTERNS, CHECK_LABEL, COMPUTE_CHECKS,
                        CONFUSED_DEPUTY_SERVICES, CRED_CHECKS, DANGEROUS_ACTIONS,
                        EVASION_CHECKS, IAM_CHECKS, IAM_WILDCARD_THRESHOLD,
                        S3_CHECKS, TECHNIQUE_PATTERNS, get_mitre_for_technique)
from .managed_policies import resolve_managed_policy_actions


class AnalysisEngine:
    """Core analysis engine for IAM security assessment."""

    def __init__(self, principals: Dict[str, Principal], edges: List[Edge],
                 policies: Dict[str, Policy], account_id: str = ""):
        self.principals = principals
        self.edges = edges
        self.policies = policies
        self.account_id = account_id or self._detect_account_id()

        self.edge_from: Dict[str, List[Edge]] = defaultdict(list)
        self.edge_to: Dict[str, List[Edge]] = defaultdict(list)
        for edge in edges:
            self.edge_from[edge.source].append(edge)
            self.edge_to[edge.target].append(edge)

        self.admins: Set[str] = {
            arn for arn, p in principals.items() if p.is_admin
        }

    def _detect_account_id(self) -> str:
        """Extract account ID from principal ARNs."""
        for arn in self.principals:
            parts = arn.split(":")
            if len(parts) > 4 and parts[4].isdigit():
                return parts[4]
        return "unknown"

    def analyze(self) -> AccountAnalysis:
        """Run full analysis and return results."""
        analysis = AccountAnalysis(
            account_id=self.account_id,
            account_alias=self.account_id,
            node_count=len(self.principals),
            edge_count=len(self.edges),
            admin_count=len(self.admins),
            principals=self.principals,
            edges=self.edges,
            policies=self.policies,
        )

        self._compute_all_capabilities()

        analysis.shadow_admins = self._find_shadow_admins()
        shadow_arns = {p.arn for p in analysis.shadow_admins}
        analysis.overly_permissive = self._find_overly_permissive(exclude_arns=shadow_arns)
        analysis.aws_managed_admins = self._find_aws_managed_admins()
        analysis.escalation_paths = self._find_escalation_paths()
        analysis.cross_account_trusts = self._analyze_cross_account_trusts()
        analysis.credential_hygiene = self._find_credential_hygiene_issues()
        analysis.findings = self._generate_findings(analysis)

        return analysis

    def _find_aws_managed_admins(self) -> List[Principal]:
        """Find AWS-managed roles that are admins (expected but worth noting)."""
        managed = []
        for arn, principal in self.principals.items():
            if principal.is_admin and self._is_aws_managed(principal.name):
                managed.append(principal)
        return managed

    def _find_credential_hygiene_issues(self) -> List[Dict[str, Any]]:
        """Credential-hygiene findings a real IAM assessment must include.

        Uses fields the graph carries (has_mfa, active_password, num_access_keys) that
        the tool previously discarded: privileged principals without MFA, console users
        without MFA, and principals holding long-term access keys.
        """
        issues = []
        for arn, p in self.principals.items():
            if p.principal_type != "user":
                continue
            privileged = p.is_admin or bool(p.dangerous_actions)
            flags = []
            if p.active_password and not p.has_mfa:
                flags.append("console password WITHOUT MFA")
            if p.num_access_keys and p.num_access_keys > 0:
                flags.append(f"{p.num_access_keys} active long-term access key(s)")
            if p.num_access_keys and p.num_access_keys > 1:
                flags.append("multiple concurrent access keys (rotation hygiene)")
            if not flags:
                continue
            if p.active_password and not p.has_mfa and privileged:
                sev = "high"
            elif p.active_password and not p.has_mfa:
                sev = "medium"
            elif p.num_access_keys and privileged:
                sev = "medium"
            else:
                sev = "low"
            issues.append({
                "arn": arn,
                "name": p.name,
                "is_admin": p.is_admin,
                "privileged": privileged,
                "has_mfa": p.has_mfa,
                "active_password": p.active_password,
                "num_access_keys": p.num_access_keys or 0,
                "id_value": p.id_value,
                "severity": sev,
                "flags": flags,
            })
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(issues, key=lambda x: (order.get(x["severity"], 3), not x["is_admin"], x["name"]))

    @staticmethod
    def _expand_action(action: str) -> Set[str]:
        """Return the subset of DANGEROUS_ACTIONS an Action string grants."""
        if action == "*":
            return set(DANGEROUS_ACTIONS)
        if action.endswith(":*"):
            service = action.split(":")[0]
            return {d for d in DANGEROUS_ACTIONS if d.startswith(service + ":")}
        if action in DANGEROUS_ACTIONS:
            return {action}
        return set()

    def _dangerous_covered_by_statement(self, stmt: PolicyStatement) -> Set[str]:
        """Dangerous actions a statement's Action/NotAction clause matches."""
        if stmt.not_actions:
            excluded = set()
            for na in stmt.not_actions:
                excluded |= self._expand_action(na)
            return DANGEROUS_ACTIONS - excluded
        covered = set()
        for a in stmt.actions:
            covered |= self._expand_action(a)
        return covered

    def _effective_policies(self, principal: Principal):
        """Every identity policy in effect for a principal, resolved.

        Includes directly-attached, inline, and group-inherited policies. AWS-managed
        policies absent from the graph are resolved from the built-in catalog; ones we
        cannot resolve are recorded on principal.unresolved_managed so the report can
        state that computed capabilities may be understated.
        Returns list of (Policy, source_label).
        """
        out = []
        seen = set()

        def add_by_arn(pa, source):
            if not pa or (pa, source) in seen:
                return
            seen.add((pa, source))
            pol = self.policies.get(pa)
            if pol:
                out.append((pol, source))
                return
            acts = resolve_managed_policy_actions(pa)
            if acts is None:
                if pa.startswith("arn:aws:iam::aws:policy/") and pa not in principal.unresolved_managed:
                    principal.unresolved_managed.append(pa)
                return
            synth = Policy(
                arn=pa, name=pa.split("/")[-1], is_aws_managed=True,
                statements=[PolicyStatement(effect="Allow",
                                            actions=sorted(acts) if acts else [],
                                            resources=["*"])],
            )
            out.append((synth, source))

        for pa in principal.policies:
            add_by_arn(pa, "attached")
        for pa in principal.group_policy_arns:
            add_by_arn(pa, "group")
        for ip in principal.inline_policies:
            out.append((ip, "inline"))
        return out

    def _compute_all_capabilities(self):
        """Compute effective dangerous actions per principal, AWS-faithfully.

        Honors: Allow/Deny (broad unconditional Deny subtracts), NotAction, inline and
        group-inherited policies, the AdministratorAccess/managed-policy catalog, the
        is_admin flag, and permissions boundaries (intersection when resolvable, else a
        'boundary_capped' flag). Records per-action evidence for reporting.
        """
        for arn, principal in self.principals.items():
            allow = {}
            deny = set()
            principal.boundary_capped = bool(principal.permissions_boundary)

            for pol, source in self._effective_policies(principal):
                for stmt in pol.statements:
                    if stmt.effect == "Allow":
                        if stmt.not_actions:
                            principal.has_notaction = True
                        covered = self._dangerous_covered_by_statement(stmt)
                        for a in covered:
                            if a not in allow:
                                allow[a] = {
                                    "policy": pol.arn,
                                    "policy_name": pol.name,
                                    "source": source,
                                    "sid": stmt.sid,
                                    "resources": list(stmt.resources) or (["<NotResource>"] if stmt.not_resources else ["*"]),
                                    "conditions": bool(stmt.conditions),
                                }
                    elif stmt.effect == "Deny":
                        broad = ("*" in stmt.resources) or bool(stmt.not_resources) or (not stmt.resources)
                        if broad and not stmt.conditions:
                            deny |= self._dangerous_covered_by_statement(stmt)

            if principal.is_admin:
                for a in DANGEROUS_ACTIONS:
                    allow.setdefault(a, {
                        "policy": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "policy_name": "AdministratorAccess",
                        "source": "admin", "sid": "", "resources": ["*"], "conditions": False,
                    })

            dangerous = set(allow) - deny

            if principal.permissions_boundary:
                bpol = self.policies.get(principal.permissions_boundary)
                bacts = None
                if bpol:
                    bacts = set()
                    for stmt in bpol.statements:
                        if stmt.effect == "Allow":
                            bacts |= self._dangerous_covered_by_statement(stmt)
                else:
                    bacts = resolve_managed_policy_actions(principal.permissions_boundary)
                if bacts is not None:
                    dangerous &= bacts

            principal.dangerous_actions = dangerous
            principal.action_evidence = {a: allow[a] for a in dangerous if a in allow}

            groups = self._classify_capabilities(dangerous)
            principal.capability_groups = groups

            principal.capabilities = [
                CHECK_LABEL.get(action, action)
                for action in sorted(dangerous)
                if action in CHECK_LABEL
            ]

    def _classify_capabilities(self, actions: Set[str]) -> List[Tuple[str, str, List[str]]]:
        """Classify actions into capability groups with severity."""
        groups = []

        iam_actions = actions & IAM_CHECKS
        s3_actions = actions & S3_CHECKS
        cred_actions = actions & CRED_CHECKS
        compute_actions = actions & COMPUTE_CHECKS
        evasion_actions = actions & EVASION_CHECKS

        if iam_actions:
            if len(iam_actions) >= IAM_WILDCARD_THRESHOLD:
                groups.append(("iam:*", "critical", sorted(iam_actions)))
            else:
                groups.append(("IAM (specific)", "high", sorted(iam_actions)))

        if s3_actions:
            label = "s3:*" if s3_actions >= S3_CHECKS else "S3 (partial)"
            groups.append((label, "high", sorted(s3_actions)))

        if cred_actions:
            groups.append(("Credential Access", "high", sorted(cred_actions)))

        if compute_actions:
            groups.append(("Service Compute Abuse", "high", sorted(compute_actions)))

        if evasion_actions:
            groups.append(("Defense Evasion", "medium", sorted(evasion_actions)))

        return groups

    def _has_wildcard_resource_for_action(self, principal: Principal, action: str) -> bool:
        """Check if a principal has wildcard resource scope for a specific action.

        This is important for distinguishing between:
        - iam:CreateAccessKey on Resource: * (can create keys for any user - DANGEROUS)
        - iam:CreateAccessKey on Resource: arn:aws:iam::*:user/${aws:username} (self only - not escalation)

        Considers attached, inline, group-inherited, and resolved managed policies.
        """
        for policy, _source in self._effective_policies(principal):
            for stmt in policy.statements:
                if stmt.effect != "Allow":
                    continue

                action_matches = False
                if stmt.not_actions:
                    action_matches = action not in self._dangerous_covered_by_statement(
                        PolicyStatement(effect="Allow", actions=list(stmt.not_actions), resources=[])
                    ) and action not in stmt.not_actions
                else:
                    for stmt_action in stmt.actions:
                        if stmt_action == "*" or stmt_action == action:
                            action_matches = True
                            break
                        elif stmt_action.endswith(":*"):
                            service = stmt_action.split(":")[0]
                            if action.startswith(service + ":"):
                                action_matches = True
                                break

                if not action_matches:
                    continue

                if stmt.not_resources and not stmt.resources:
                    return True

                for resource in stmt.resources:
                    if resource == "*":
                        return True
                    if "${aws:username}" in resource or "${aws:userid}" in resource:
                        continue
                    if action.startswith("iam:"):
                        if resource.endswith("/*") or resource.endswith(":*"):
                            return True

        return False

    def _has_wildcard_passrole(self, principal: Principal) -> bool:
        """Check if a principal can pass ANY role (Resource: *)."""
        return self._has_wildcard_resource_for_action(principal, "iam:PassRole")

    def _find_shadow_admins(self) -> List[Principal]:
        """Find principals with admin-equivalent permissions but no AdministratorAccess.

        A true shadow admin is one who has DIRECT escalation capabilities:
        1. Can directly assume an admin role (1-hop sts:AssumeRole)
        2. Has IAM-modifying permissions (iam:AttachRolePolicy, iam:CreateAccessKey, etc.)
        3. Has iam:PassRole + compute permissions (can create Lambda/EC2/etc with admin role)

        NOT someone who is just in a multi-hop escalation path.
        """
        shadow = []

        direct_escalation_actions = {
            "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
            "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
            "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
            "iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup",
        }

        passrole_combo_actions = {
            "lambda:CreateFunction", "lambda:UpdateFunctionCode",
            "ec2:RunInstances", "cloudformation:CreateStack",
            "codebuild:CreateProject", "glue:CreateJob",
            "sagemaker:CreateNotebookInstance", "ecs:RunTask",
        }

        for arn, principal in self.principals.items():
            if principal.is_admin:
                continue
            if self._is_aws_managed(principal.name):
                continue

            can_assume_admin = False
            for edge in self.edge_from.get(arn, []):
                if edge.target in self.admins and "AssumeRole" in edge.short_reason:
                    can_assume_admin = True
                    break

            if can_assume_admin:
                shadow.append(principal)
                continue

            has_direct_iam = False
            for iam_action in principal.dangerous_actions & direct_escalation_actions:
                if self._has_wildcard_resource_for_action(principal, iam_action):
                    has_direct_iam = True
                    break

            has_passrole = "iam:PassRole" in principal.dangerous_actions
            has_wildcard_passrole = has_passrole and self._has_wildcard_passrole(principal)
            has_compute = bool(principal.dangerous_actions & passrole_combo_actions)
            has_passrole_combo = has_wildcard_passrole and has_compute

            has_credential_theft = (
                "iam:CreateAccessKey" in principal.dangerous_actions and
                self._has_wildcard_resource_for_action(principal, "iam:CreateAccessKey")
            )

            if has_direct_iam or has_passrole_combo or has_credential_theft:
                shadow.append(principal)

        return shadow

    def _can_reach_admin(self, start_arn: str, visited: Set[str] = None) -> bool:
        """Check if principal can reach an admin through edges."""
        if visited is None:
            visited = set()

        if start_arn in visited:
            return False
        visited.add(start_arn)

        for edge in self.edge_from.get(start_arn, []):
            if edge.target in self.admins:
                return True
            if self._can_reach_admin(edge.target, visited):
                return True

        return False

    def _find_overly_permissive(self, exclude_arns: Optional[Set[str]] = None) -> List[Principal]:
        """Find principals with dangerous but non-admin permissions.

        Excludes admins, AWS-managed roles, and (per the finding's own description)
        principals already reported as shadow admins, so the same principal is not
        double-counted across findings. Applies resource scope analysis to reduce FPs.
        """
        exclude_arns = exclude_arns or set()
        overly = []

        for arn, principal in self.principals.items():
            if principal.is_admin:
                continue
            if arn in exclude_arns:
                continue
            if self._is_aws_managed(principal.name):
                continue

            risk_score = self._calculate_permission_risk(principal)
            if risk_score >= 5:
                overly.append((principal, risk_score))

        overly.sort(key=lambda x: -x[1])
        return [p for p, _ in overly]

    def _calculate_permission_risk(self, principal: Principal) -> int:
        """Calculate risk score for a principal's permissions.

        Considers:
        - Action type (IAM > compute > read)
        - Resource scope (* = high risk, specific = lower)
        - Condition presence (conditions = lower risk)
        """
        score = 0

        escalation_actions = {
            "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
            "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
            "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
            "iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup", "iam:CreateAccessKey",
        }

        for policy_arn in principal.policies:
            policy = self.policies.get(policy_arn)
            if not policy:
                continue

            for stmt in policy.statements:
                if stmt.effect != "Allow":
                    continue

                is_wildcard_resource = any(r == "*" for r in stmt.resources)
                has_conditions = bool(stmt.conditions)

                for action in stmt.actions:
                    base_score = 0

                    if action == "*":
                        base_score = 10
                    elif action in escalation_actions:
                        base_score = 4
                    elif action in DANGEROUS_ACTIONS:
                        base_score = 2
                    elif action.endswith(":*"):
                        service = action.split(":")[0]
                        if service == "iam":
                            base_score = 5
                        elif service in ["sts", "secretsmanager", "ssm"]:
                            base_score = 3
                        elif service in ["s3", "ec2", "lambda"]:
                            base_score = 2

                    if not is_wildcard_resource and base_score > 0:
                        base_score = max(1, base_score - 1)

                    if has_conditions and base_score > 0:
                        base_score = max(1, base_score - 1)

                    score += base_score

        return score

    def _find_escalation_paths(self) -> List[EscalationPath]:
        """Find and analyze all privilege escalation paths."""
        paths = []

        for arn, principal in self.principals.items():
            if principal.is_admin:
                continue
            if self._is_aws_managed(principal.name):
                continue

            admin_paths = self._find_paths_to_admin(arn)
            for target_arn, hops in admin_paths:
                target = self.principals.get(target_arn)
                if not target:
                    continue

                technique = self._classify_technique(hops)
                path = EscalationPath(
                    source=principal,
                    target=target,
                    hops=hops,
                    technique=technique,
                )

                self._score_path(path)
                paths.append(path)

        return sorted(paths, key=lambda p: -p.risk_score)

    def _find_paths_to_admin(self, start_arn: str) -> List[Tuple[str, List[Edge]]]:
        """BFS to find all paths from start to any admin."""
        results = []
        queue = [(start_arn, [])]
        visited = {start_arn}

        while queue:
            current, path = queue.pop(0)

            for edge in self.edge_from.get(current, []):
                if edge.target in visited:
                    continue

                new_path = path + [edge]

                if edge.target in self.admins:
                    results.append((edge.target, new_path))
                elif len(new_path) < 5:
                    visited.add(edge.target)
                    queue.append((edge.target, new_path))

        return results

    def _classify_technique(self, hops: List[Edge]) -> str:
        """Classify escalation technique based on edge reasons."""
        if not hops:
            return "Unknown"

        combined_reason = " ".join(h.reason for h in hops)

        for technique, patterns in TECHNIQUE_PATTERNS.items():
            if any(re.search(p, combined_reason, re.I) for p in patterns):
                return technique

        return "Other"

    def _score_path(self, path: EscalationPath):
        """Calculate risk score for an escalation path."""
        hop_count = len(path.hops)
        if hop_count == 1:
            path.complexity = 10
        elif hop_count == 2:
            path.complexity = 8
        elif hop_count <= 4:
            path.complexity = 5
        else:
            path.complexity = 2

        path.exposure = 5
        if path.source.has_access_keys:
            path.exposure += 3
        if path.source.principal_type == "role":
            if path.source.trust_policy:
                trust_str = json.dumps(path.source.trust_policy)
                if '"*"' in trust_str or "arn:aws:iam::" in trust_str:
                    path.exposure += 2

        path.blast_radius = 10 if path.target.is_admin else 5

        weighted = (
            (path.complexity * 0.25) +
            (path.exposure * 0.35) +
            (path.blast_radius * 0.40)
        )
        path.risk_score = min(100, round(weighted * 10))

        if path.risk_score >= 80:
            path.severity = "critical"
        elif path.risk_score >= 60:
            path.severity = "high"
        elif path.risk_score >= 40:
            path.severity = "medium"
        else:
            path.severity = "low"

        path.mitre_techniques = get_mitre_for_technique(path.technique)

        path.attack_narrative = self._generate_attack_narrative(path)

    def _generate_attack_narrative(self, path: EscalationPath) -> str:
        """Generate a human-readable attack narrative for the escalation path."""
        source_type = path.source.principal_type
        source_name = path.source.name
        target_name = path.target.name

        if source_type == "user":
            narrative = f"An attacker who compromises the IAM user '{source_name}'"
            if path.source.has_access_keys:
                narrative += " (which has active access keys)"
        elif source_type == "role":
            narrative = f"An attacker who can assume the role '{source_name}'"
        else:
            narrative = f"An attacker with access to '{source_name}'"

        if len(path.hops) == 1:
            hop = path.hops[0]
            narrative += f" can directly escalate to '{target_name}' by exploiting: {hop.reason}."
        else:
            narrative += " can escalate through a multi-step attack chain:\n"
            for i, hop in enumerate(path.hops, 1):
                hop_target = hop.target.split("/")[-1] if "/" in hop.target else hop.target.split(":")[-1]
                narrative += f"  {i}. {hop.reason} -> {hop_target}\n"

        if path.target.is_admin:
            narrative += "\nThis results in full administrative access to the AWS account, "
            narrative += "allowing the attacker to access all resources, exfiltrate data, "
            narrative += "create backdoors, and disable security controls."

        return narrative

    @staticmethod
    def _external_id_enforced(conditions: Dict) -> bool:
        """True only if sts:ExternalId is bound to a concrete value under an equality
        operator. Presence of the key is NOT enforcement: StringLike with '*', a Null
        check, or StringNotEquals do not constrain who can assume the role."""
        if not isinstance(conditions, dict):
            return False
        for op, kv in conditions.items():
            if not isinstance(kv, dict):
                continue
            op_l = op.lower()
            for k, v in kv.items():
                if k.lower() != "sts:externalid":
                    continue
                vals = v if isinstance(v, list) else [v]
                if "equals" in op_l and "notequals" not in op_l:
                    if all(isinstance(x, str) and x and "*" not in x and "?" not in x for x in vals):
                        return True
        return False

    def _analyze_cross_account_trusts(self) -> List[CrossAccountTrust]:
        """Analyze role trust policies for external assumability.

        Handles AWS, Federated (SAML/OIDC, e.g. GitHub Actions) and Service principals;
        verifies that ExternalId is actually ENFORCED (not merely present); and escalates
        risk when the trusted-into role is itself admin/privileged.
        """
        trusts = []

        for arn, principal in self.principals.items():
            if principal.principal_type != "role":
                continue
            if not principal.trust_policy:
                continue

            trust_doc = principal.trust_policy
            if isinstance(trust_doc, str):
                try:
                    trust_doc = json.loads(trust_doc)
                except Exception:
                    continue

            target_is_admin = principal.is_admin or bool(principal.dangerous_actions)

            statements = trust_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                principals_field = stmt.get("Principal", {})
                if isinstance(principals_field, str):
                    principals_field = {"AWS": [principals_field]}
                if principals_field == "*":
                    principals_field = {"AWS": ["*"]}

                conditions = stmt.get("Condition", {})
                condition_str = json.dumps(conditions).lower()
                has_external_id = "sts:externalid" in condition_str
                external_id_enforced = self._external_id_enforced(conditions)
                has_source = ("aws:sourcearn" in condition_str) or ("aws:sourceaccount" in condition_str)
                has_org_id = "aws:principalorgid" in condition_str
                has_principal_arn = "aws:principalarn" in condition_str
                has_mfa = "aws:multifactorauthpresent" in condition_str
                has_sub_aud = any(x in condition_str for x in (":sub", ":aud", "saml:aud", ":oaud"))

                aws_principals = principals_field.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for trusted in aws_principals:
                    is_wildcard = trusted == "*"
                    trusted_account = ""
                    if not is_wildcard:
                        if "arn:aws:iam::" in trusted or "arn:aws:sts::" in trusted:
                            parts = trusted.split(":")
                            if len(parts) > 4:
                                trusted_account = parts[4]
                        elif trusted.isdigit() and len(trusted) == 12:
                            trusted_account = trusted
                    if trusted_account and trusted_account == self.account_id and not is_wildcard:
                        continue

                    if is_wildcard:
                        if not conditions:
                            risk, reason = "critical", "Principal:* with no conditions (any AWS account can assume)"
                        elif has_org_id or has_principal_arn:
                            risk, reason = "medium", "Wildcard principal constrained by org/principal condition"
                        elif external_id_enforced or has_mfa:
                            risk, reason = "high", "Wildcard principal with only ExternalId/MFA (guessable/insufficient)"
                        else:
                            risk, reason = "high", "Wildcard principal with weak/non-enforcing conditions"
                    else:
                        if external_id_enforced or has_mfa or has_org_id or has_principal_arn:
                            risk, reason = "low", "Specific external principal with an enforced protective condition"
                        elif has_external_id and not external_id_enforced:
                            risk, reason = "medium", "ExternalId present but NOT enforced (wildcard/Null/NotEquals) - confused-deputy risk"
                        else:
                            risk, reason = "medium", "Specific external principal, no ExternalId - confused-deputy risk"

                    if target_is_admin and risk in ("medium", "high"):
                        risk = "critical" if risk == "high" or is_wildcard else "high"
                        reason += "; trusted-into role is ADMIN/privileged"

                    trusts.append(CrossAccountTrust(
                        role_arn=arn, role_name=principal.name,
                        trusted_principal=trusted,
                        trusted_account=trusted_account or ("*" if is_wildcard else "unknown"),
                        has_external_id=has_external_id, has_conditions=bool(conditions),
                        is_wildcard=is_wildcard, risk_level=risk,
                        principal_kind="AWS", external_id_enforced=external_id_enforced,
                        target_is_admin=target_is_admin, reason=reason,
                        remediation_key="cross_account_wildcard" if is_wildcard else
                                        ("cross_account_no_external_id" if not external_id_enforced else ""),
                    ))

                fed_principals = principals_field.get("Federated", [])
                if isinstance(fed_principals, str):
                    fed_principals = [fed_principals]
                for fed in fed_principals:
                    fed_l = str(fed).lower()
                    is_oidc = fed_l.startswith("arn:aws:iam::") and ":oidc-provider/" in fed_l
                    is_github = "token.actions.githubusercontent.com" in fed_l
                    is_saml = ":saml-provider/" in fed_l
                    if is_github:
                        if not has_sub_aud:
                            risk = "critical"
                            reason = "GitHub Actions OIDC trust with NO sub/aud constraint - ANY GitHub repo can assume this role"
                        elif ("*" in condition_str) or (":sub" not in condition_str):
                            risk = "high"
                            reason = "GitHub Actions OIDC trust with a wildcard/under-constrained sub (branch/repo scoping too broad)"
                        else:
                            risk = "low"
                            reason = "GitHub Actions OIDC trust scoped to a specific repo/branch via sub"
                    elif is_oidc:
                        risk = "high" if not has_sub_aud else "low"
                        reason = ("OIDC federated trust without sub/aud constraint" if not has_sub_aud
                                  else "OIDC federated trust constrained by sub/aud")
                    elif is_saml:
                        risk = "medium" if "saml:aud" not in condition_str else "low"
                        reason = ("SAML federated trust (verify IdP and saml:aud)" if risk != "low"
                                  else "SAML federated trust with audience restriction")
                    else:
                        risk, reason = "medium", "Federated trust to an external identity provider"
                    if target_is_admin and risk in ("medium", "high"):
                        risk = "critical" if risk == "high" else "high"
                        reason += "; trusted-into role is ADMIN/privileged"
                    trusts.append(CrossAccountTrust(
                        role_arn=arn, role_name=principal.name,
                        trusted_principal=str(fed),
                        trusted_account="federated",
                        has_external_id=False, has_conditions=bool(conditions),
                        is_wildcard=False, risk_level=risk,
                        principal_kind="Federated", external_id_enforced=False,
                        target_is_admin=target_is_admin, reason=reason,
                        remediation_key="federated_oidc",
                    ))

                svc_principals = principals_field.get("Service", [])
                if isinstance(svc_principals, str):
                    svc_principals = [svc_principals]
                for svc in svc_principals:
                    svc_prefix = str(svc).split(".")[0].lower()
                    if svc_prefix not in CONFUSED_DEPUTY_SERVICES:
                        continue
                    if has_source or has_org_id:
                        continue
                    risk = "high" if target_is_admin else "medium"
                    trusts.append(CrossAccountTrust(
                        role_arn=arn, role_name=principal.name,
                        trusted_principal=str(svc),
                        trusted_account="service",
                        has_external_id=False, has_conditions=bool(conditions),
                        is_wildcard=False, risk_level=risk,
                        principal_kind="Service", external_id_enforced=False,
                        target_is_admin=target_is_admin,
                        reason=f"Service trust ({svc}) can act on behalf of other resources but is missing aws:SourceArn/aws:SourceAccount - cross-service confused-deputy risk",
                        remediation_key="service_confused_deputy",
                    ))

        return sorted(trusts, key=lambda t:
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(t.risk_level, 4))

    _EVIDENCE_PRIORITY = [
        "*", "iam:*", "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
        "iam:PutRolePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey", "iam:AddUserToGroup",
        "iam:PassRole", "sts:AssumeRole", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
        "ec2:RunInstances", "cloudformation:CreateStack", "codebuild:CreateProject",
        "secretsmanager:GetSecretValue", "ssm:GetParameter",
    ]

    def _principal_evidence(self, p: Principal, limit: int = 6) -> List[Dict]:
        """Concrete per-principal evidence: which policy/statement grants each dangerous
        action. This is what a report needs ('what exactly is the issue')."""
        ev = getattr(p, "action_evidence", {}) or {}
        ordered = [a for a in self._EVIDENCE_PRIORITY if a in ev]
        ordered += [a for a in sorted(ev) if a not in ordered]
        out = []
        for a in ordered[:limit]:
            e = ev[a]
            out.append({
                "action": a,
                "policy": e.get("policy", ""),
                "policy_name": e.get("policy_name", ""),
                "source": e.get("source", "attached"),
                "sid": e.get("sid", ""),
                "resources": e.get("resources", ["*"]),
                "conditional": e.get("conditions", False),
            })
        return out

    def _generate_findings(self, analysis: AccountAnalysis) -> List[Finding]:
        """Generate structured findings from analysis results."""
        findings = []

        explicit_admins = [p for arn, p in self.principals.items()
                         if p.is_admin and not self._is_aws_managed(p.name)]
        total_admins = len(self.admins)
        managed_admin_count = total_admins - len(explicit_admins)
        if explicit_admins:
            findings.append(Finding(
                id=f"{self.account_id}_admin_access",
                title="Principals with Administrator Access",
                severity="critical",
                category="iam",
                description=(f"These {len(explicit_admins)} principals have full administrative access to all AWS "
                            f"services. (The account has {total_admins} administrative principals in total; the "
                            f"other {managed_admin_count} are AWS-managed/service roles reported separately below.)"),
                principals=[p.arn for p in explicit_admins],
                impact="Compromise of any of these credentials results in full account takeover.",
                remediation="Review each admin principal. Replace AdministratorAccess with AWS managed job-function policies (PowerUserAccess, SystemAdministrator, etc.). "
                           "Use IAM Access Analyzer to generate least-privilege policies based on actual access patterns. Enable MFA for all admin accounts. "
                           "Consider using AWS IAM Identity Center for centralized access management.",
                details={
                    "principals_detail": [
                        {"arn": p.arn, "name": p.name, "type": p.principal_type}
                        for p in explicit_admins
                    ]
                },
            ))

        if analysis.aws_managed_admins:
            findings.append(Finding(
                id=f"{self.account_id}_aws_managed_admin",
                title="Default AWS Managed Roles",
                severity="medium",
                category="iam",
                description="These AWS-managed roles were identified as administrative principals. "
                           "They are created by AWS services such as Control Tower, StackSets, and SSO. "
                           "While expected to be privileged, verify access is appropriately restricted.",
                principals=[p.arn for p in analysis.aws_managed_admins],
                impact="AWS managed roles carry elevated permissions by design. Review trust policies "
                      "to confirm access is restricted to authorized principals only.",
                remediation="Verify trust policies restrict access to legitimate principals. Use IAM Access Analyzer to identify external access. "
                           "Consider using SCPs to limit actions even for managed roles.",
                details={
                    "principals_detail": [
                        {"arn": p.arn, "name": p.name, "managed": True}
                        for p in analysis.aws_managed_admins
                    ]
                },
            ))

        if analysis.shadow_admins:
            shadow_details = []
            for p in analysis.shadow_admins:
                dangerous_actions = sorted(p.dangerous_actions)[:20] if p.dangerous_actions else []
                shadow_details.append({
                    "arn": p.arn,
                    "name": p.name,
                    "id_value": p.id_value,
                    "policies": p.policies[:10],
                    "dangerous_actions": dangerous_actions,
                    "capabilities": p.capabilities[:10],
                    "evidence": self._principal_evidence(p),
                    "boundary_capped": p.boundary_capped,
                    "has_notaction": p.has_notaction,
                    "unresolved_managed": p.unresolved_managed,
                    "capability_groups": [
                        {"group": g[0], "severity": g[1], "count": len(g[2])}
                        for g in p.capability_groups
                    ],
                })

            findings.append(Finding(
                id=f"{self.account_id}_shadow_admin",
                title="Shadow Administrators",
                severity="critical",
                category="iam",
                description="These principals can escalate to admin privileges without having "
                           "AdministratorAccess policy attached, making them invisible to standard IAM audits.",
                principals=[p.arn for p in analysis.shadow_admins],
                impact="Hidden administrative access that bypasses standard security reviews.",
                remediation="Remove excessive permissions that enable privilege escalation. "
                           "Implement IAM permissions boundaries to cap maximum permissions. "
                           "Use AWS Organizations SCPs/RCPs for organization-wide guardrails. "
                           "Review with IAM Access Analyzer policy validation.",
                details={"principals_detail": shadow_details},
            ))

        if analysis.overly_permissive:
            op_details = []
            for p in analysis.overly_permissive[:20]:
                has_critical = any(g[1] == "critical" for g in p.capability_groups)
                has_high = any(g[1] == "high" for g in p.capability_groups)
                sev = "critical" if has_critical else "high" if has_high else "medium"

                dangerous_actions = sorted(p.dangerous_actions)[:20] if p.dangerous_actions else []
                op_details.append({
                    "arn": p.arn,
                    "name": p.name,
                    "type": p.principal_type,
                    "id_value": p.id_value,
                    "severity": sev,
                    "policies": p.policies[:10],
                    "dangerous_actions": dangerous_actions,
                    "capabilities": p.capabilities[:8],
                    "evidence": self._principal_evidence(p),
                    "boundary_capped": p.boundary_capped,
                    "has_notaction": p.has_notaction,
                    "unresolved_managed": p.unresolved_managed,
                    "capability_groups": [
                        {"group": g[0], "severity": g[1], "actions": g[2][:5]}
                        for g in p.capability_groups
                    ],
                })

            findings.append(Finding(
                id=f"{self.account_id}_overly_permissive",
                title="Overly Permissive IAM Principals",
                severity="high",
                category="iam",
                description="These principals have permissions significantly broader than required, "
                           "excluding those already reported as administrators or shadow admins.",
                principals=[p.arn for p in analysis.overly_permissive[:20]],
                impact="Increased blast radius in case of credential compromise. "
                      "Each principal has dangerous capabilities listed below.",
                remediation="Apply least-privilege principles per AWS best practices. Use IAM Access Analyzer to "
                           "validate policies and generate least-privilege policies based on access activity. "
                           "Use last accessed information to identify unused permissions. "
                           "Implement permissions boundaries for delegated administration.",
                details={
                    "total_count": len(analysis.overly_permissive),
                    "principals_detail": op_details,
                },
            ))

        risky_trusts = [t for t in analysis.cross_account_trusts
                       if t.risk_level in ("critical", "high")]
        if risky_trusts:
            kinds = sorted(set(t.principal_kind for t in risky_trusts))
            findings.append(Finding(
                id=f"{self.account_id}_cross_account_trust",
                title="Risky Trust Relationships (Cross-Account / Federated / Service)",
                severity="critical" if any(t.risk_level == "critical" for t in risky_trusts) else "high",
                category="trust",
                description="These role trust policies allow assumption from external or under-constrained "
                           "principals: cross-account AWS principals, federated identity providers "
                           "(SAML/OIDC, e.g. GitHub Actions), or AWS services without SourceArn/SourceAccount. "
                           f"Trust kinds present: {', '.join(kinds)}.",
                principals=[t.role_arn for t in risky_trusts],
                impact="External or under-constrained principals may assume these roles. Where the role is "
                      "itself admin/privileged, this is a direct external path to account compromise.",
                remediation="AWS principals: replace Principal:'*' with specific ARNs and add an ENFORCED "
                           "sts:ExternalId (StringEquals with a secret value) or aws:PrincipalOrgID. "
                           "Federated/OIDC: constrain the sub/aud (for GitHub Actions pin repo:ORG/REPO:ref:...). "
                           "Service trusts: add aws:SourceArn/aws:SourceAccount to prevent confused-deputy abuse.",
                details={"trusts": [asdict(t) for t in risky_trusts]},
            ))

        if analysis.credential_hygiene:
            worst = "high" if any(c["severity"] == "high" for c in analysis.credential_hygiene) else \
                    "medium" if any(c["severity"] == "medium" for c in analysis.credential_hygiene) else "low"
            findings.append(Finding(
                id=f"{self.account_id}_credential_hygiene",
                title="IAM Credential Hygiene (MFA / Access Keys)",
                severity=worst,
                category="credential_hygiene",
                description="IAM users with weak credential hygiene: console access without MFA and/or "
                           "long-lived access keys. These are the most common root causes of real cloud "
                           "account compromise and are core CIS AWS Foundations checks.",
                principals=[c["arn"] for c in analysis.credential_hygiene],
                impact="A phished password without MFA, or a leaked static access key, grants an attacker the "
                      "user's full permission set. Privileged users without MFA are the highest priority.",
                remediation="Enforce MFA for all IAM users with console access (SCP/permission-boundary deny "
                           "when aws:MultiFactorAuthPresent is false). Replace long-term access keys with "
                           "short-lived credentials (IAM Identity Center / roles); rotate or delete unused keys.",
                details={"issues": analysis.credential_hygiene},
            ))

        critical_paths = [p for p in analysis.escalation_paths if p.severity == "critical"]
        if critical_paths:
            findings.append(Finding(
                id=f"{self.account_id}_privesc_critical",
                title="Critical Privilege Escalation Paths",
                severity="critical",
                category="privesc",
                description=f"Found {len(critical_paths)} paths where non-admin principals can "
                           "escalate to full administrative access.",
                principals=sorted(set(p.source.arn for p in critical_paths[:20])),
                impact="Attackers with access to these principals can gain full account control.",
                remediation="Remove or restrict permissions that enable escalation. Use permissions boundaries to limit maximum permissions. "
                           "Common fixes include: restricting iam:PassRole to specific roles, "
                           "adding resource conditions to sts:AssumeRole, limiting ec2:RunInstances.",
                details={
                    "path_count": len(critical_paths),
                    "techniques": sorted(set(p.technique for p in critical_paths)),
                },
            ))

        return findings

    def _is_aws_managed(self, name: str) -> bool:
        """Check if name matches AWS-managed resource patterns."""
        return any(re.search(p, name) for p in AWS_MANAGED_PATTERNS)
