"""Core IAM security analysis engine: effective-permission evaluation, shadow-admin and privesc detection, trust analysis and credential hygiene."""

import json
import re
from collections import defaultdict
from dataclasses import asdict
from fnmatch import fnmatchcase
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
        """Find service-linked roles that are admins (expected but worth noting)."""
        managed = []
        for arn, principal in self.principals.items():
            if principal.is_admin and self._is_aws_managed(principal):
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
        pattern = str(action).lower()
        return {candidate for candidate in DANGEROUS_ACTIONS
                if fnmatchcase(candidate.lower(), pattern)}

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
        """Compute a conservative inventory of potentially dangerous actions.

        Honors: Allow/Deny (broad unconditional Deny subtracts), NotAction, inline and
        group-inherited policies, the AdministratorAccess/managed-policy catalog, the
        is_admin flag, and permissions boundaries (intersection when resolvable, else a
        'boundary_capped' flag). Records per-action evidence for reporting.
        """
        for arn, principal in self.principals.items():
            allow = {}
            allow_candidates = defaultdict(list)
            deny = set()
            principal.boundary_capped = False

            for pol, source in self._effective_policies(principal):
                for stmt in pol.statements:
                    if stmt.effect.lower() == "allow":
                        if stmt.not_actions:
                            principal.has_notaction = True
                        covered = self._dangerous_covered_by_statement(stmt)
                        for a in covered:
                            item = {
                                "policy": pol.arn,
                                "policy_name": pol.name,
                                "source": source,
                                "sid": stmt.sid,
                                "resources": list(stmt.resources) or (["<NotResource>"] if stmt.not_resources else ["*"]),
                                "conditions": stmt.conditions,
                            }
                            allow_candidates[a].append(item)
                            allow.setdefault(a, item)
                    elif stmt.effect.lower() == "deny":
                        # Deny+NotResource still leaves the excluded resources usable, so it
                        # cannot remove the action globally from this resource-agnostic set.
                        broad = (("*" in stmt.resources) or (not stmt.resources)) and not stmt.not_resources
                        if broad and not stmt.conditions:
                            deny |= self._dangerous_covered_by_statement(stmt)

            if principal.is_admin:
                for a in DANGEROUS_ACTIONS:
                    item = {
                        "policy": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "policy_name": "AdministratorAccess",
                        "source": "admin", "sid": "", "resources": ["*"], "conditions": {},
                    }
                    allow.setdefault(a, item)
                    allow_candidates[a].append(item)

            dangerous = set(allow) - deny

            if principal.permissions_boundary:
                bpol = self.policies.get(principal.permissions_boundary)
                bacts = None
                if bpol:
                    allow_statements = []
                    bdeny = set()
                    for stmt in bpol.statements:
                        if stmt.effect.lower() == "allow":
                            allow_statements.append(stmt)
                        elif stmt.effect.lower() == "deny":
                            broad = (("*" in stmt.resources) or (not stmt.resources)) and not stmt.not_resources
                            if broad and not stmt.conditions:
                                bdeny |= self._dangerous_covered_by_statement(stmt)
                    bacts = set()
                    for action in dangerous - bdeny:
                        for evidence in allow_candidates.get(action, []):
                            if any(
                                action in self._dangerous_covered_by_statement(stmt)
                                and self._resource_patterns_overlap(evidence.get("resources", ["*"]), stmt.resources)
                                for stmt in allow_statements
                            ):
                                bacts.add(action)
                                allow[action] = evidence
                                break
                else:
                    resolved = resolve_managed_policy_actions(principal.permissions_boundary)
                    if resolved is None:
                        bacts = None
                    else:
                        bacts = set()
                        for action_pattern in resolved:
                            bacts |= self._expand_action(action_pattern)
                if bacts is not None:
                    dangerous &= bacts
                else:
                    # The boundary exists but its body could not be resolved, so
                    # remaining capability results are intentionally caveated.
                    principal.boundary_capped = True

            principal.dangerous_actions = dangerous
            principal.action_evidence = {a: allow[a] for a in dangerous if a in allow}

            groups = self._classify_capabilities(dangerous)
            principal.capability_groups = groups

            principal.capabilities = [
                CHECK_LABEL.get(action, action)
                for action in sorted(dangerous)
                if action in CHECK_LABEL
            ]

    @staticmethod
    def _resource_patterns_overlap(identity_resources: List[str], boundary_resources: List[str]) -> bool:
        """Return whether two positive Resource pattern sets can select a common ARN.

        NotResource cannot be represented by the evidence summary, so it remains a
        conservative possible match rather than being incorrectly eliminated.
        """
        left = identity_resources or ["*"]
        right = boundary_resources or ["*"]
        if "<NotResource>" in left:
            return True
        for identity_pattern in left:
            for boundary_pattern in right:
                if identity_pattern == "*" or boundary_pattern == "*":
                    return True
                if fnmatchcase(identity_pattern, boundary_pattern) or fnmatchcase(boundary_pattern, identity_pattern):
                    return True
        return False

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
                # A collection of specific IAM actions is not proof of iam:*.
                groups.append(("IAM (broad tracked set)", "high", sorted(iam_actions)))
            else:
                groups.append(("IAM (specific)", "high", sorted(iam_actions)))

        if s3_actions:
            # The inventory only tracks selected high-impact S3 actions. Even all of
            # them together is not proof that the policy grants s3:*.
            label = "S3 (all tracked actions)" if s3_actions >= S3_CHECKS else "S3 (partial)"
            groups.append((label, "high", sorted(s3_actions)))

        if cred_actions:
            groups.append(("Credential Access", "high", sorted(cred_actions)))

        if compute_actions:
            groups.append(("Service Compute Abuse", "high", sorted(compute_actions)))

        if evasion_actions:
            groups.append(("Defense Evasion", "medium", sorted(evasion_actions)))

        return groups

    def _find_shadow_admins(self) -> List[Principal]:
        """Find non-admin principals with a PMapper-proven direct edge to admin.

        Permission combinations alone are intentionally not promoted to shadow-admin:
        exploitable IAM and PassRole techniques depend on the target, trust policy,
        service conditions, and supporting permissions. PMapper's edge is the proof.
        """
        shadow = []

        for arn, principal in self.principals.items():
            if principal.is_admin:
                continue
            if self._is_aws_managed(principal):
                continue

            if any(edge.target in self.admins for edge in self.edge_from.get(arn, [])):
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

        Excludes admins, AWS service-linked roles, and (per the finding's own description)
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
            if self._is_aws_managed(principal):
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

        # action_evidence is built from every effective source: direct, inline,
        # group-inherited, and resolved AWS-managed policies. Using it here keeps
        # finding classification aligned with the effective-permission result.
        for action in principal.dangerous_actions:
            evidence = principal.action_evidence.get(action, {})
            base_score = 4 if action in escalation_actions else 2
            resources = evidence.get("resources", ["*"])
            if "*" not in resources:
                base_score = max(1, base_score - 1)
            if evidence.get("conditions"):
                base_score = max(1, base_score - 1)
            score += base_score

        return score

    def _find_escalation_paths(self) -> List[EscalationPath]:
        """Find and analyze all privilege escalation paths."""
        paths = []

        for arn, principal in self.principals.items():
            if principal.is_admin:
                continue
            if self._is_aws_managed(principal):
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
        queue = [(start_arn, [], {start_arn})]

        while queue:
            current, path, visited = queue.pop(0)

            for edge in self.edge_from.get(current, []):
                if edge.target in visited:
                    continue

                new_path = path + [edge]

                if edge.target in self.admins:
                    results.append((edge.target, new_path))
                elif len(new_path) < 5:
                    queue.append((edge.target, new_path, visited | {edge.target}))

        return results

    def _classify_technique(self, hops: List[Edge]) -> str:
        """Classify escalation technique based on edge reasons."""
        if not hops:
            return "Unknown"

        combined_reason = " ".join(f"{h.short_reason} {h.reason}" for h in hops)

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
        path.hop_explanations = self._build_hop_explanations(path)
        path.resulting_access = self._describe_resulting_access(path)
        path.missing_prerequisites = self._find_missing_prerequisites(path)
        path.evidence_status = (
            "required-local-evidence-present"
            if not path.missing_prerequisites else "incomplete-local-evidence"
        )
        path.validation_notes = self._build_path_validation_notes(path)

    def _generate_attack_narrative(self, path: EscalationPath) -> str:
        """Generate a human-readable attack narrative for the escalation path."""
        source_type = path.source.principal_type
        source_name = path.source.name
        target_name = path.target.name

        if source_type == "user":
            narrative = f"The graph indicates that an attacker who compromises the IAM user '{source_name}'"
            if path.source.has_access_keys:
                narrative += " (which has active access keys)"
        elif source_type == "role":
            narrative = f"The graph indicates that an attacker who can assume the role '{source_name}'"
        else:
            narrative = f"The graph indicates that an attacker with access to '{source_name}'"

        if len(path.hops) == 1:
            hop = path.hops[0]
            narrative += f" can directly escalate to '{target_name}' by exploiting: {hop.reason}."
        else:
            narrative += " can escalate through a multi-step attack chain:\n"
            for i, hop in enumerate(path.hops, 1):
                hop_target = hop.target.split("/")[-1] if "/" in hop.target else hop.target.split(":")[-1]
                narrative += f"  {i}. {hop.reason} -> {hop_target}\n"

        if path.target.is_admin:
            narrative += "\nIf the modeled steps remain valid in the live request context, this results in full administrative access to the AWS account, "
            narrative += "allowing the attacker to access all resources, exfiltrate data, "
            narrative += "create backdoors, and disable security controls."

        return narrative

    @staticmethod
    def _list_value(value: Any) -> List[Any]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def _trust_evidence(self, target: Optional[Principal], mechanism: str,
                        source_arn: str) -> List[Dict[str, Any]]:
        """Return relevant role-trust statements without claiming live authorization."""
        if not target or not isinstance(target.trust_policy, dict):
            return []
        statements = self._list_value(target.trust_policy.get("Statement", []))
        evidence = []
        for statement in statements:
            if not isinstance(statement, dict) or statement.get("Effect", "").lower() != "allow":
                continue
            actions = [str(a) for a in self._list_value(statement.get("Action", []))]
            if not any(fnmatchcase("sts:AssumeRole".lower(), a.lower()) for a in actions):
                continue
            principal = statement.get("Principal", {})
            service_principal = {
                "Lambda CreateFunction": "lambda.amazonaws.com",
                "EC2 Instance Profile": "ec2.amazonaws.com",
            }.get(mechanism)
            if service_principal:
                services = self._list_value(principal.get("Service", [])) if isinstance(principal, dict) else []
                if service_principal not in services:
                    continue
            else:
                aws_principals = self._list_value(principal.get("AWS", [])) if isinstance(principal, dict) else self._list_value(principal)
                source_parts = source_arn.split(":")
                source_account = source_parts[4] if len(source_parts) > 4 else ""
                partition = source_parts[1] if len(source_parts) > 1 else "aws"
                relevant = any(
                    str(value) in {"*", source_arn, f"arn:{partition}:iam::{source_account}:root"}
                    for value in aws_principals
                )
                if not relevant:
                    continue
            evidence.append({
                "effect": "Allow",
                "actions": actions,
                "principal": principal,
                "conditions": statement.get("Condition", {}),
            })
        return evidence

    def _policy_evidence(self, principal: Optional[Principal], actions: List[str],
                         target_arn: str) -> List[Dict[str, Any]]:
        if not principal:
            return []
        evidence = []
        for action in actions:
            if action not in principal.dangerous_actions:
                continue
            target_scoped = action in {"sts:AssumeRole", "iam:PassRole"}
            for policy, source in self._effective_policies(principal):
                for statement in policy.statements:
                    if statement.effect.lower() != "allow" or action not in self._dangerous_covered_by_statement(statement):
                        continue
                    if target_scoped:
                        resources = statement.resources or ["*"]
                        if not any(fnmatchcase(target_arn, resource) for resource in resources):
                            continue
                        if any(fnmatchcase(target_arn, excluded) for excluded in statement.not_resources):
                            continue
                    evidence.append({
                        "action": action,
                        "policy_name": policy.name,
                        "policy_arn": policy.arn,
                        "attachment_source": source,
                        "sid": statement.sid,
                        "resources": list(statement.resources) or (["<NotResource>"] if statement.not_resources else ["*"]),
                        "not_resources": list(statement.not_resources),
                        "conditions": statement.conditions,
                    })
        return evidence

    def _build_hop_explanations(self, path: EscalationPath) -> List[Dict[str, Any]]:
        explanations = []
        for step, hop in enumerate(path.hops, 1):
            source = self.principals.get(hop.source)
            target = self.principals.get(hop.target)
            mechanism = self._classify_technique([hop])
            if mechanism == "Direct STS AssumeRole":
                actions = ["sts:AssumeRole"]
                access = (
                    f"A successful AssumeRole call returns a role session with the permissions of "
                    f"'{target.name if target else hop.target}', subject to all applicable limits."
                )
                why = (
                    "PMapper generated an STS access edge. The call requires authorization to "
                    "sts:AssumeRole and a compatible target role trust policy."
                )
            elif mechanism == "Lambda CreateFunction":
                actions = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
                access = (
                    f"Code that is successfully run by Lambda uses the execution-role credentials "
                    f"and permissions of '{target.name if target else hop.target}'."
                )
                why = (
                    "PMapper generated a Lambda edge. A usable path requires permission to pass this "
                    "specific execution role, create/configure a function, cause it to run, and a target "
                    "trust policy that permits lambda.amazonaws.com."
                )
            elif mechanism == "EC2 Instance Profile":
                actions = ["iam:PassRole", "ec2:RunInstances"]
                access = "Workloads launched with the instance profile can obtain the target role's credentials through IMDS."
                why = "PMapper generated an EC2 edge based on PassRole and workload-launch capability."
            else:
                actions = []
                access = f"The modeled edge reaches '{target.name if target else hop.target}'."
                why = "PMapper generated this access edge from the exported IAM relationship."

            policy_evidence = self._policy_evidence(source, actions, hop.target)
            trust_evidence = self._trust_evidence(target, mechanism, hop.source)
            if not policy_evidence:
                why += " No matching retained identity-policy statement was found, so the graph edge is the only local proof and must be checked live."

            explanations.append({
                "step": step,
                "source": hop.source,
                "target": hop.target,
                "mechanism": mechanism,
                "why": why,
                "graph_evidence": {"reason": hop.reason, "short_reason": hop.short_reason},
                "identity_policy_evidence": policy_evidence,
                "target_trust_evidence": trust_evidence,
                "access_gained": access,
            })
        return explanations

    @staticmethod
    def _describe_resulting_access(path: EscalationPath) -> str:
        context = "role session or service execution context"
        if path.target.is_admin:
            return (
                f"If every hop succeeds, the source reaches the administrative {context} "
                f"'{path.target.name}'. This is modeled account-administrator access, not proof that "
                "a live request will succeed."
            )
        return f"If every hop succeeds, the source reaches {context} '{path.target.name}'."

    @staticmethod
    def _find_missing_prerequisites(path: EscalationPath) -> List[str]:
        missing = []
        for hop in path.hop_explanations:
            actions = {item.get("action") for item in hop.get("identity_policy_evidence", [])}
            mechanism = hop.get("mechanism")
            if mechanism == "Direct STS AssumeRole":
                if "sts:AssumeRole" not in actions:
                    missing.append(f"Step {hop['step']}: no target-scoped sts:AssumeRole Allow was retained.")
                if not hop.get("target_trust_evidence"):
                    missing.append(f"Step {hop['step']}: no relevant target role trust statement was extracted.")
            elif mechanism == "Lambda CreateFunction":
                for action in ("iam:PassRole", "lambda:CreateFunction"):
                    if action not in actions:
                        missing.append(f"Step {hop['step']}: no applicable {action} Allow was retained.")
                if "lambda:InvokeFunction" not in actions:
                    missing.append(
                        f"Step {hop['step']}: no InvokeFunction Allow was retained; prove another permitted trigger can run the function."
                    )
                if not hop.get("target_trust_evidence"):
                    missing.append(f"Step {hop['step']}: no Lambda service trust statement was extracted from the target role.")
            elif mechanism == "EC2 Instance Profile":
                for action in ("iam:PassRole", "ec2:RunInstances"):
                    if action not in actions:
                        missing.append(f"Step {hop['step']}: no applicable {action} Allow was retained.")
                if not hop.get("target_trust_evidence"):
                    missing.append(f"Step {hop['step']}: no EC2 service trust statement was extracted from the target role.")
            else:
                missing.append(
                    f"Step {hop['step']}: technique-specific prerequisites are not parsed; rely on the PMapper edge only after live validation."
                )
        return missing

    @staticmethod
    def _build_path_validation_notes(path: EscalationPath) -> List[str]:
        notes = [
            "Confirm the source credentials/session are usable and each referenced principal and resource still exists.",
            "Evaluate SCPs, permissions boundaries, session policies, resource policies and all request-time conditions for every hop.",
            "Treat the PMapper edge as static authorization evidence; validate with read-only simulation or an explicitly authorized test before reporting exploitability.",
        ]
        if any((e.get("conditions") or {}) for hop in path.hop_explanations
               for e in hop.get("identity_policy_evidence", [])):
            notes.append("At least one identity-policy Allow is conditional; the displayed condition must match the real request context.")
        if any(hop.get("mechanism") == "Lambda CreateFunction" for hop in path.hop_explanations):
            notes.append("For Lambda, confirm iam:PassedToService/resource scoping, execution-role trust, and a permitted trigger or InvokeFunction path.")
        if len(path.hops) > 1:
            notes.append("For this multi-hop route, repeat the authorization check from each newly obtained role session to the next target.")
        return notes

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

    @staticmethod
    def _positive_condition_values(conditions: Dict, key_suffix: str, *, allow_like: bool = False) -> List[str]:
        """Return values only from positive operators that can narrow a request."""
        values = []
        for operator, entries in (conditions or {}).items():
            if not isinstance(entries, dict):
                continue
            op = operator.lower().split(":")[-1]
            positive = op in {"stringequals", "arnequals", "bool"} or (allow_like and op in {"stringlike", "arnlike"})
            if not positive:
                continue
            for key, value in entries.items():
                if key.lower().endswith(key_suffix.lower()):
                    values.extend(str(v) for v in (value if isinstance(value, list) else [value]))
        return values

    @classmethod
    def _exact_condition_enforced(cls, conditions: Dict, key_suffix: str) -> bool:
        values = cls._positive_condition_values(conditions, key_suffix)
        return bool(values) and all(v and "*" not in v and "?" not in v for v in values)

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

            target_is_admin = principal.is_admin
            target_is_privileged = target_is_admin or bool(principal.dangerous_actions)

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
                source_accounts = self._positive_condition_values(conditions, "aws:sourceaccount")
                source_arns = self._positive_condition_values(conditions, "aws:sourcearn", allow_like=True)
                has_source = (bool(source_accounts) and all(v.isdigit() and len(v) == 12 for v in source_accounts)) or \
                    (bool(source_arns) and all(v.startswith("arn:") and not v.startswith("arn:*") for v in source_arns))
                has_org_id = self._exact_condition_enforced(conditions, "aws:principalorgid")
                has_principal_arn = self._exact_condition_enforced(conditions, "aws:principalarn")
                mfa_values = self._positive_condition_values(conditions, "aws:multifactorauthpresent")
                has_mfa = bool(mfa_values) and all(v.lower() == "true" for v in mfa_values)
                sub_values = self._positive_condition_values(conditions, ":sub", allow_like=True)
                aud_values = (self._positive_condition_values(conditions, ":aud") +
                              self._positive_condition_values(conditions, ":oaud") +
                              self._positive_condition_values(conditions, "saml:aud"))
                has_sub = bool(sub_values)
                has_aud = bool(aud_values)

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
                            risk, reason = "medium", "Specific external principal without an ExternalId (verify whether this is an owned or third-party account)"

                    if target_is_privileged and risk in ("medium", "high"):
                        risk = "critical" if target_is_admin and (risk == "high" or is_wildcard) else "high"
                        reason += ("; trusted-into role is ADMIN" if target_is_admin
                                   else "; trusted-into role has dangerous permissions")

                    trusts.append(CrossAccountTrust(
                        role_arn=arn, role_name=principal.name,
                        trusted_principal=trusted,
                        trusted_account=trusted_account or ("*" if is_wildcard else "unknown"),
                        has_external_id=has_external_id, has_conditions=bool(conditions),
                        is_wildcard=is_wildcard, risk_level=risk,
                        principal_kind="AWS", external_id_enforced=external_id_enforced,
                        target_is_admin=target_is_admin, target_is_privileged=target_is_privileged,
                        reason=reason,
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
                        github_aud = bool(aud_values) and all(v == "sts.amazonaws.com" for v in aud_values)
                        if not has_sub and not github_aud:
                            risk = "critical"
                            reason = "GitHub Actions OIDC trust with NO sub/aud constraint - ANY GitHub repo can assume this role"
                        elif not has_sub or not github_aud or any(v in {"*", "repo:*"} or v.startswith("repo:*/") for v in sub_values):
                            risk = "high"
                            reason = "GitHub Actions OIDC trust with missing/under-constrained positive sub or aud restriction"
                        else:
                            risk = "low"
                            reason = "GitHub Actions OIDC trust scoped to a specific repo/branch via sub"
                    elif is_oidc:
                        risk = "high" if not (has_sub and has_aud) else "low"
                        reason = ("OIDC federated trust without positive sub and aud constraints" if risk == "high"
                                  else "OIDC federated trust constrained by sub/aud")
                    elif is_saml:
                        risk = "medium" if not self._exact_condition_enforced(conditions, "saml:aud") else "low"
                        reason = ("SAML federated trust (verify IdP and saml:aud)" if risk != "low"
                                  else "SAML federated trust with audience restriction")
                    else:
                        risk, reason = "medium", "Federated trust to an external identity provider"
                    if target_is_privileged and risk in ("medium", "high"):
                        risk = "critical" if target_is_admin and risk == "high" else "high"
                        reason += ("; trusted-into role is ADMIN" if target_is_admin
                                   else "; trusted-into role has dangerous permissions")
                    trusts.append(CrossAccountTrust(
                        role_arn=arn, role_name=principal.name,
                        trusted_principal=str(fed),
                        trusted_account="federated",
                        has_external_id=False, has_conditions=bool(conditions),
                        is_wildcard=False, risk_level=risk,
                        principal_kind="Federated", external_id_enforced=False,
                        target_is_admin=target_is_admin, target_is_privileged=target_is_privileged,
                        reason=reason,
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
                    risk = "high" if target_is_privileged else "medium"
                    trusts.append(CrossAccountTrust(
                        role_arn=arn, role_name=principal.name,
                        trusted_principal=str(svc),
                        trusted_account="service",
                        has_external_id=False, has_conditions=bool(conditions),
                        is_wildcard=False, risk_level=risk,
                        principal_kind="Service", external_id_enforced=False,
                        target_is_admin=target_is_admin, target_is_privileged=target_is_privileged,
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

    @staticmethod
    def _permission_explanation(action: str, resources: List[str], conditions: Any) -> str:
        """Describe what the collected statement proves without inventing prerequisites."""
        scope = "all resources supported by the action" if "*" in resources else \
            f"the listed resource scope ({', '.join(resources[:2])}{' ...' if len(resources) > 2 else ''})"
        caveat = " The statement is conditional; the shown condition must match at request time." if conditions else ""
        if action == "iam:PassRole":
            meaning = (f"Can pass {scope} to a compatible AWS service. This is not role assumption by itself; "
                       "an allowed service API and a service trust relationship are also required.")
        elif action.startswith("sts:AssumeRole"):
            meaning = (f"The identity policy permits an STS role-assumption request against {scope}. "
                       "The target role trust policy and any organization controls must also allow it.")
        elif action.startswith("iam:Attach") or action.startswith("iam:Put"):
            meaning = (f"Can modify permissions on {scope}. Escalation is possible only when that scope includes "
                       "a usable identity and the requested policy operation is otherwise allowed.")
        elif action in {"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"}:
            meaning = (f"Can alter the effective version of {scope}. Impact depends on where that managed policy "
                       "is attached and whether version limits and other controls permit the change.")
        elif action in {"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:AddUserToGroup"}:
            meaning = f"Can change credentials or membership for {scope}; this can provide access equal to the affected identity or group."
        elif action in {"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "kms:Decrypt", "s3:GetObject"}:
            meaning = f"Can read sensitive data from {scope}; resource policies, KMS authorization, and request context may further restrict access."
        elif action.startswith(("lambda:", "ec2:", "codebuild:", "cloudformation:", "glue:", "ecs:", "sagemaker:")):
            meaning = (f"Can invoke or modify compute/deployment functionality in {scope}. Privilege escalation additionally "
                       "requires a usable execution role or an already privileged target and any supporting actions.")
        else:
            meaning = f"The collected identity-policy statement allows {action} against {scope}, subject to AWS's complete authorization evaluation."
        return meaning + caveat

    @staticmethod
    def _validation_commands(p: Principal, evidence: List[Dict]) -> List[str]:
        """Produce non-mutating, AWS CLI-valid commands tied to the actual evidence."""
        commands = []
        for item in evidence[:3]:
            resources = item.get("resources") or ["*"]
            resource = next((r for r in resources if r != "<NotResource>"), "*")
            commands.append(
                "aws iam simulate-principal-policy "
                f"--policy-source-arn '{p.arn}' --action-names '{item['action']}' "
                f"--resource-arns '{resource}'"
            )
        entity_flag = "--role-name" if p.principal_type == "role" else "--user-name"
        commands.append(f"aws iam list-attached-{p.principal_type}-policies {entity_flag} '{p.name}'")
        commands.append(f"aws iam list-{p.principal_type}-policies {entity_flag} '{p.name}'")
        commands.append(f"aws iam generate-service-last-accessed-details --arn '{p.arn}'")
        return commands

    def _principal_evidence(self, p: Principal, limit: int = 10) -> List[Dict]:
        """Concrete per-principal evidence: which policy/statement grants each dangerous
        action. This is what a report needs ('what exactly is the issue')."""
        ev = getattr(p, "action_evidence", {}) or {}
        ordered = [a for a in self._EVIDENCE_PRIORITY if a in ev]
        ordered += [a for a in sorted(ev) if a not in ordered]
        out = []
        for a in ordered[:limit]:
            e = ev[a]
            resources = e.get("resources", ["*"])
            conditions = e.get("conditions", {})
            out.append({
                "action": a,
                "policy": e.get("policy", ""),
                "policy_name": e.get("policy_name", ""),
                "source": e.get("source", "attached"),
                "sid": e.get("sid", ""),
                "resources": resources,
                "conditions": conditions,
                "conditional": bool(conditions),
                "explanation": self._permission_explanation(a, resources, conditions),
            })
        return out

    def _generate_findings(self, analysis: AccountAnalysis) -> List[Finding]:
        """Generate structured findings from analysis results."""
        findings = []

        explicit_admins = [p for arn, p in self.principals.items()
                         if p.is_admin and not self._is_aws_managed(p)]
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
                remediation="Review each admin principal and replace standing broad access with customer-managed least-privilege policies where practical. "
                           "Use IAM Access Analyzer and CloudTrail activity to inform policy reduction. Require MFA for human administrative access. "
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
                    "permissions_boundary": p.permissions_boundary,
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
                description="The PMapper graph contains a direct access edge from each principal to an "
                           "administrative principal even though AdministratorAccess is not attached directly. "
                           "Validate runtime conditions and organization guardrails before reporting exploitation.",
                principals=[p.arn for p in analysis.shadow_admins],
                impact="If the modeled edge remains valid at runtime, compromise of the source principal can lead to administrative access.",
                remediation="Remove or scope the policy/trust relationship that creates the proven edge. "
                           "Use permissions boundaries and AWS Organizations SCPs/RCPs as additional guardrails, not as a substitute for removing unintended access. "
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
                evidence = self._principal_evidence(p)
                op_details.append({
                    "arn": p.arn,
                    "name": p.name,
                    "type": p.principal_type,
                    "id_value": p.id_value,
                    "severity": sev,
                    "policies": p.policies[:10],
                    "dangerous_actions": dangerous_actions,
                    "capabilities": p.capabilities[:8],
                    "evidence": evidence,
                    "dangerous_action_count": len(p.dangerous_actions),
                    "evidence_omitted_count": max(0, len(p.dangerous_actions) - len(evidence)),
                    "validation_commands": self._validation_commands(p, evidence),
                    "permissions_boundary": p.permissions_boundary,
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
                title="Potentially Overly Permissive IAM Principals",
                severity="high",
                category="iam",
                description="Static policy evidence shows multiple high-impact permissions on these principals, "
                           "excluding those already reported as administrators or shadow admins. Confirm job function, "
                           "request context, and organization/resource guardrails before concluding the access is excessive.",
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
                remediation="AWS principals: replace Principal:'*' with specific ARNs. For owned accounts, consider aws:PrincipalOrgID; "
                           "for third-party delegation, use an enforced, provider-assigned sts:ExternalId. "
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
                description="IAM users requiring credential review: console access without MFA and/or "
                           "active long-term access keys. An active key is inventory evidence, not proof "
                           "that the key is old, unused, exposed, or improperly managed.",
                principals=[c["arn"] for c in analysis.credential_hygiene],
                impact="A phished password without MFA, or a leaked static access key, grants an attacker the "
                      "user's full permission set. Privileged users without MFA are the highest priority.",
                remediation="Enforce MFA for IAM users with console access. Prefer short-lived credentials "
                           "through IAM Identity Center or roles; use a credential report and last-used data "
                           "before deciding whether an active access key should be rotated or deleted.",
                details={"issues": analysis.credential_hygiene},
            ))

        critical_paths = [p for p in analysis.escalation_paths if p.severity == "critical"]
        if critical_paths:
            findings.append(Finding(
                id=f"{self.account_id}_privesc_critical",
                title="Critical Privilege Escalation Paths",
                severity="critical",
                category="privesc",
                description=f"PMapper modeled {len(critical_paths)} critical paths from non-admin "
                           "principals to full administrative access. Validate runtime conditions and external guardrails.",
                principals=sorted(set(p.source.arn for p in critical_paths[:20])),
                impact="If a modeled path is executable in the live request context, compromise of its source can lead to full account control.",
                remediation="Remove or restrict permissions that enable escalation. Use permissions boundaries to limit maximum permissions. "
                           "Common fixes include: restricting iam:PassRole to specific roles, "
                           "adding resource conditions to sts:AssumeRole, limiting ec2:RunInstances.",
                details={
                    "path_count": len(critical_paths),
                    "techniques": sorted(set(p.technique for p in critical_paths)),
                },
            ))

        return findings

    def _is_aws_managed(self, principal: Principal) -> bool:
        """Identify AWS service-linked roles from their reserved ARN path.

        Role names such as CloudFormation*, AWSReservedSSO_* or StackSet-* are not
        sufficient proof that a principal is AWS-owned and must not suppress findings.
        """
        return ":role/aws-service-role/" in principal.arn.lower()
