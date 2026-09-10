"""PMapper-style 'who can do X' query engine and text-output parser."""

import json
import re
from collections import defaultdict
from fnmatch import fnmatchcase
from typing import Dict, List, Optional, Set

from .models import AccountAnalysis
from .knowledge import DANGEROUS_ACTIONS
from .managed_policies import resolve_managed_policy_actions


class QueryResultsAnalyzer:
    """Analyze pmapper query text output to extract findings."""

    def __init__(self, results: Dict[str, List[str]], stats: Dict[str, str]):
        self.results = results
        self.stats = stats
        self.account_id = stats.get("account_id", "unknown")

    def extract_principal(self, line: str) -> Optional[str]:
        """Extract principal ARN or name from a query result line."""
        m = re.match(r"^((user|role|group)/[\w\-\.@+=]+)", line.strip())
        if m:
            return m.group(1)

        arn_match = re.search(r"(arn:aws:iam::\d+:(user|role|group)/[\w\-\.@+=]+)", line)
        if arn_match:
            return arn_match.group(1)

        parts = line.split()
        if parts:
            return parts[0].strip()

        return None

    def get_principals_for_check(self, check_key: str) -> Set[str]:
        """Get all principals that can perform a specific action."""
        principals = set()
        for line in self.results.get(check_key, []):
            p = self.extract_principal(line)
            if p and "amazonaws.com" not in p:
                principals.add(p)
        return principals

    def get_privesc_paths(self) -> List[Dict]:
        """Parse privilege escalation paths from preset results."""
        paths = []
        current_path = None

        raw_lines = []
        for key in ["privesc_all", "privesc_skip"]:
            raw_lines.extend(self.results.get(key, []))

        seen = set()
        for line in raw_lines:
            if line in seen:
                continue
            seen.add(line)

            if "is an administrative principal" in line:
                if current_path:
                    paths.append(current_path)
                    current_path = None
                continue

            elif "can escalate privileges by accessing" in line:
                if current_path:
                    paths.append(current_path)

                source = self.extract_principal(line)
                target_match = re.search(r"accessing the administrative principal (\S+?)[:$\s]", line)
                target = target_match.group(1).rstrip(":") if target_match else ""

                hops = []
                if ": " in line:
                    inline = line.split(": ", 1)[1].strip()
                    if inline:
                        hops.append(inline)

                current_path = {
                    "source": source,
                    "target": target,
                    "hops": hops,
                    "raw_line": line,
                }
            else:
                if current_path and line.strip():
                    current_path["hops"].append(line.strip())

        if current_path:
            paths.append(current_path)

        return paths

    def get_shadow_admins(self) -> List[str]:
        """Get shadow admins from wrongadmin preset."""
        return list(self.get_principals_for_check("wrongadmin"))

    def get_admins(self) -> Set[str]:
        """Extract admin principals from privesc output."""
        admins = set()
        for line in self.results.get("privesc_all", []):
            if "is an administrative principal" in line:
                p = self.extract_principal(line)
                if p:
                    admins.add(p)
        return admins

    def build_principal_capabilities(self) -> Dict[str, Set[str]]:
        """Build a map of principal -> set of dangerous actions they can perform."""
        capabilities = defaultdict(set)

        query_to_action = {
            "iam_create_user": "iam:CreateUser",
            "iam_create_access_key": "iam:CreateAccessKey",
            "iam_create_login_profile": "iam:CreateLoginProfile",
            "iam_attach_user_policy": "iam:AttachUserPolicy",
            "iam_attach_role_policy": "iam:AttachRolePolicy",
            "iam_attach_group_policy": "iam:AttachGroupPolicy",
            "iam_put_user_policy": "iam:PutUserPolicy",
            "iam_put_role_policy": "iam:PutRolePolicy",
            "iam_put_group_policy": "iam:PutGroupPolicy",
            "iam_set_default_policy_version": "iam:SetDefaultPolicyVersion",
            "iam_create_policy_version": "iam:CreatePolicyVersion",
            "iam_passrole": "iam:PassRole",
            "iam_add_user_to_group": "iam:AddUserToGroup",
            "iam_update_assume_role_policy": "iam:UpdateAssumeRolePolicy",
            "sts_assumerole": "sts:AssumeRole",
            "secretsmanager_get": "secretsmanager:GetSecretValue",
            "ssm_get_parameter": "ssm:GetParameter",
            "ssm_get_parameters": "ssm:GetParameters",
            "ssm_get_parameters_by_path": "ssm:GetParametersByPath",
            "s3_get_object": "s3:GetObject",
            "s3_put_object": "s3:PutObject",
            "s3_delete_object": "s3:DeleteObject",
            "s3_put_bucket_policy": "s3:PutBucketPolicy",
            "ec2_run_instances": "ec2:RunInstances",
            "lambda_create_function": "lambda:CreateFunction",
            "lambda_update_code": "lambda:UpdateFunctionCode",
            "lambda_add_permission": "lambda:AddPermission",
            "lambda_invoke": "lambda:InvokeFunction",
            "glue_create_job": "glue:CreateJob",
            "glue_update_job": "glue:UpdateJob",
            "cloudformation_create_stack": "cloudformation:CreateStack",
            "cloudformation_update_stack": "cloudformation:UpdateStack",
            "codebuild_create_project": "codebuild:CreateProject",
            "codebuild_start_build": "codebuild:StartBuild",
            "sagemaker_create_training": "sagemaker:CreateTrainingJob",
            "sagemaker_create_notebook": "sagemaker:CreateNotebookInstance",
            "ecs_run_task": "ecs:RunTask",
            "ecs_register_task_definition": "ecs:RegisterTaskDefinition",
            "states_create_statemachine": "states:CreateStateMachine",
            "datapipeline_create_pipeline": "datapipeline:CreatePipeline",
            "cloudtrail_stop": "cloudtrail:StopLogging",
            "cloudtrail_delete": "cloudtrail:DeleteTrail",
            "guardduty_delete": "guardduty:DeleteDetector",
            "config_stop": "config:StopConfigurationRecorder",
            "kms_decrypt": "kms:Decrypt",
        }

        for query_key, action in query_to_action.items():
            for principal in self.get_principals_for_check(query_key):
                capabilities[principal].add(action)

        return dict(capabilities)


class QueryEngine:
    """PMapper-style query interface for IAM analysis."""

    PRESETS = {
        "privesc": {
            "name": "Privilege Escalation Paths",
            "description": "Find all principals that can escalate to admin",
            "filter": lambda p, qe: p.arn in qe.privesc_sources,
        },
        "admin": {
            "name": "Administrative Principals",
            "description": "List all principals with administrative access",
            "filter": lambda p, qe: p.is_admin,
        },
        "shadow": {
            "name": "Shadow Administrators",
            "description": "Principals that can become admin without being admin",
            "filter": lambda p, qe: p.arn in qe.shadow_admin_arns,
        },
        "cross-account": {
            "name": "Cross-Account Access",
            "description": "Principals with cross-account trust relationships",
            "filter": lambda p, qe: QueryEngine._has_cross_account_trust(p),
        },
        "ssm": {
            "name": "SSM Access",
            "description": "Principals that can use SSM for lateral movement",
            "actions": ["ssm:SendCommand", "ssm:StartSession"],
        },
        "secrets": {
            "name": "Secrets Access",
            "description": "Principals that can access secrets",
            "actions": ["secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters"],
        },
        "s3": {
            "name": "S3 Data Access",
            "description": "Principals with broad S3 access",
            "actions": ["s3:GetObject", "s3:PutObject", "s3:*"],
        },
        "dangerous": {
            "name": "Dangerous Permissions",
            "description": "Principals with any dangerous IAM actions",
            "actions": list(DANGEROUS_ACTIONS),
        },
    }

    def __init__(self, analysis: 'AccountAnalysis'):
        self.analysis = analysis
        self._build_indexes()

    def _build_indexes(self):
        """Build index of actions to principals and edge lookup."""
        self.action_to_principals = defaultdict(set)
        self.edge_from = defaultdict(list)
        self.admins = set()

        for edge in self.analysis.edges:
            self.edge_from[edge.source].append(edge)

        for principal in self.analysis.principals.values():
            if principal.is_admin:
                self.admins.add(principal.arn)
            for action in principal.dangerous_actions:
                self.action_to_principals[action].add(principal.arn)
        self.privesc_sources = {path.source.arn for path in self.analysis.escalation_paths}
        self.shadow_admin_arns = {principal.arn for principal in self.analysis.shadow_admins}

    @staticmethod
    def _has_cross_account_trust(principal) -> bool:
        """Check if principal has cross-account trust."""
        if not principal.trust_policy:
            return False
        trust_str = json.dumps(principal.trust_policy)
        if re.search(r'arn:aws:iam::(?!{})'.format(principal.account_id), trust_str):
            return True
        if '"*"' in trust_str:
            return True
        return False

    def query(self, query_str: str) -> List[Dict]:
        """
        Execute a PMapper-style query.
        Supports: 'who can do <action>' and 'who can do <action> with <resource>'
        """
        results = []

        query_text = query_str.strip()

        # Actions are case-insensitive, but resource ARNs can contain
        # case-sensitive S3 keys. Preserve the resource exactly as entered.
        match = re.match(
            r"who can do ([a-z0-9:*?]+)(?:\s+with\s+(.+))?",
            query_text,
            re.IGNORECASE,
        )
        if match:
            action = match.group(1)
            resource = match.group(2) if match.group(2) else "*"
            results = self._query_action(action, resource)
        else:
            if ":" in query_str:
                results = self._query_action(query_str, "*")

        return results

    def _query_action(self, action: str, resource: str = "*") -> List[Dict]:
        """Find all principals that can perform an action."""
        results = []

        for principal in self.analysis.principals.values():
            can_do = self._can_directly_do(principal, action, resource)
            matched_via = None
            if can_do:
                matched_via = "admin (*)" if principal.is_admin else "direct"

            if not can_do:
                access_path = self._find_access_path(principal.arn, action, resource)
                if access_path:
                    can_do = True
                    target_name = access_path[-1].target.split("/")[-1]
                    count = len(access_path)
                    matched_via = f"indirect via {target_name} ({count} hop{'s' if count != 1 else ''})"

            if can_do:
                results.append({
                    "principal": principal.arn,
                    "name": principal.name,
                    "type": principal.principal_type,
                    "is_admin": principal.is_admin,
                    "matched_via": matched_via,
                    "direct": matched_via == "direct",
                })

        return sorted(results, key=lambda x: (not x["direct"], x["name"]))

    def _find_access_path(self, start_arn: str, action: str, resource: str):
        """Return the shortest graph path to a principal that can do the action."""
        queue = [(start_arn, [])]
        visited = {start_arn}
        while queue:
            current, path = queue.pop(0)
            for edge in self.edge_from.get(current, []):
                if edge.target in visited:
                    continue
                visited.add(edge.target)
                new_path = path + [edge]
                target = self.analysis.principals.get(edge.target)
                if target and self._can_directly_do(target, action, resource):
                    return new_path
                queue.append((edge.target, new_path))
        return []

    @staticmethod
    def _action_matches(statement, action: str) -> bool:
        requested = action.lower()
        if statement.not_actions:
            return not any(fnmatchcase(requested, pattern.lower())
                           for pattern in statement.not_actions)
        return any(fnmatchcase(requested, pattern.lower()) for pattern in statement.actions)

    @staticmethod
    def _resource_matches(statement, resource: str) -> bool:
        """Whether a statement covers the requested resource.

        Resource "*" in a query means "any resource", while a concrete ARN is
        matched using IAM-style * and ? wildcards.
        """
        if resource == "*":
            if statement.not_resources:
                return not any(pattern == "*" for pattern in statement.not_resources)
            return bool(statement.resources)
        if statement.not_resources:
            return not any(fnmatchcase(resource, pattern) for pattern in statement.not_resources)
        return any(fnmatchcase(resource, pattern) for pattern in statement.resources)

    def _effective_policies(self, principal):
        policies = []
        seen = set()
        for policy_arn in list(principal.policies) + list(principal.group_policy_arns):
            if not policy_arn or policy_arn in seen:
                continue
            seen.add(policy_arn)
            policy = self.analysis.policies.get(policy_arn)
            if policy:
                policies.append(policy)
                continue
            actions = resolve_managed_policy_actions(policy_arn)
            if actions is not None:
                from .models import Policy, PolicyStatement
                policies.append(Policy(
                    arn=policy_arn,
                    name=policy_arn.split("/")[-1],
                    statements=[PolicyStatement("Allow", sorted(actions), ["*"])],
                    is_aws_managed=True,
                ))
        policies.extend(principal.inline_policies)
        return policies

    def _policy_set_allows(self, policies, action: str, resource: str) -> bool:
        allowed = False
        for policy in policies:
            for statement in policy.statements:
                if not self._action_matches(statement, action):
                    continue
                if not self._resource_matches(statement, resource):
                    continue
                effect = statement.effect.lower()
                if effect == "allow":
                    allowed = True
                elif effect == "deny" and not statement.conditions:
                    if resource == "*" and not (
                        "*" in statement.resources and not statement.not_resources
                    ):
                        # A resource-scoped deny does not mean the principal lacks
                        # this action everywhere.
                        continue
                    return False
        return allowed

    def _can_directly_do(self, principal, action: str, resource: str) -> bool:
        policies = self._effective_policies(principal)
        identity_allowed = self._policy_set_allows(policies, action, resource)
        if principal.is_admin:
            identity_allowed = True
        if not identity_allowed:
            return False

        if principal.permissions_boundary:
            boundary = self.analysis.policies.get(principal.permissions_boundary)
            if boundary and not self._policy_set_allows([boundary], action, resource):
                return False
        return True

    def run_preset(self, preset_name: str) -> List[Dict]:
        """Run a preset query."""
        preset = self.PRESETS.get(preset_name)
        if not preset:
            return []

        results = []

        if "actions" in preset:
            seen = set()
            for action in preset["actions"]:
                for result in self._query_action(action, "*"):
                    if result["principal"] not in seen:
                        seen.add(result["principal"])
                        result["matched_action"] = action
                        results.append(result)

        elif "filter" in preset:
            filter_fn = preset["filter"]
            for principal in self.analysis.principals.values():
                try:
                    if filter_fn(principal, self):
                        results.append({
                            "principal": principal.arn,
                            "name": principal.name,
                            "type": principal.principal_type,
                            "is_admin": principal.is_admin,
                        })
                except Exception:
                    pass

        return results

    def print_results(self, results: List[Dict], title: str = "Query Results"):
        """Print query results in PMapper style."""
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"  Found: {len(results)} principal(s)")
        print(f"{'='*60}\n")

        if not results:
            print("  No matching principals found.\n")
            return

        by_type = defaultdict(list)
        for r in results:
            by_type[r.get("type", "unknown")].append(r)

        for ptype, principals in sorted(by_type.items()):
            print(f"  [{ptype.upper()}S] ({len(principals)})")
            for p in principals:
                admin_tag = " [ADMIN]" if p.get("is_admin") else ""
                via = f" (via {p.get('matched_via')})" if p.get("matched_via") else ""
                action = f" [{p.get('matched_action')}]" if p.get("matched_action") else ""
                print(f"    - {p['name']}{admin_tag}{via}{action}")
            print()
