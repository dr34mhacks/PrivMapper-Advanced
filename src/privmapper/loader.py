"""Load and parse PMapper graph JSON (nodes/edges/policies/groups) into the model."""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from .models import Edge, Policy, PolicyStatement, Principal
from .knowledge import AWS_MANAGED_PATTERNS


class GraphLoader:
    """Load and parse PMapper graph data from JSON files."""

    def __init__(self, graph_path: Path):
        self.graph_path = Path(graph_path)
        self.nodes_file = self.graph_path / "nodes.json"
        self.edges_file = self.graph_path / "edges.json"
        self.groups_file = self.graph_path / "groups.json"
        self.policies_file = self.graph_path / "policies.json"

    def validate(self) -> bool:
        """Check if required files exist."""
        required = [self.nodes_file, self.edges_file]
        for f in required:
            if not f.exists():
                return False
        return True

    def load(self) -> Tuple[Dict[str, Principal], List[Edge], Dict[str, Policy]]:
        """Load all graph data and return parsed structures."""
        principals = self._load_nodes()
        edges = self._load_edges()
        policies = self._load_policies()
        members_by_group, policies_by_group = self._load_groups()

        # PMapper's native schema stores group membership on each Node and the
        # group's policies in groups.json; groups do not carry a member list.
        for principal in principals.values():
            for group_arn in principal.group_memberships:
                for policy_arn in policies_by_group.get(group_arn, []):
                    if policy_arn not in principal.group_policy_arns:
                        principal.group_policy_arns.append(policy_arn)

        # Also accept enriched graph exports that place members on groups.
        for group_arn, members in members_by_group.items():
            gpols = policies_by_group.get(group_arn, [])
            for member_arn in members:
                if member_arn in principals:
                    p = principals[member_arn]
                    if group_arn not in p.group_memberships:
                        p.group_memberships.append(group_arn)
                    for pa in gpols:
                        if pa not in p.group_policy_arns:
                            p.group_policy_arns.append(pa)

        return principals, edges, policies

    def _load_nodes(self) -> Dict[str, Principal]:
        """Parse nodes.json into Principal objects."""
        principals = {}
        try:
            with open(self.nodes_file) as f:
                data = json.load(f)

            nodes = data if isinstance(data, list) else data.get("nodes", [])

            for node in nodes:
                arn = node.get("arn", node.get("Arn", ""))
                if not arn:
                    continue

                arn_parts = arn.split(":")
                account_id = arn_parts[4] if len(arn_parts) > 4 else ""
                resource = arn_parts[5] if len(arn_parts) > 5 else ""

                if resource.startswith("user/"):
                    ptype = "user"
                    name = resource.split("/")[-1]
                elif resource.startswith("role/"):
                    ptype = "role"
                    name = resource.split("/")[-1]
                elif resource.startswith("group/"):
                    ptype = "group"
                    name = resource.split("/")[-1]
                else:
                    ptype = "unknown"
                    name = resource

                attached_policies = node.get("attached_policies",
                                           node.get("AttachedPolicies", []))
                if isinstance(attached_policies, list):
                    policy_arns = [p.get("arn", p) if isinstance(p, dict) else p
                                   for p in attached_policies]
                else:
                    policy_arns = []

                is_admin = node.get("is_admin", node.get("IsAdmin", False))

                trust_policy = node.get("trust_policy",
                                       node.get("TrustPolicy",
                                               node.get("AssumeRolePolicyDocument")))

                num_keys = node.get("num_access_keys",
                                    node.get("access_keys", node.get("NumAccessKeys")))
                has_keys = node.get("has_access_keys", node.get("AccessKeys", None))
                if isinstance(has_keys, list):
                    num_keys = num_keys if num_keys is not None else len(has_keys)
                    has_keys = len(has_keys) > 0
                if num_keys is None:
                    num_keys = 0
                try:
                    num_keys = int(num_keys)
                except (TypeError, ValueError):
                    num_keys = 0
                if has_keys is None:
                    has_keys = num_keys > 0

                has_mfa = bool(node.get("has_mfa", node.get("HasMFA", False)))
                active_password = bool(node.get("active_password",
                                                node.get("ActivePassword", False)))
                id_value = node.get("id_value", node.get("IdValue", "")) or ""
                instance_profile = node.get("instance_profile", node.get("InstanceProfile"))
                is_instance_profile = bool(instance_profile)
                perm_boundary = node.get("permissions_boundary",
                                         node.get("PermissionsBoundary"))
                if isinstance(perm_boundary, dict):
                    perm_boundary = perm_boundary.get("arn", perm_boundary.get("PermissionsBoundaryArn"))

                raw_groups = node.get("group_memberships", node.get("GroupMemberships", []))
                if not isinstance(raw_groups, list):
                    raw_groups = []
                group_memberships = [
                    group.get("arn", group.get("Arn", "")) if isinstance(group, dict) else group
                    for group in raw_groups
                ]
                group_memberships = [group for group in group_memberships if group]

                inline_policies = []
                raw_inline = node.get("inline_policies", node.get("InlinePolicies", []))
                if isinstance(raw_inline, dict):
                    raw_inline = [{"name": k, "policy_doc": v} for k, v in raw_inline.items()]
                if isinstance(raw_inline, list):
                    for ip in raw_inline:
                        if not isinstance(ip, dict):
                            continue
                        ip_name = ip.get("name", ip.get("PolicyName", "inline"))
                        ip_doc = ip.get("policy_doc", ip.get("document",
                                        ip.get("PolicyDocument", ip.get("Document", ip))))
                        inline_policies.append(Policy(
                            arn=f"{arn}/inline/{ip_name}",
                            name=ip_name,
                            statements=self._parse_statements(ip_doc),
                            is_aws_managed=False,
                        ))

                principals[arn] = Principal(
                    arn=arn,
                    name=name,
                    principal_type=ptype,
                    account_id=account_id,
                    policies=policy_arns,
                    inline_policies=inline_policies,
                    is_admin=is_admin,
                    trust_policy=trust_policy,
                    has_access_keys=bool(has_keys),
                    num_access_keys=num_keys,
                    is_instance_profile=is_instance_profile,
                    group_memberships=group_memberships,
                    has_mfa=has_mfa,
                    active_password=active_password,
                    id_value=id_value,
                    permissions_boundary=perm_boundary,
                    tags=node.get("tags", node.get("Tags", {})),
                )

        except Exception as e:
            raise ValueError(f"Invalid nodes.json: {e}") from e

        return principals

    def _load_edges(self) -> List[Edge]:
        """Parse edges.json into Edge objects."""
        edges = []
        try:
            with open(self.edges_file) as f:
                data = json.load(f)

            edge_list = data if isinstance(data, list) else data.get("edges", [])

            for edge in edge_list:
                source = edge.get("source", edge.get("Source", ""))
                target = edge.get("destination", edge.get("target",
                                 edge.get("Destination", edge.get("Target", ""))))
                reason = edge.get("reason", edge.get("Reason", ""))
                short = edge.get("short_reason", edge.get("ShortReason", ""))

                if source and target:
                    edges.append(Edge(
                        source=source,
                        target=target,
                        reason=reason,
                        short_reason=short or reason[:100],
                    ))

        except Exception as e:
            raise ValueError(f"Invalid edges.json: {e}") from e

        return edges

    @staticmethod
    def _parse_statements(doc) -> List[PolicyStatement]:
        """Parse a policy document into PolicyStatement objects.

        Handles Action/NotAction and Resource/NotResource. Critically, Resource is
        left EMPTY (not defaulted to ['*']) when only NotResource is present, so an
        exclusion is never silently inverted into a full wildcard.
        """
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except Exception:
                return []
        if not isinstance(doc, dict):
            return []

        raw_stmts = doc.get("Statement", [])
        if isinstance(raw_stmts, dict):
            raw_stmts = [raw_stmts]

        statements = []
        for stmt in raw_stmts:
            if not isinstance(stmt, dict):
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            not_actions = stmt.get("NotAction", [])
            if isinstance(not_actions, str):
                not_actions = [not_actions]

            has_resource_key = "Resource" in stmt
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            not_resources = stmt.get("NotResource", [])
            if isinstance(not_resources, str):
                not_resources = [not_resources]
            if not has_resource_key and not not_resources:
                resources = ["*"]

            statements.append(PolicyStatement(
                effect=stmt.get("Effect", "Allow"),
                actions=actions,
                resources=resources,
                conditions=stmt.get("Condition", {}),
                not_actions=not_actions,
                not_resources=not_resources,
                sid=stmt.get("Sid", ""),
            ))
        return statements

    def _load_policies(self) -> Dict[str, Policy]:
        """Parse policies.json into Policy objects."""
        policies = {}
        if not self.policies_file.exists():
            return policies

        try:
            with open(self.policies_file) as f:
                data = json.load(f)

            policy_list = data if isinstance(data, list) else data.get("policies", [])

            for pol in policy_list:
                arn = pol.get("arn", pol.get("Arn", ""))
                name = pol.get("name", pol.get("PolicyName", arn.split("/")[-1]))

                doc = pol.get("document", pol.get("PolicyDocument",
                             pol.get("policy_doc", pol.get("Document", {}))))
                statements = self._parse_statements(doc)

                is_aws = arn.startswith("arn:aws:iam::aws:") or any(
                    re.search(p, name) for p in AWS_MANAGED_PATTERNS
                )

                policies[arn] = Policy(
                    arn=arn,
                    name=name,
                    statements=statements,
                    is_aws_managed=is_aws,
                )

        except Exception as e:
            raise ValueError(f"Invalid policies.json: {e}") from e

        return policies

    def _load_groups(self):
        """Parse groups.json. Returns (members_by_group, policies_by_group).

        The second map (group ARN -> attached policy ARNs) was previously discarded,
        which made every permission a user holds ONLY via a group invisible to the
        capability engine.
        """
        members = {}
        group_policies = {}
        if not self.groups_file.exists():
            return members, group_policies

        try:
            with open(self.groups_file) as f:
                data = json.load(f)

            if isinstance(data, dict):
                for group_arn, val in data.items():
                    if isinstance(val, list):
                        members[group_arn] = val
                    elif isinstance(val, dict):
                        members[group_arn] = val.get("members", val.get("Members", []))
                        pols = val.get("attached_policies", val.get("AttachedPolicies", []))
                        group_policies[group_arn] = [
                            p.get("arn", p) if isinstance(p, dict) else p for p in pols
                        ]
            elif isinstance(data, list):
                for group in data:
                    arn = group.get("arn", group.get("Arn", ""))
                    if not arn:
                        continue
                    members[arn] = group.get("members", group.get("Members", []))
                    pols = group.get("attached_policies", group.get("AttachedPolicies", []))
                    group_policies[arn] = [
                        p.get("arn", p) if isinstance(p, dict) else p for p in pols
                    ]

        except Exception as e:
            raise ValueError(f"Invalid groups.json: {e}") from e

        return members, group_policies


def find_pmapper_graphs() -> List[Path]:
    """Auto-detect pmapper graph directories."""
    graphs = []

    configured_storage = os.environ.get("PMAPPER_STORAGE")
    if configured_storage:
        search_paths = [Path(configured_storage).expanduser()]
    elif sys.platform in ("win32", "cygwin") and os.environ.get("APPDATA"):
        search_paths = [Path(os.environ["APPDATA"]) / "principalmapper"]
    elif sys.platform == "darwin":
        search_paths = [Path.home() / "Library" / "Application Support" /
                        "com.nccgroup.principalmapper"]
    else:
        data_home = os.environ.get("XDG_DATA_HOME")
        search_paths = [((Path(data_home).expanduser() if data_home else
                         Path.home() / ".local" / "share") / "principalmapper")]
    search_paths.append(Path.home() / ".principalmapper")
    search_paths = list(dict.fromkeys(search_paths))

    for base in search_paths:
        if not base.exists():
            continue

        for item in base.iterdir():
            if item.is_dir():
                graph_dir = item / "graph"
                if graph_dir.exists() and (graph_dir / "nodes.json").exists():
                    graphs.append(graph_dir)
                elif (item / "nodes.json").exists():
                    graphs.append(item)

    return graphs
