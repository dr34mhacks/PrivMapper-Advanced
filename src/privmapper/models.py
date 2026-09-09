"""Typed data model for IAM principals, policies, edges, findings and analysis results."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class PolicyStatement:
    effect: str
    actions: List[str]
    resources: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)
    principals: List[str] = field(default_factory=list)
    not_actions: List[str] = field(default_factory=list)
    not_resources: List[str] = field(default_factory=list)
    sid: str = ""


@dataclass
class Policy:
    arn: str
    name: str
    statements: List[PolicyStatement] = field(default_factory=list)
    is_aws_managed: bool = False


@dataclass
class Principal:
    arn: str
    name: str
    principal_type: str
    account_id: str
    policies: List[str] = field(default_factory=list)
    inline_policies: List[Policy] = field(default_factory=list)
    trust_policy: Optional[Dict] = None
    is_admin: bool = False
    has_access_keys: bool = False
    num_access_keys: int = 0
    is_instance_profile: bool = False
    group_memberships: List[str] = field(default_factory=list)
    group_policy_arns: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    has_mfa: bool = False
    active_password: bool = False
    id_value: str = ""
    permissions_boundary: Optional[str] = None
    dangerous_actions: Set[str] = field(default_factory=set)
    capabilities: List[str] = field(default_factory=list)
    capability_groups: List[Tuple[str, str, List[str]]] = field(default_factory=list)
    action_evidence: Dict[str, Any] = field(default_factory=dict)
    has_notaction: bool = False
    boundary_capped: bool = False
    unresolved_managed: List[str] = field(default_factory=list)


@dataclass
class Edge:
    source: str
    target: str
    reason: str
    short_reason: str = ""


@dataclass
class EscalationPath:
    source: Principal
    target: Principal
    hops: List[Edge]
    technique: str
    risk_score: int = 0
    severity: str = "medium"
    complexity: int = 1
    exposure: int = 5
    blast_radius: int = 5
    mitre_techniques: List[Dict] = field(default_factory=list)
    attack_narrative: str = ""


@dataclass
class CrossAccountTrust:
    role_arn: str
    role_name: str
    trusted_principal: str
    trusted_account: str
    has_external_id: bool
    has_conditions: bool
    is_wildcard: bool
    risk_level: str
    principal_kind: str = "AWS"
    external_id_enforced: bool = False
    target_is_admin: bool = False
    reason: str = ""
    remediation_key: str = ""


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    principals: List[str]
    impact: str
    remediation: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountAnalysis:
    account_id: str
    account_alias: str
    node_count: int
    edge_count: int
    admin_count: int
    principals: Dict[str, Principal]
    edges: List[Edge]
    policies: Dict[str, Policy]
    findings: List[Finding] = field(default_factory=list)
    escalation_paths: List[EscalationPath] = field(default_factory=list)
    cross_account_trusts: List[CrossAccountTrust] = field(default_factory=list)
    shadow_admins: List[Principal] = field(default_factory=list)
    overly_permissive: List[Principal] = field(default_factory=list)
    aws_managed_admins: List[Principal] = field(default_factory=list)
    credential_hygiene: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RunMetadata:
    """Metadata about the analysis run for display in report."""
    profiles: List[str] = field(default_factory=list)
    input_paths: List[str] = field(default_factory=list)
    regions_used: List[str] = field(default_factory=list)
    regions_excluded: List[str] = field(default_factory=list)
    auto_detected_regions: bool = False
    run_timestamp: str = ""
    tool_version: str = "1.0.0"
    pmapper_version: str = ""
    output_directory: str = ""
    output_formats: List[str] = field(default_factory=list)
