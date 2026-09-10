"""Security knowledge base: dangerous actions, techniques, MITRE mappings, validation guidance and query catalogs."""

from typing import Dict, List, Optional


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
    "s3:GetObject", "s3:PutBucketPolicy", "s3:PutObject", "s3:DeleteObject",
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
    "guardduty:DeleteDetector", "config:StopConfigurationRecorder", "kms:Decrypt",
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
    "Lambda CreateFunction": [r"lambda:CreateFunction", r"lambda.*create.*function", r"create.*function.*role"],
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


CRED_CHECKS = {"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "kms:Decrypt"}


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
    "iam:PassRole":                 "Pass permitted IAM roles to AWS services (resource and conditions apply)",
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
    "kms:Decrypt":                  "Decrypt data protected by accessible KMS keys",
    "ec2:RunInstances":             "Launch EC2 instances with privileged instance profiles",
    "lambda:UpdateFunctionCode":    "Replace Lambda function code to abuse the execution role",
    "lambda:AddPermission":         "Grant external accounts access to Lambda functions",
    "lambda:CreateFunction":        "Create Lambda functions (execution-role use requires iam:PassRole)",
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
            "1. Confirm the principal and its current policy attachments",
            "2. Simulate representative write, read, and delete actions against exact resources",
            "3. Check permissions boundaries, SCPs, RCPs, resource policies, and session policy constraints",
            "4. Treat full account takeover as the impact of credential compromise, not as proof that compromise occurred",
        ],
        "aws_cli_commands": '''# Inventory attached and inline policies (choose role or user)
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
aws iam list-attached-user-policies --user-name <USER_NAME>
aws iam list-user-policies --user-name <USER_NAME>

# Safely simulate representative actions; replace with exact actions/resources
aws iam simulate-principal-policy --policy-source-arn <PRINCIPAL_ARN> \\
    --action-names iam:CreateUser s3:DeleteBucket \\
    --resource-arns <EXACT_RESOURCE_ARN>''',
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
            "2. Confirm the exact target resource, policy ARN constraints, and Condition values",
            "3. Verify any complementary permissions and target trust required by the modeled graph edge",
            "4. Use policy simulation and configuration review; do not mutate a customer identity to prove impact",
        ],
        "aws_cli_commands": '''# Inspect source policies and the target role without changing them
aws iam list-attached-role-policies --role-name <SOURCE_ROLE_NAME>
aws iam list-role-policies --role-name <SOURCE_ROLE_NAME>
aws iam get-role --role-name <TARGET_ROLE_NAME>

# Simulate the exact action and target ARN shown by the finding
aws iam simulate-principal-policy --policy-source-arn <SOURCE_PRINCIPAL_ARN> \\
    --action-names <EVIDENCED_ACTION> --resource-arns <TARGET_RESOURCE_ARN>''',
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
            "2. Validate each hop's source policy, resource scope, conditions, and target trust",
            "3. Verify organization and resource guardrails that the static graph cannot prove",
            "4. Common patterns: iam:PassRole + service abuse, sts:AssumeRole chain, credential harvesting",
        ],
        "aws_cli_commands": '''# Validate each identity-policy side of the path without executing it
aws iam simulate-principal-policy --policy-source-arn <SOURCE_PRINCIPAL_ARN> \\
    --action-names <HOP_ACTION> --resource-arns <HOP_TARGET_ARN>

# For AssumeRole/PassRole paths, inspect target trust and attached policies
aws iam get-role --role-name <TARGET_ROLE_NAME>
aws iam list-attached-role-policies --role-name <TARGET_ROLE_NAME>''',
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
            "1. Determine exactly which external principal and STS action the trust permits",
            "2. Evaluate every trust-policy Condition operator and value, not just key presence",
            "3. Confirm the external principal also has identity-side permission where AWS requires it",
            "4. Review the target role's effective permissions to establish the actual blast radius",
        ],
        "aws_cli_commands": '''# Retrieve and review the URL-decoded role trust document
aws iam get-role --role-name <TARGET_ROLE_NAME> \\
    --query 'Role.AssumeRolePolicyDocument'

# Validate an exported trust document with IAM Access Analyzer
aws accessanalyzer validate-policy --policy-type RESOURCE_POLICY \\
    --validate-policy-resource-type AWS::IAM::AssumeRolePolicyDocument \\
    --policy-document file://trust-policy.json''',
        "evidence": "Check role trust policy for Principal: '*' or missing sts:ExternalId condition",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html",
            "https://attack.mitre.org/techniques/T1199/",
        ],
    },
    "overly_permissive": {
        "title": "Potentially Overly Permissive Permissions",
        "risk_rating": "High",
        "cvss_estimate": "7.5 (High)",
        "description": "Static policy evidence shows multiple high-impact permissions. The tool cannot know the principal's business need, so confirm job function and all authorization guardrails before reporting the access as excessive.",
        "impact": {
            "confidentiality": "Broader access than necessary increases exposure of sensitive data",
            "integrity": "More modification capabilities than job function requires",
            "availability": "Could accidentally or maliciously disrupt services",
            "business": "Violates least-privilege principle, increases incident impact",
        },
        "exploitation_steps": [
            "1. Identify the specific dangerous permissions granted (see capability list)",
            "2. Confirm each permission against its exact Resource and Condition values",
            "3. Use last-accessed evidence and business purpose to determine whether the permission is actually excessive",
        ],
        "aws_cli_commands": '''# Simulate only the exact action/resource reported for the principal
aws iam simulate-principal-policy --policy-source-arn <PRINCIPAL_ARN> \\
    --action-names <EVIDENCED_ACTION> --resource-arns <EVIDENCED_RESOURCE_ARN>

# Use IAM Access Analyzer to validate policies
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY \\
    --policy-document file://policy.json

# Check last accessed information for unused permissions
aws iam generate-service-last-accessed-details --arn <PRINCIPAL_ARN>
aws iam get-service-last-accessed-details --job-id <JOB_ID>''',
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
            "1. Inventory secret and parameter metadata without retrieving values",
            "2. Confirm the exact resource ARNs covered by each identity-policy statement",
            "3. Check KMS key policies, resource policies, conditions, boundaries, and organization controls",
            "4. Use policy simulation to validate authorization without exposing customer secrets",
        ],
        "aws_cli_commands": '''# Inventory secret metadata without retrieving secret values
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
aws ssm describe-parameters

# Validate the exact secret read without retrieving any data
aws iam simulate-principal-policy --policy-source-arn <PRINCIPAL_ARN> \\
    --action-names secretsmanager:GetSecretValue --resource-arns <SECRET_ARN>''',
        "evidence": "Actions: secretsmanager:GetSecretValue, ssm:GetParameter, ssm:GetParameters, ssm:GetParametersByPath",
        "references": [
            "https://attack.mitre.org/techniques/T1552/005/",
        ],
    },
    "credential_hygiene": {
        "title": "IAM Credential Review",
        "risk_rating": "Context dependent",
        "cvss_estimate": "",
        "description": "IAM users with console access without MFA and/or active long-term access keys. Key presence alone does not prove age, exposure, non-use, or a policy violation; confirm with the credential report and last-used data.",
        "impact": {
            "confidentiality": "A phished password (no MFA) or a leaked long-term key grants the user's full permission set to an attacker",
            "integrity": "Compromised credentials allow modification of any resource the user can reach",
            "availability": "Attacker can lock out or disrupt using the compromised identity",
            "business": "Actual risk depends on the principal's permissions, MFA applicability, key handling, age, and last-used evidence",
        },
        "exploitation_steps": [
            "1. Confirm whether the user has an active console password and MFA device",
            "2. Collect access-key creation date, status, and last-used service/region/time",
            "3. Determine whether each credential is required and handled according to company policy",
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
    # A static IAM graph lacks the environment and business context required for
    # a defensible CVSS score, so do not present one as computed proof.
    guidance["cvss_estimate"] = ""
    guidance["cvss_vector"] = ""
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
