"""Remediation snippets for each finding class and escalation technique."""

from typing import Dict

from .models import CrossAccountTrust, EscalationPath


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
            "issue": "External trust requires ownership and purpose validation; ExternalId is specifically relevant to third-party delegation",
            "fix": "For third parties, require a unique provider-assigned ExternalId. For owned accounts, prefer specific principals and organization-aware controls where appropriate",
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
            "issue": "A PMapper edge indicates Lambda can be used to access a more privileged execution role",
            "fix": "Restrict Lambda mutation/invocation permissions and iam:PassRole; ensure only Lambda-compatible, least-privileged roles can be passed",
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

# Create customer-managed policies from validated Access Analyzer and CloudTrail evidence.''',
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
        elif not trust.has_external_id and trust.principal_kind == "AWS":
            return cls.REMEDIATIONS["cross_account_no_external_id"]
        else:
            return {
                "issue": "Cross-account trust relationship",
                "fix": "Verify the trusted account is legitimate and regularly audit access",
                "example": "Use AWS CloudTrail to monitor AssumeRole events",
            }
