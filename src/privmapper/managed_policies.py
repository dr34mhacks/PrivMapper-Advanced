"""Resolution of well-known AWS-managed policy ARNs to their (approximate) action sets, so managed grants are not mistaken for 'no permissions'."""

import re
from typing import Optional, Set

from .knowledge import DANGEROUS_ACTIONS


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
