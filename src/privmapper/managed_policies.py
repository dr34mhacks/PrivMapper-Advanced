"""Conservative fallback for a stable AWS-managed policy when its body is absent."""
from typing import Optional, Set

AWS_MANAGED_POLICY_EXPANSIONS = {
    "AdministratorAccess": {"*"},
}


def resolve_managed_policy_actions(policy_arn: str) -> Optional[Set[str]]:
    """Return actions only for a stable, exactly understood managed policy.

    Returns None when the policy is AWS-managed but not in our catalog, so callers
    can flag "managed policy body unavailable; capabilities may be understated".
    Returns an empty set only for policies we know grant no escalation-relevant power.
    """
    if not policy_arn.startswith("arn:aws:iam::aws:policy/"):
        return None
    name = policy_arn.split("/")[-1]

    expansion = AWS_MANAGED_POLICY_EXPANSIONS.get(name)
    return set(expansion) if expansion is not None else None
