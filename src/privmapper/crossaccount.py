"""Correlate trust relationships across multiple analyzed accounts."""

from collections import defaultdict
from typing import Dict, List

from .models import AccountAnalysis, Finding


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
                id="cross_account_trust_topology",
                title="Cross-Account Trust Topology (Validation Required)",
                severity="medium",
                category="cross_account",
                description=(f"Found {len(trust_chains)} multi-account trust sequences. Trust relationships "
                             "alone do not prove that a principal can traverse the sequence; identity permissions, "
                             "target trust conditions, SCPs/RCPs, boundaries, and session policies must also align."),
                principals=[],
                impact="A sequence may enable lateral movement only when the required AssumeRole authorization is confirmed at every hop.",
                remediation="Review and minimize cross-account trust relationships. "
                           "Use ExternalId for third-party confused-deputy scenarios and organization conditions for owned accounts where appropriate. "
                           "Consider using AWS Organizations SCPs to restrict cross-account access.",
                details={"chains": trust_chains, "proven_traversable": False},
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
