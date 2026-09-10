"""Export analysis results to a single structured JSON file."""

import json
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List

from ..models import AccountAnalysis, Finding
from ..knowledge import AWS_MANAGED_PATTERNS


class JSONExporter:
    """Export analysis results to JSON."""

    @staticmethod
    def export(analyses: List[AccountAnalysis], output_path: Path,
               cross_account_findings: List[Finding] = None):
        """Export all analyses to a single JSON file."""
        output = {
            "generated_at": datetime.now().isoformat(),
            "tool": "privmapper_advanced",
            "version": "2.0.0",
            "accounts": [],
            "cross_account_findings": [
                asdict(finding) for finding in (cross_account_findings or [])
            ],
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
                        "hop_explanations": p.hop_explanations,
                        "resulting_access": p.resulting_access,
                        "validation_notes": p.validation_notes,
                        "evidence_status": p.evidence_status,
                        "missing_prerequisites": p.missing_prerequisites,
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
