"""Export findings and escalation paths to CSV with risk and evidence fields."""

import csv
import json
from pathlib import Path
from typing import List

from ..models import AccountAnalysis, Finding
from ..knowledge import get_exploitation_guidance
from ..remediation import RemediationEngine


class CSVExporter:
    """Export analysis results to CSV."""

    FIELDS = ["account_id", "finding_id", "title", "severity", "category", "cvss",
              "principal", "risk_score", "evidence", "impact", "remediation"]

    @staticmethod
    def export(analyses: List[AccountAnalysis], output_path: Path,
               cross_account_findings: List[Finding] = None):
        """Export findings to CSV with assessment substance and evidence."""
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
                    "cvss": "",
                    "principal": path.source.arn,
                    "risk_score": path.risk_score,
                    "evidence": json.dumps({
                        "chain": chain,
                        "hops": path.hop_explanations,
                        "evidence_status": path.evidence_status,
                        "missing_prerequisites": path.missing_prerequisites,
                        "validation_notes": path.validation_notes,
                    }, separators=(",", ":")),
                    "impact": path.resulting_access,
                    "remediation": RemediationEngine.get_path_remediation(path)["fix"],
                })

        for finding in cross_account_findings or []:
            affected = finding.principals or ["multiple accounts"]
            for principal in affected:
                rows.append({
                    "account_id": "multi-account",
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "category": finding.category,
                    "cvss": "",
                    "principal": principal,
                    "risk_score": "",
                    "evidence": finding.description,
                    "impact": finding.impact,
                    "remediation": finding.remediation,
                })

        if rows:
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSVExporter.FIELDS)
                writer.writeheader()
                writer.writerows(rows)

            print(f"[+] CSV exported: {output_path}")
        else:
            print("[!] No findings to export to CSV")
