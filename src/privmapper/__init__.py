"""PrivMapper - AWS IAM privilege-escalation analysis and reporting.

Reads a PMapper graph (or runs pmapper), performs AWS-faithful IAM analysis, and
produces an interactive HTML report plus JSON/CSV for security assessments.
"""

__version__ = "2.0.0"

from .models import (AccountAnalysis, CrossAccountTrust, Edge, EscalationPath, Finding,
                     Policy, PolicyStatement, Principal, RunMetadata)
from .loader import GraphLoader, find_pmapper_graphs
from .analysis import AnalysisEngine
from .queries import QueryEngine
from .crossaccount import CrossAccountAnalyzer
from .reporting.json_export import JSONExporter
from .reporting.csv_export import CSVExporter
from .reporting.html_export import HTMLExporter

__all__ = [
    "__version__", "AccountAnalysis", "CrossAccountTrust", "Edge", "EscalationPath",
    "Finding", "Policy", "PolicyStatement", "Principal", "RunMetadata",
    "GraphLoader", "find_pmapper_graphs", "AnalysisEngine", "QueryEngine",
    "CrossAccountAnalyzer", "JSONExporter", "CSVExporter", "HTMLExporter",
]
