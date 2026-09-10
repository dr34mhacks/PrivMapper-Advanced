"""Interactive HTML report generation."""

import json
import base64
import hashlib
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..models import (AccountAnalysis, CrossAccountTrust, EscalationPath, Finding,
                      RunMetadata)
from ..knowledge import DANGEROUS_ACTIONS, get_exploitation_guidance
from ..queries import QueryEngine
from .assets import CSS as _CSS, GRAPH_JS as _GRAPH_JS, APP_JS as _APP_JS


class HTMLExporter:
    """Generate interactive HTML report."""

    CSS = _CSS

    GRAPH_JS = _GRAPH_JS

    JS = _APP_JS

    CYTOSCAPE_SHA256 = "92d752b48ea949720675865197fd2a0001c95bc5888545e990af60321712d4c6"
    FONT_MANIFEST = (
        ("inter-400.ttf", "Inter", 400, "1b08e7fc267a5c7e1d614100f604b83e7e8a0be241f0f288faa2b3ac93a683ba"),
        ("inter-500.ttf", "Inter", 500, "8c883f63b2c4157d997319f2c8bc6995ed4357ef371940d31ca159004a4aae63"),
        ("inter-600.ttf", "Inter", 600, "e7a1aaf7eda9f2fad4131725fa556265ec75ca7b2d756260173a040363e8d4f7"),
        ("inter-700.ttf", "Inter", 700, "b37284b5701b6b168dfc770aa1a4ac492106422fd3ba76bc7641e37434e8019c"),
        ("inter-800.ttf", "Inter", 800, "eec66af7f2337bd34fe6e801cf92ededcb57a20c0d7bc40a61d4eefcbe3dd40c"),
        ("jetbrains-mono-400.ttf", "JetBrains Mono", 400, "44ce4a84f20d60f24539bd0cef11f79c29e38609e0f8adf18551c9794a5d9dc3"),
        ("jetbrains-mono-500.ttf", "JetBrains Mono", 500, "3386a05f6ece969e4537de6be894170d20558e82f7d56c8c5d332972ef172160"),
        ("jetbrains-mono-600.ttf", "JetBrains Mono", 600, "df54dbfafba61d4911eb3dab9bba2d20531fb009f01d64dd42fa96ab862584d8"),
    )

    @classmethod
    def _cytoscape_js(cls) -> str:
        """Load the pinned vendored graph library and reject unexpected changes."""
        asset = Path(__file__).with_name("vendor") / "cytoscape-3.28.1.min.js"
        payload = asset.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != cls.CYTOSCAPE_SHA256:
            raise RuntimeError(f"vendored Cytoscape integrity check failed: {digest}")
        return payload.decode("utf-8")

    @classmethod
    def _font_css(cls) -> str:
        """Embed the original Google Fonts weights as data URLs for offline reports."""
        font_dir = Path(__file__).with_name("vendor") / "fonts"
        rules = []
        for filename, family, weight, expected in cls.FONT_MANIFEST:
            payload = (font_dir / filename).read_bytes()
            if hashlib.sha256(payload).hexdigest() != expected:
                raise RuntimeError(f"vendored font integrity check failed: {filename}")
            encoded = base64.b64encode(payload).decode("ascii")
            rules.append(
                f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};font-display:swap;"
                f"src:url(data:font/ttf;base64,{encoded}) format('truetype');}}"
            )
        return "".join(rules)

    @staticmethod
    def _json_for_script(value) -> str:
        """Serialize data without allowing it to terminate an HTML script block."""
        return (json.dumps(value)
                .replace("&", "\\u0026")
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029"))

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
        graph_json = cls._json_for_script(graph_data)

        policy_scripts = cls._generate_policy_scripts(analyses)
        cytoscape_js = cls._cytoscape_js()
        font_css = cls._font_css()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
    <title>IAM Security Report - {run_date}</title>
    <style>{font_css}{cls.CSS}</style>
    <script>{cytoscape_js}</script>
</head>
<body>
    <!-- Sidebar Navigation -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <div class="sidebar-logo-icon">&#9733;</div>
                PrivMapper
            </div>
            <div class="sidebar-version">Advanced v2.0</div>
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
                        <div style="font-size:12px;margin-top:8px">No critical issue was detected in the supplied graph. Review the methodology limits before treating this as assurance.</div>
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
        </div><!-- End main -->
        <footer class="site-footer">
            <div>
                Made with <span style="color:#e94560">&hearts;</span> by
                <a href="https://github.com/dr34mhacks" target="_blank" rel="noopener noreferrer">Sid</a>
            </div>
            <div>
                Built on the shoulders of
                <a href="https://github.com/nccgroup/PMapper" target="_blank" rel="noopener noreferrer">PMapper</a>
                by NCC Group
            </div>
        </footer>
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
                refs_html += f'<a href="{cls._escape(ref)}" target="_blank" rel="noopener noreferrer" style="color:var(--primary);text-decoration:none">{cls._escape(ref)}</a><br>'
            refs_html += '</div>'

        cvss = guidance.get("cvss_estimate", "")
        cvss_vector = guidance.get("cvss_vector", "")
        cvss_html = f'<span style="font-family:var(--mono);font-size:10px;color:var(--cr);margin-left:8px">{cls._escape(cvss)}</span>' if cvss else ""
        cvss_vector_html = (f'<p style="font-size:11px;margin-top:6px"><strong>Suggested contextual CVSS v3.1 (validate scope):</strong> '
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
                            <h4>Potential Abuse Scenario (validate prerequisites)</h4>
                            {exploit_html if exploit_html else f'<p style="font-size:12px;color:var(--tx2)">See AWS CLI commands below</p>'}
                        </div>
                    </div>
                    <div class="finding-section" style="margin-top:16px">
                        <h4>AWS CLI Validation / Controlled Proof of Concept</h4>
                        <p style="font-size:11px;color:var(--tx2);margin-bottom:8px">These commands are non-mutating validation aids. Supply the exact resource and required context values; simulator output can differ from live authorization.</p>
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
        sev = finding.severity.upper()
        n = len(finding.principals)
        affected = chr(10).join(finding.principals[:25])
        if len(finding.principals) > 25:
            affected += f"\n... (+{len(finding.principals) - 25} more)"
        evidence = guidance.get("evidence", "See affected principals and their attached policies.")
        principal_evidence = []
        for pd in finding.details.get("principals_detail", [])[:5]:
            rows = []
            for ev in pd.get("evidence", [])[:4]:
                resource = ", ".join(ev.get("resources") or ["*"])
                condition = json.dumps(ev.get("conditions") or {}, sort_keys=True)
                rows.append(
                    f"  - {ev.get('action', '')} via {ev.get('policy_name', '')}; "
                    f"Resource={resource}; Condition={condition or '{}'}"
                )
            if rows:
                principal_evidence.append(f"{pd.get('arn', pd.get('name', ''))}:\n" + "\n".join(rows))
        if principal_evidence:
            evidence += "\n\nCollected policy evidence (top 5 principals / 4 actions each):\n" + "\n".join(principal_evidence)
        remediation = finding.remediation
        report_text = (
            f"Title: {finding.title}\n"
            f"Severity: {sev}" + (f"  |  {cvss}" if cvss else "") + "\n"
            + (f"Suggested contextual CVSS (validate scope): {cvss_vector}\n" if cvss_vector else "")
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
            pw = 'Yes' if c.get('active_password') else 'No'
            mfa = ('Yes' if c.get('has_mfa') else "<span style='color:var(--cr)'>No</span>") \
                if c.get('active_password') else 'N/A'
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
        html += '<th>Role</th><th>Kind</th><th>Trusted principal</th><th>Admin</th><th>Privileged</th><th>Risk</th><th>Why</th>'
        html += '</tr></thead><tbody>'
        for t in trusts:
            tgt = '<span class="badge critical" style="font-size:8px">Yes</span>' if t.get('target_is_admin') else 'No'
            privileged = '<span class="badge high" style="font-size:8px">Yes</span>' if t.get('target_is_privileged') else 'No'
            html += (f"<tr><td><code>{cls._escape(t.get('role_name',''))}</code></td>"
                     f"<td>{cls._escape(t.get('principal_kind','AWS'))}</td>"
                     f"<td><code style='font-size:10px'>{cls._escape(str(t.get('trusted_principal',''))[:60])}</code></td>"
                     f"<td>{tgt}</td>"
                     f"<td>{privileged}</td>"
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
            for i, pd in enumerate(principals_detail):
                name = pd.get("name", pd.get("arn", "").split("/")[-1])
                arn = pd.get("arn", "")
                ptype = "role" if ":role/" in arn else "user"
                groups = pd.get("capability_groups", [])
                hidden_class = "principals-hidden" if i >= show_limit else ""
                badges = "".join(
                    f'<span class="badge {g.get("severity", "medium")}" style="font-size:8px;padding:2px 6px">'
                    f'{cls._escape(g.get("group", "Permissions"))} ({len(g.get("actions", []))})</span>'
                    for g in groups[:4]
                )
                evidence_html = ""
                for ev in pd.get("evidence", []):
                    source = {"group": "inherited from group", "inline": "inline policy", "admin": "AdministratorAccess"}.get(
                        ev.get("source", "attached"), "attached policy")
                    resources = ", ".join(ev.get("resources") or ["*"])
                    conditions = ev.get("conditions") or {}
                    condition_html = ""
                    if conditions:
                        condition_html = (f'<div style="font-size:9px;color:var(--hi);margin-top:3px">'
                                          f'Condition: <code>{cls._escape(json.dumps(conditions, sort_keys=True))}</code></div>')
                    evidence_html += f'''
                        <div style="padding:8px 0;border-bottom:1px solid var(--bd)">
                            <div style="font-size:11px"><code style="color:var(--cr)">{cls._escape(ev.get("action", ""))}</code>
                            &larr; {cls._escape(ev.get("policy_name", "unnamed policy"))}
                            <span style="color:var(--tx2)">({cls._escape(source)}{'; Sid ' + cls._escape(ev.get('sid', '')) if ev.get('sid') else ''})</span></div>
                            <div style="font-size:10px;margin-top:3px"><strong>Resource:</strong> <code>{cls._escape(resources)}</code></div>
                            {condition_html}
                            <div style="font-size:10px;color:var(--tx2);margin-top:4px">{cls._escape(ev.get("explanation", ""))}</div>
                        </div>'''
                omitted = pd.get("evidence_omitted_count", 0)
                if omitted:
                    evidence_html += f'<div style="font-size:10px;color:var(--hi);margin-top:6px">+{omitted} additional tracked actions; inspect the JSON export and attached policies.</div>'
                commands = "\n".join(pd.get("validation_commands", []))
                command_html = (f'<details style="margin-top:8px"><summary style="font-size:10px;cursor:pointer">Read-only validation commands</summary>'
                                f'<pre style="font-size:9px;white-space:pre-wrap;margin-top:6px">{cls._escape(commands)}</pre></details>') if commands else ""
                caveats = []
                if pd.get("permissions_boundary"):
                    caveats.append("permissions boundary body unresolved; result may be overstated" if pd.get("boundary_capped")
                                   else "permissions boundary included in the static action inventory")
                if pd.get("has_notaction"):
                    caveats.append("NotAction is present; review the full statement")
                if pd.get("unresolved_managed"):
                    caveats.append(f'{len(pd["unresolved_managed"])} managed-policy body/bodies unresolved; result may be understated')
                caveat_html = f'<div style="font-size:9px;color:var(--hi);margin-top:6px">&#9888; {cls._escape("; ".join(caveats))}</div>' if caveats else ""
                html += f'''<div class="principal-card {hidden_class}" data-principal-idx="{fid}">
                    <div class="principal-card-left" style="align-items:flex-start">
                        <div class="principal-card-icon {ptype}">{'R' if ptype == 'role' else 'U'}</div>
                        <div class="principal-card-info" style="min-width:0">
                            <div class="principal-card-name">{cls._escape(name)}</div>
                            <div class="principal-card-arn">{cls._escape(arn)}</div>
                            <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px">{badges}</div>
                            <details style="margin-top:8px" {'open' if i < 3 else ''}>
                                <summary style="font-size:10px;cursor:pointer">Why flagged: {pd.get('dangerous_action_count', len(pd.get('dangerous_actions', [])))} tracked high-impact action(s)</summary>
                                <div style="border-left:2px solid var(--bd);padding-left:9px;margin-top:6px">{evidence_html}</div>
                            </details>
                            {caveat_html}{command_html}
                        </div>
                    </div>
                    <div class="principal-card-actions"><button class="copy-arn-btn" onclick="event.stopPropagation();copyArn(this,'{cls._escape_js(arn)}')">Copy ARN</button></div>
                </div>'''

            if len(principals_detail) > show_limit:
                html += f'''<button class="show-more-btn" onclick="togglePrincipals(this, '{fid}')" data-showing="false">
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
                if pd.get("permissions_boundary"):
                    caveats.append("permissions boundary evaluated" if not pd.get("boundary_capped")
                                   else "permissions boundary body unresolved; access may be overstated")
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
        arns_json = cls._json_for_script(all_arns).replace("'", "\\'")

        query_explanations = {
            "Administrative Principals": {
                "what": "IAM principals with AdministratorAccess or equivalent full permissions",
                "why": "Admin principals are high-value targets. Compromise of any admin credential = full account takeover.",
                "check": "Verify each admin is necessary. Consider using permission boundaries even for admins."
            },
            "Privilege Escalation": {
                "what": "Non-admin principals who can escalate to admin through one or more steps",
                "why": "The graph contains a path to full access that can be overlooked in attachment-only IAM reviews.",
                "check": "Treat each as potentially admin-capable; validate conditions, SCPs/RCPs, session policies, and the current target trust before reporting."
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
                "why": "A usable path requires both a compatible target trust policy and authorization for the caller's sts:AssumeRole request. The per-hop evidence below shows what was actually found.",
                "impact": "A successful call returns a target-role session, subject to boundaries, session policies, SCPs and request conditions.",
                "verify_cli": "aws iam simulate-principal-policy --policy-source-arn <SOURCE_PRINCIPAL_ARN> --action-names sts:AssumeRole --resource-arns <TARGET_ROLE_ARN>\naws iam get-role --role-name <TARGET_ROLE_NAME>",
                "exploit_cli": "# After assuming the role, use the temporary credentials:\nexport AWS_ACCESS_KEY_ID=<AccessKeyId>\nexport AWS_SECRET_ACCESS_KEY=<SecretAccessKey>\nexport AWS_SESSION_TOKEN=<SessionToken>\naws sts get-caller-identity  # Verify you're now the target role"
            },
            "Lambda Function Abuse": {
                "what": "The attacker can create or modify Lambda functions that execute with a privileged role.",
                "why": "Having lambda:CreateFunction/UpdateFunctionCode with iam:PassRole allows creating functions that run with elevated privileges. The Lambda service assumes the execution role.",
                "impact": "Code execution in the context of privileged roles, enabling arbitrary AWS API calls.",
                "verify_cli": "aws lambda list-functions --query 'Functions[*].[FunctionName,Role]'\naws iam simulate-principal-policy --policy-source-arn <SOURCE_PRINCIPAL_ARN> --action-names iam:PassRole --resource-arns <TARGET_ROLE_ARN>\naws iam simulate-principal-policy --policy-source-arn <SOURCE_PRINCIPAL_ARN> --action-names lambda:CreateFunction --resource-arns '*'",
                "exploit_cli": "# Create a malicious Lambda that exfiltrates role credentials:\naws lambda create-function --function-name exploit-func \\\n  --runtime python3.9 --role <PRIVILEGED_ROLE_ARN> \\\n  --handler index.handler --zip-file fileb://exploit.zip\naws lambda invoke --function-name exploit-func output.txt"
            },
            "Lambda CreateFunction": {
                "what": "The source may be able to configure Lambda to run code with the target execution role.",
                "why": "A usable route requires resource-scoped iam:PassRole, function-creation permission, Lambda-compatible role trust, and a way to cause the function to execute. Review each prerequisite below.",
                "impact": "Successfully executed function code receives the target role's session credentials and effective permissions.",
                "verify_cli": "aws iam simulate-principal-policy --policy-source-arn <SOURCE_ARN> --action-names lambda:CreateFunction iam:PassRole --resource-arns <TARGET_ROLE_ARN>\naws iam get-role --role-name <TARGET_ROLE_NAME>",
                "exploit_cli": "# In an explicitly authorized test account, validate with a benign function that calls only sts:GetCallerIdentity."
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

            html += '<h4 style="margin-top:16px">Why these paths exist</h4>'
            for path_index, path in enumerate(tech_paths[:10], 1):
                html += f'''
                <details style="margin:8px 0;border:1px solid var(--bd);border-radius:6px;padding:9px 11px">
                    <summary style="cursor:pointer;color:var(--tx);font-size:12px;font-weight:600">
                        Path {path_index}: <code>{cls._escape(path.source.name)}</code> &rarr; <code>{cls._escape(path.target.name)}</code>
                    </summary>
                    <p style="font-size:11px;color:{'var(--olive)' if not path.missing_prerequisites else 'var(--cr)'};margin:9px 0 4px">
                        <strong>Evidence status:</strong> {cls._escape(path.evidence_status.replace('-', ' '))}. Live validation is still required.
                    </p>
                    <p style="font-size:12px;line-height:1.6;color:var(--tx2);margin:10px 0">{cls._escape(path.attack_narrative)}</p>
                '''
                if path.missing_prerequisites:
                    html += '<div style="font-size:12px;color:var(--tx);font-weight:600">Missing local prerequisites</div><ul style="font-size:11px;line-height:1.6;color:var(--cr);margin:4px 0 8px 18px">'
                    for prerequisite in path.missing_prerequisites:
                        html += f'<li>{cls._escape(prerequisite)}</li>'
                    html += '</ul>'
                for hop in path.hop_explanations:
                    html += f'''
                    <div style="border-left:3px solid var(--hi);padding:7px 10px;margin:9px 0;background:var(--bg2)">
                        <div style="font-size:12px;font-weight:600;color:var(--tx)">Step {hop["step"]}: {cls._escape(hop["mechanism"])}</div>
                        <div style="font-size:11px;color:var(--tx2);margin-top:4px"><code>{cls._escape(hop["source"])}</code> &rarr; <code>{cls._escape(hop["target"])}</code></div>
                        <p style="font-size:12px;line-height:1.55;color:var(--tx2);margin:7px 0"><strong style="color:var(--tx)">Why:</strong> {cls._escape(hop["why"])}</p>
                        <p style="font-size:12px;line-height:1.55;color:var(--tx2);margin:7px 0"><strong style="color:var(--tx)">Graph proof:</strong> {cls._escape(hop["graph_evidence"].get("reason", ""))}</p>
                    '''
                    policy_evidence = hop.get("identity_policy_evidence", [])
                    if policy_evidence:
                        html += '<div style="font-size:12px;color:var(--tx);font-weight:600">Identity-policy evidence</div><ul style="font-size:11px;line-height:1.6;color:var(--tx2);margin:4px 0 6px 18px">'
                        for evidence in policy_evidence:
                            conditions = evidence.get("conditions") or {}
                            condition_text = json.dumps(conditions, sort_keys=True) if conditions else "none"
                            scope_label = "not-resources" if evidence.get("not_resources") else "resources"
                            scope_value = evidence.get("not_resources") or evidence.get("resources", [])
                            html += (
                                f'<li><code>{cls._escape(evidence["action"])}</code> from '
                                f'<code>{cls._escape(evidence["policy_name"])}</code> '
                                f'({cls._escape(evidence["attachment_source"])}); {scope_label} '
                                f'<code>{cls._escape(json.dumps(scope_value))}</code>; '
                                f'conditions <code>{cls._escape(condition_text)}</code></li>'
                            )
                        html += '</ul>'
                    else:
                        html += '<p style="font-size:11px;color:var(--cr);margin:5px 0">No matching identity-policy statement was retained; validate this edge against the live policies.</p>'

                    trust_evidence = hop.get("target_trust_evidence", [])
                    if trust_evidence:
                        html += '<div style="font-size:12px;color:var(--tx);font-weight:600">Target trust evidence</div><ul style="font-size:11px;line-height:1.6;color:var(--tx2);margin:4px 0 6px 18px">'
                        for trust in trust_evidence:
                            html += (
                                f'<li>Principal <code>{cls._escape(json.dumps(trust.get("principal", {}), sort_keys=True))}</code>; '
                                f'actions <code>{cls._escape(json.dumps(trust.get("actions", [])))}</code>; '
                                f'conditions <code>{cls._escape(json.dumps(trust.get("conditions", {}), sort_keys=True))}</code></li>'
                            )
                        html += '</ul>'
                    else:
                        html += '<p style="font-size:11px;color:var(--olive);margin:5px 0">No matching target-trust statement was extracted; inspect the live role trust policy.</p>'
                    html += f'''
                        <p style="font-size:12px;line-height:1.55;color:var(--tx2);margin:7px 0"><strong style="color:var(--tx)">Access gained:</strong> {cls._escape(hop["access_gained"])}</p>
                    </div>
                    '''

                html += f'''
                    <div style="font-size:12px;line-height:1.6;color:var(--tx2);margin-top:9px"><strong style="color:var(--tx)">Result if successful:</strong> {cls._escape(path.resulting_access)}</div>
                    <div style="font-size:12px;color:var(--tx);font-weight:600;margin-top:9px">Validate before reporting as exploitable</div>
                    <ul style="font-size:11px;line-height:1.6;color:var(--tx2);margin:4px 0 2px 18px">
                '''
                for note in path.validation_notes:
                    html += f'<li>{cls._escape(note)}</li>'
                html += '</ul></details>'

            verify_cli = tech_info.get("verify_cli", "")
            # Reports contain non-mutating validation commands only. Abuse mechanics
            # are explained in prose and per-hop evidence, not supplied as execution recipes.
            combined_cli = verify_cli

            if combined_cli:
                html += f'''
                <details style="margin-top:12px">
                    <summary style="cursor:pointer;color:var(--hi);font-size:12px;font-weight:500">Read-only validation commands</summary>
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

                policy_json_str = cls._json_for_script(policy_doc)
                issues_json = cls._json_for_script(dangerous_in_policy)

                scripts.append(
                    f"registerPolicy({cls._json_for_script(policy_arn)}, {policy_json_str}, {issues_json});"
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
            "Ad-hoc queries evaluate Action/NotAction and Resource/NotResource wildcards against the requested resource",
            "Escalation evidence uses PMapper authentication edges and preserves distinct paths up to five hops",
            "Trust policies: AWS, Federated (SAML/OIDC incl. GitHub Actions), and Service principals; ExternalId enforcement is verified, not just presence",
            "Credential hygiene: MFA, console password, and long-term access keys",
        ]
        does_not = [
            "Service Control Policies (SCPs) and Resource Control Policies (RCPs) - org guardrails are NOT modeled; a finding may be capped by an SCP",
            "Resource-based policies (S3 bucket / KMS key / SNS policies) and session policies",
            "Runtime condition evaluation (source IP, aws:PrincipalTag, time) - conditions are noted, not simulated",
            "AWS-managed policy bodies not in the built-in catalog (flagged per-principal as 'unresolved' so capabilities are not silently understated)",
            "Access-key AGE and last-used, and unused permissions (collect from an IAM credential report / Access Analyzer to complete the assessment)",
            "Escalation chains longer than five hops (the enumeration limit used to keep cyclic graphs tractable)",
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
