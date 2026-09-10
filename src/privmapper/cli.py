"""Command-line interface and run orchestration for PrivMapper."""

import argparse
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List

from .models import AccountAnalysis, Finding, RunMetadata
from .knowledge import (AWS_MANAGED_PATTERNS, CHECK_LABEL, COMPUTE_CHECKS, CRED_CHECKS,
                        EXCLUDE_REGIONS, IAM_CHECKS, IAM_WILDCARD_THRESHOLD)
from .utils import err, log, ok
from .loader import GraphLoader, find_pmapper_graphs
from .runner import PMapperRunner
from .analysis import AnalysisEngine
from .queries import QueryEngine, QueryResultsAnalyzer
from .crossaccount import CrossAccountAnalyzer
from .reporting.json_export import JSONExporter
from .reporting.csv_export import CSVExporter
from .reporting.html_export import HTMLExporter


def main():
    parser = argparse.ArgumentParser(
        description=("Evidence-backed AWS IAM graph analysis and reporting. "
                     "Analyze existing PMapper data or collect multiple AWS profiles concurrently."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run pmapper with auto-detected regions (recommended)
  %(prog)s --profile my-aws-profile --create-graph
  %(prog)s --profile profile1 --profile profile2 --create-graph
  %(prog)s --profiles profile1 profile2 profile3 --workers 3
  %(prog)s --profile-file ./aws-profiles.txt --create-graph

  # Run pmapper with explicitly excluded regions
  %(prog)s --profile my-aws-profile

  # Read existing pmapper graph data
  %(prog)s --input /path/to/pmapper/graph/
  %(prog)s --input ./account1 --input ./account2

  # Export formats
  %(prog)s --profile prod --format html,json,csv

  # Auto-detect existing pmapper data
  %(prog)s --auto-detect

  # No arguments: print this help menu and perform no scan
  %(prog)s

  # PMapper-style queries (requires --input or --profile)
  %(prog)s -i ./graph --query "who can do iam:CreateUser"
  %(prog)s -i ./graph --query "who can do s3:GetObject"
  %(prog)s -i ./graph --query "sts:AssumeRole"

  # Preset queries
  %(prog)s -i ./graph --preset privesc      # Privilege escalation paths
  %(prog)s -i ./graph --preset admin        # All admin principals
  %(prog)s -i ./graph --preset shadow       # Shadow admins
  %(prog)s -i ./graph --preset secrets      # Secrets access
  %(prog)s -i ./graph --preset dangerous    # Any dangerous permissions
        """,
    )

    parser.add_argument(
        "--profile", "-p",
        action="append",
        dest="profiles",
        metavar="PROFILE",
        help="AWS profile to collect; repeat or use comma-separated names.",
    )
    parser.add_argument(
        "--profiles",
        action="append",
        nargs="+",
        dest="profile_groups",
        metavar="PROFILE",
        help="One or more AWS profiles to collect concurrently.",
    )
    parser.add_argument(
        "--profile-file",
        action="append",
        dest="profile_files",
        metavar="PATH",
        help="Text file containing newline- or comma-separated AWS profile names; repeatable.",
    )

    parser.add_argument(
        "--input", "-i",
        action="append",
        dest="inputs",
        metavar="PATH",
        help="Path to pmapper graph directory (can specify multiple)",
    )

    parser.add_argument(
        "--output", "-o",
        default=f"privmapper_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output directory (default: privmapper_report_TIMESTAMP)",
    )
    parser.add_argument(
        "--format", "-f",
        default="html",
        help="Output formats: html,json,csv (comma-separated) or all (default: html)",
    )
    parser.add_argument(
        "--auto-detect", "-a",
        action="store_true",
        help="Auto-detect pmapper graph directories",
    )
    parser.add_argument(
        "--exclude-regions",
        default=EXCLUDE_REGIONS,
        help="Regions to exclude during graph creation (space-separated)",
    )
    parser.add_argument(
        "--create-graph",
        action="store_true",
        help="Auto-detect enabled regions and run pmapper graph create (recommended)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Maximum profiles to collect concurrently (default: 4)",
    )

    parser.add_argument(
        "--query", "-Q",
        metavar="QUERY",
        help="PMapper-style query (e.g., 'who can do iam:CreateUser', 'who can do s3:GetObject with arn:aws:s3:::bucket/*')",
    )
    parser.add_argument(
        "--preset",
        choices=["privesc", "admin", "shadow", "cross-account", "ssm", "secrets", "s3", "dangerous"],
        help="Run preset query (privesc=privilege escalation, admin=all admins, shadow=shadow admins, etc.)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1337,
        help="Port for local HTTP server to view report (default: 1337)",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start HTTP server after generating report",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    profile_values = list(args.profiles or [])
    for group in args.profile_groups or []:
        profile_values.extend(group)
    for profile_file in args.profile_files or []:
        path = Path(profile_file).expanduser()
        try:
            content = path.read_text()
        except OSError as ex:
            parser.error(f"cannot read --profile-file {profile_file}: {ex}")
        for line in content.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                profile_values.extend(line.split(","))
    profiles = []
    for value in profile_values:
        profiles.extend(name.strip() for name in value.split(",") if name.strip())
    args.profiles = list(dict.fromkeys(profiles)) or None

    valid_formats = {"html", "json", "csv"}
    if args.format.strip().lower() == "all":
        args.format = "html,json,csv"
    requested_formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    invalid_formats = requested_formats - valid_formats
    if not requested_formats or invalid_formats:
        parser.error("--format must be all or contain only: html,json,csv")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if (args.profile_groups or args.profile_files) and not args.profiles:
        parser.error("profile list input did not contain any profile names")
    if args.profiles and (args.inputs or args.auto_detect):
        parser.error("profile inputs cannot be combined with --input or --auto-detect")

    output_dir = Path(args.output)
    analyses = []
    profile_results = {}

    run_metadata = RunMetadata(
        run_timestamp=datetime.now().strftime("%d %b %Y %H:%M:%S"),
        output_directory=str(output_dir.absolute()),
        output_formats=[f.strip().lower() for f in args.format.split(",")],
    )

    all_regions_used: List[str] = []
    all_regions_excluded: List[str] = []

    if args.profiles:
        print(f"\n{'='*60}")
        print("  PrivMapper Advanced - IAM Security Analysis")
        print("  Mode: Run PMapper")
        print(f"  Profiles: {', '.join(args.profiles)}")
        if args.create_graph:
            print("  Region Detection: Auto (enabled regions only)")
        print(f"{'='*60}\n")

        output_dir.mkdir(parents=True, exist_ok=True)

        workers = max(1, min(args.workers, len(args.profiles)))
        log(f"Collecting {len(args.profiles)} profile(s) with {workers} concurrent worker(s)")
        profile_runs = {}
        runners = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="privmapper") as executor:
            future_to_profile = {}
            for profile in args.profiles:
                runner = PMapperRunner(
                    profile,
                    output_dir,
                    exclude_regions=args.exclude_regions,
                    auto_detect_regions=args.create_graph,
                )
                runners[profile] = runner
                future_to_profile[executor.submit(runner.run_full_analysis)] = profile

            for future in as_completed(future_to_profile):
                profile = future_to_profile[future]
                try:
                    profile_runs[profile] = future.result()
                except Exception as ex:
                    err(f"Profile {profile} failed: {ex}")

        for profile in args.profiles:
            log(f"{'═'*50}")
            log(f"Profile: {profile}")
            log(f"{'═'*50}")

            runner = runners[profile]
            if profile not in profile_runs:
                continue
            stats, results, svg_path = profile_runs[profile]

            if runner.regions_used:
                all_regions_used.extend(runner.regions_used)
                run_metadata.auto_detected_regions = runner.used_auto_detect
            if runner.regions_excluded:
                all_regions_excluded.extend(runner.regions_excluded)

            if not stats:
                err(f"Failed to analyze {profile}")
                continue

            # Prefer the generated JSON graph so live scans receive exactly the
            # same boundary, trust, credential, evidence, and path analysis as
            # --input mode. Text-query parsing remains a compatibility fallback.
            graph_path = runner.find_graph_path(stats.get("account_id", ""))
            if graph_path:
                loader = GraphLoader(graph_path)
                try:
                    principals, edges, policies = loader.load()
                except ValueError as ex:
                    err(f"Profile {profile} produced an invalid graph: {ex}")
                    continue
                analysis = AnalysisEngine(
                    principals, edges, policies, stats.get("account_id", "")
                ).analyze()
                analysis.account_alias = profile
                analyses.append(analysis)
                profile_results[profile] = {
                    "stats": stats,
                    "results": results,
                    "svg_path": svg_path,
                    "graph_path": graph_path,
                }
                ok(f"Profile {profile} complete - {len(analysis.findings)} findings, "
                   f"{len(analysis.escalation_paths)} paths")
                continue

            profile_results[profile] = {
                "stats": stats,
                "results": results,
                "svg_path": svg_path,
            }

            analyzer = QueryResultsAnalyzer(results, stats)
            capabilities = analyzer.build_principal_capabilities()
            privesc_paths = analyzer.get_privesc_paths()
            shadow_admins = analyzer.get_shadow_admins()
            admins = analyzer.get_admins()

            findings = []

            non_managed_admins = [a for a in admins if not any(re.search(p, a) for p in AWS_MANAGED_PATTERNS)]
            if non_managed_admins:
                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_admin_access",
                    title="Principals with Administrator Access",
                    severity="critical",
                    category="iam",
                    description="These principals have full administrative access to all AWS services.",
                    principals=list(non_managed_admins),
                    impact="Compromise of any of these credentials results in full account takeover.",
                    remediation="Review each admin principal. Remove AdministratorAccess where not required.",
                ))

            if shadow_admins:
                shadow_details = []
                for sa in shadow_admins[:20]:
                    caps = capabilities.get(sa, set())
                    shadow_details.append({
                        "arn": sa,
                        "name": sa.split("/")[-1] if "/" in sa else sa,
                        "capabilities": [CHECK_LABEL.get(c, c) for c in sorted(caps) if c in CHECK_LABEL][:10],
                    })

                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_shadow_admin",
                    title="Shadow Administrators",
                    severity="critical",
                    category="iam",
                    description="These principals can escalate to admin privileges without having "
                               "AdministratorAccess policy attached.",
                    principals=shadow_admins,
                    impact="Hidden administrative access that bypasses standard security reviews.",
                    remediation="Remove excessive permissions that enable privilege escalation.",
                    details={"principals_detail": shadow_details},
                ))

            overly_permissive = []
            for principal, caps in sorted(capabilities.items(), key=lambda x: -len(x[1])):
                if principal in admins or principal in shadow_admins:
                    continue
                if any(re.search(p, principal) for p in AWS_MANAGED_PATTERNS):
                    continue
                if len(caps) >= 3:
                    iam_caps = caps & IAM_CHECKS
                    groups = []
                    if len(iam_caps) >= IAM_WILDCARD_THRESHOLD:
                        groups.append({"group": "iam:*", "severity": "critical"})
                    elif iam_caps:
                        groups.append({"group": "IAM (specific)", "severity": "high"})
                    if caps & CRED_CHECKS:
                        groups.append({"group": "Credential Access", "severity": "high"})
                    if caps & COMPUTE_CHECKS:
                        groups.append({"group": "Service Compute Abuse", "severity": "high"})

                    overly_permissive.append({
                        "arn": principal,
                        "name": principal.split("/")[-1] if "/" in principal else principal,
                        "severity": "critical" if len(iam_caps) >= IAM_WILDCARD_THRESHOLD else "high",
                        "capabilities": [CHECK_LABEL.get(c, c) for c in sorted(caps) if c in CHECK_LABEL][:8],
                        "capability_groups": groups,
                    })

            if overly_permissive:
                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_overly_permissive",
                    title="Overly Permissive IAM Principals",
                    severity="high",
                    category="iam",
                    description="These principals have permissions significantly broader than required.",
                    principals=[op["arn"] for op in overly_permissive[:20]],
                    impact="Increased blast radius in case of credential compromise.",
                    remediation="Apply least-privilege principles. Use IAM Access Analyzer.",
                    details={"principals_detail": overly_permissive[:20]},
                ))

            if privesc_paths:
                findings.append(Finding(
                    id=f"{stats.get('account_id', 'unknown')}_privesc",
                    title=f"Privilege Escalation Paths ({len(privesc_paths)} found)",
                    severity="critical",
                    category="privesc",
                    description="Non-admin principals can escalate to administrative access.",
                    principals=sorted(set(p.get("source", "") for p in privesc_paths[:20])),
                    impact="Attackers with access to these principals can gain full account control.",
                    remediation="Remove or restrict permissions that enable escalation.",
                    details={"paths": privesc_paths[:20]},
                ))

            analysis = AccountAnalysis(
                account_id=stats.get("account_id", "unknown"),
                account_alias=profile,
                node_count=int(stats.get("nodes", 0)),
                edge_count=int(stats.get("edges", 0)),
                admin_count=int(stats.get("admins", 0)),
                principals={},
                edges=[],
                policies={},
                findings=findings,
                escalation_paths=[],
                cross_account_trusts=[],
                shadow_admins=[],
                overly_permissive=[],
            )
            analyses.append(analysis)

            ok(f"Profile {profile} complete - {len(findings)} findings")

    else:
        input_paths = []

        if args.inputs:
            for p in args.inputs:
                path = Path(p)
                if path.exists():
                    if (path / "nodes.json").exists():
                        input_paths.append(path)
                    elif (path / "graph" / "nodes.json").exists():
                        input_paths.append(path / "graph")
                    else:
                        for subdir in path.iterdir():
                            if subdir.is_dir():
                                if (subdir / "nodes.json").exists():
                                    input_paths.append(subdir)
                                elif (subdir / "graph" / "nodes.json").exists():
                                    input_paths.append(subdir / "graph")
                else:
                    print(f"[!] Path not found: {p}")

        if args.auto_detect or not input_paths:
            detected = find_pmapper_graphs()
            if detected:
                print(f"[*] Auto-detected {len(detected)} pmapper graph(s)")
                input_paths.extend(detected)

        if not input_paths:
            print("[!] No pmapper graph data found.")
            print("    Use --profile to run pmapper, or --input to specify graph data")
            print("    Example: python privmapper_advanced.py --profile my-aws-profile")
            print("    Example: python privmapper_advanced.py --input /path/to/graph/")
            sys.exit(1)

        input_paths = list(dict.fromkeys(input_paths))

        print(f"\n{'='*60}")
        print("  PrivMapper Advanced - IAM Security Analysis")
        print("  Mode: Read Existing Graph Data")
        print(f"  Analyzing {len(input_paths)} graph(s)")
        print(f"{'='*60}\n")

        for graph_path in input_paths:
            print(f"[*] Loading: {graph_path}")

            loader = GraphLoader(graph_path)
            if not loader.validate():
                print(f"[!] Invalid graph directory: {graph_path}")
                continue

            try:
                principals, edges, policies = loader.load()
            except ValueError as ex:
                print(f"[!] Could not load graph {graph_path}: {ex}")
                continue
            print(f"    Loaded {len(principals)} principals, {len(edges)} edges, {len(policies)} policies")

            engine = AnalysisEngine(principals, edges, policies)
            analysis = engine.analyze()
            analyses.append(analysis)

            print(f"    Found {len(analysis.findings)} findings, {len(analysis.escalation_paths)} escalation paths")

    if not analyses:
        print("[!] No valid graphs to analyze")
        sys.exit(1)

    if args.query or args.preset:
        for analysis in analyses:
            query_engine = QueryEngine(analysis)

            if args.query:
                print(f"\n[*] Running query: {args.query}")
                results = query_engine.query(args.query)
                query_engine.print_results(results, f"Query: {args.query}")

            if args.preset:
                preset_info = QueryEngine.PRESETS.get(args.preset, {})
                print(f"\n[*] Running preset: {args.preset}")
                results = query_engine.run_preset(args.preset)
                query_engine.print_results(results, preset_info.get("name", args.preset))

        if not args.format or args.format == "html":
            print("\n[*] Query complete. Use --format to also generate a full report.")
            sys.exit(0)

    cross_findings = []
    if len(analyses) > 1:
        print("\n[*] Running cross-account analysis...")
        cross_analyzer = CrossAccountAnalyzer(analyses)
        cross_findings = cross_analyzer.analyze()
        print(f"    Found {len(cross_findings)} cross-account findings")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.profiles:
        run_metadata.profiles = args.profiles
    if args.inputs:
        run_metadata.input_paths = [str(p) for p in args.inputs] if args.inputs else []
    run_metadata.regions_used = list(dict.fromkeys(all_regions_used))
    run_metadata.regions_excluded = list(dict.fromkeys(all_regions_excluded))

    formats = [f.strip().lower() for f in args.format.split(",")]

    if "html" in formats:
        HTMLExporter.export(analyses, cross_findings, output_dir / "report.html", run_metadata)

    if "json" in formats:
        JSONExporter.export(analyses, output_dir / "findings.json", cross_findings)

    if "csv" in formats:
        CSVExporter.export(analyses, output_dir / "findings.csv", cross_findings)

    print(f"\n{'='*60}")
    print("  Analysis Complete")
    print(f"  Output: {output_dir}/")
    print(f"{'='*60}\n")

    total_critical = sum(len([f for f in a.findings if f.severity == "critical"]) for a in analyses)
    total_paths = sum(len(a.escalation_paths) for a in analyses)

    if total_critical > 0:
        print(f"  [!] {total_critical} CRITICAL findings require immediate attention")
    if total_paths > 0:
        print(f"  [!] {total_paths} privilege escalation paths detected")

    if "html" in formats and not args.no_server:
        print(f"\n  Starting local server on port {args.port}...")
        print(f"  Open in browser: http://localhost:{args.port}/report.html")
        print("  Press Ctrl+C to stop the server\n")

        import http.server
        import socketserver

        os.chdir(output_dir)

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

        try:
            with socketserver.TCPServer(("127.0.0.1", args.port), QuietHandler) as httpd:
                httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"  [!] Port {args.port} is already in use. Use --port to specify a different port.")
            else:
                print(f"  [!] Could not start server: {e}")
            print(f"\n  Open report manually: open {output_dir}/report.html\n")
    elif "html" in formats:
        print(f"\n  Open report: open {output_dir}/report.html\n")
    else:
        generated = [str(output_dir / ("findings.json" if f == "json" else "findings.csv"))
                     for f in formats if f in ("json", "csv")]
        print(f"\n  Generated: {', '.join(generated)}\n")
