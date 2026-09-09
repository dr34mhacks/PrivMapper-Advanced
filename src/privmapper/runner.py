"""Drive the pmapper CLI: region detection, graph creation, preset/manual queries."""

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .knowledge import EXCLUDE_REGIONS, MANUAL_QUERIES, PRESET_QUERIES
from .utils import err, log, ok, warn


def get_enabled_regions(profile: str) -> List[str]:
    """Query AWS to get list of enabled (opted-in) regions for the account."""
    log(f"[*] Detecting enabled regions for profile: {profile}")

    try:
        cmd = [
            "aws", "ec2", "describe-regions",
            "--region", "us-east-1",
            "--query", "Regions[?OptInStatus!=`not-opted-in`].RegionName",
            "--output", "text",
            "--profile", profile
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            err(f"Failed to query regions: {result.stderr}")
            return []

        regions = result.stdout.strip().split()
        if regions:
            ok(f"    Found {len(regions)} enabled regions")
            return regions
        else:
            warn("    No regions returned, using default list")
            return []

    except FileNotFoundError:
        err("AWS CLI not found - install with: pip install awscli")
        return []
    except subprocess.TimeoutExpired:
        err("Region query timed out")
        return []
    except Exception as ex:
        err(f"Region query failed: {ex}")
        return []


class PMapperRunner:
    """Run pmapper commands and collect results."""

    def __init__(self, profile: str, output_dir: Path,
                 exclude_regions: str = EXCLUDE_REGIONS,
                 include_regions: Optional[List[str]] = None,
                 auto_detect_regions: bool = False):
        self.profile = profile
        self.output_dir = output_dir
        self.exclude_regions = exclude_regions
        self.include_regions = include_regions
        self.auto_detect_regions = auto_detect_regions
        self.profile_dir = output_dir / profile
        self.preset_dir = self.profile_dir / "presets"
        self.query_dir = self.profile_dir / "queries"
        self.regions_used: List[str] = []
        self.regions_excluded: List[str] = []
        self.used_auto_detect: bool = False

        for d in (self.profile_dir, self.preset_dir, self.query_dir):
            d.mkdir(parents=True, exist_ok=True)

    def run_command(self, args: List[str], outfile: Optional[Path] = None,
                   label: str = "", timeout: int = 600) -> Tuple[bool, str]:
        """Run a pmapper command. Returns (success, output)."""
        env = os.environ.copy()
        env["AWS_STS_REGIONAL_ENDPOINTS"] = "legacy"

        cmd = ["pmapper", "--profile", self.profile] + args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout
            )
            output = result.stdout + result.stderr

            if outfile:
                outfile.parent.mkdir(parents=True, exist_ok=True)
                with open(outfile, "a") as f:
                    f.write(output)

            if result.returncode == 0:
                if label:
                    ok(f"  {label}")
                return True, output
            else:
                if label:
                    warn(f"  {label} (non-zero exit)")
                return False, output

        except FileNotFoundError:
            err("pmapper not found - install with: pip install principalmapper")
            return False, ""
        except subprocess.TimeoutExpired:
            if label:
                warn(f"  {label} (timeout after {timeout}s)")
            return False, ""
        except Exception as ex:
            if label:
                warn(f"  {label} ({ex})")
            return False, ""

    def create_graph(self) -> bool:
        """Create the pmapper graph for this profile."""
        log("[1/5] Creating IAM graph")
        graph_log = self.profile_dir / "01_graph_create.log"

        args = ["graph", "create"]

        regions_to_use = self.include_regions

        if self.auto_detect_regions and not regions_to_use:
            regions_to_use = get_enabled_regions(self.profile)
            self.used_auto_detect = True

        if regions_to_use:
            log(f"    Using {len(regions_to_use)} regions: {', '.join(regions_to_use[:5])}{'...' if len(regions_to_use) > 5 else ''}")
            args += ["--include-regions"] + regions_to_use
            self.regions_used = regions_to_use
        elif self.exclude_regions:
            excluded = self.exclude_regions.split()
            args += ["--exclude-regions"] + excluded
            self.regions_excluded = excluded

        success, output = self.run_command(args, graph_log, "graph create", timeout=600)

        verify_success, verify_output = self.run_command(["graph", "display"])
        if "Nodes" in verify_output or "nodes" in verify_output.lower():
            ok("  Graph verified")
            return True
        elif not success:
            err(f"  Graph creation failed for {self.profile}")
            return False

        return True

    def get_graph_stats(self) -> Dict[str, str]:
        """Get graph statistics."""
        log("[2/5] Getting graph stats")
        stats_file = self.profile_dir / "02_graph_stats.txt"
        success, output = self.run_command(["graph", "display"], stats_file, "graph stats")

        stats = {}
        for line in output.splitlines():
            if "Account" in line:
                m = re.search(r"(\d{10,})", line)
                if m:
                    stats["account_id"] = m.group(1)
            elif "Nodes" in line:
                m = re.search(r"(\d+)\s*\((\d+)\s*admin", line)
                if m:
                    stats["nodes"] = m.group(1)
                    stats["admins"] = m.group(2)
            elif "Edges" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    stats["edges"] = m.group(1)

        return stats

    def run_preset_queries(self) -> Dict[str, List[str]]:
        """Run all preset queries and return results."""
        log("[3/5] Running preset queries")
        results = {}

        for key, args, label in PRESET_QUERIES:
            outfile = self.preset_dir / f"{key}.txt"
            outfile.write_text(f"Query: {' '.join(args)}\n---\n")
            success, output = self.run_command(args, outfile, label)
            results[key] = self._parse_query_output(output)

        return results

    def run_manual_queries(self) -> Dict[str, List[str]]:
        """Run all manual queries and return results."""
        log("[4/5] Running manual queries")
        results = {}
        total = len(MANUAL_QUERIES)

        for i, (key, query) in enumerate(MANUAL_QUERIES, 1):
            outfile = self.query_dir / f"{key}.txt"
            outfile.write_text(f"Query: {query}\n---\n")
            success, output = self.run_command(["query", query], outfile)
            results[key] = self._parse_query_output(output)

            pct = int(i / total * 30)
            bar = "█" * pct + "░" * (30 - pct)
            print(f"\r  [{bar}] {i}/{total} {key:<40}", end="", flush=True)

        print()
        return results

    def generate_visualization(self) -> Optional[Path]:
        """Generate SVG visualization."""
        log("[5/5] Generating SVG visualization")
        svg_out = self.profile_dir / "graph.svg"
        t_before = time.time()

        self.run_command(["visualize", "--filetype", "svg"], label="SVG generation")

        search_dirs = [
            Path.home() / ".local" / "share" / "principalmapper",
            Path.home() / ".principalmapper",
            Path("."),
        ]

        found_svg = None
        for sdir in search_dirs:
            if not sdir.exists():
                continue
            for svg in sdir.rglob("*.svg"):
                if svg.stat().st_mtime >= t_before - 2:
                    found_svg = svg
                    break
            if found_svg:
                break

        if found_svg:
            shutil.copy2(str(found_svg), str(svg_out))
            ok(f"  SVG saved to {svg_out}")
            return svg_out
        else:
            warn("  SVG not found")
            return None

    def _parse_query_output(self, output: str) -> List[str]:
        """Parse pmapper query output into list of findings."""
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Query:") or line == "---":
                continue
            if "No results" in line or "0 results" in line:
                continue
            findings.append(line)
        return findings

    def run_full_analysis(self) -> Tuple[Dict[str, str], Dict[str, List[str]], Optional[Path]]:
        """Run complete pmapper analysis. Returns (stats, all_results, svg_path)."""
        if not self.create_graph():
            return {}, {}, None

        stats = self.get_graph_stats()

        preset_results = self.run_preset_queries()
        manual_results = self.run_manual_queries()

        all_results = {**preset_results, **manual_results}

        svg_path = self.generate_visualization()

        ok(f"Profile {self.profile} complete")
        return stats, all_results, svg_path
