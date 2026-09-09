<p align="center">
  <img src="docs/logo.png" alt="PrivMapper Advanced - AWS IAM attack path analysis & reporting" width="640">
</p>

<p align="center">
  <b>AWS IAM privilege-escalation analysis that comes out as an assessment-ready report.</b><br>
  <sub>Grouped findings · full attack paths · interactive graph · per-finding evidence, CVSS &amp; MITRE · copy-paste write-ups</sub>
</p>

<p align="center">
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square">
  <img alt="Dependencies: none" src="https://img.shields.io/badge/deps-none%20(stdlib)-brightgreen?style=flat-square">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img alt="Built on PMapper" src="https://img.shields.io/badge/built%20on-PMapper-84a98c?style=flat-square">
</p>

<p align="center">
  <a href="#install--run">Install</a> ·
  <a href="#what-you-get">What you get</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#limitations">Limitations</a>
</p>

---

**PrivMapper** turns a [PMapper](https://github.com/nccgroup/PMapper) IAM graph into the report a security team actually ships: grouped findings, full multi-hop escalation chains, an interactive attack graph, and a copy-paste write-up for every finding. It reads a graph offline (no AWS access needed to analyse) or runs PMapper for you across profiles.

Under the hood it evaluates IAM the way AWS does (explicit `Deny`, `NotAction`, permissions boundaries, inline and group-inherited policies, AWS-managed policies, and trust across AWS / federated / service principals). That is the point: it surfaces what a raw graph misses (credential hygiene, GitHub-OIDC trust, confused-deputy, boundary-capped access) and drops the false positives a naive "who has `iam:*`" check throws.

<p align="center">
  <img src="docs/screenshot-dashboard.jpg" alt="PrivMapper dashboard: severity summary, finding counts and methodology panel" width="900">
  <br><sub>Dashboard: at-a-glance severity summary, and a methodology panel that states what the analysis does and does not evaluate.</sub>
</p>

## What you get

| Finding | What it shows |
|---|---|
| **Administrator Access** | Full-admin principals, separated from AWS-managed / service admin roles |
| **Shadow Administrators** | Admin-equivalent access with no `AdministratorAccess` attached, plus the exact policy statement that grants it |
| **Overly Permissive** | Broad access ranked by risk, deduplicated against shadow admins |
| **Escalation Paths** | Every route to admin, grouped by technique, with full hop chains and a per-path risk score |
| **Risky Trust** | Cross-account, federated (GitHub OIDC / SAML) and service confused-deputy trust, with enforcement-aware `ExternalId` checks |
| **Credential Hygiene** | Console and privileged users without MFA, and long-term access keys |

Every finding carries a CVSS v3.1 vector, MITRE ATT&CK mapping, validation + exploitation AWS CLI, concrete evidence, and a ready-to-paste report block.

<p align="center">
  <img src="docs/screenshot-finding.jpg" alt="A finding showing per-principal evidence and exploitation steps" width="900">
  <br><sub>Each finding names the exact policy statement that grants each dangerous action (including via groups), with impact and exploitation steps.</sub>
</p>

<p align="center">
  <img src="docs/screenshot-paths.jpg" alt="Privilege escalation paths grouped by technique with full hop chains" width="900">
  <br><sub>Escalation paths grouped by technique, with the full multi-hop chain, hop count and per-path risk.</sub>
</p>

## Install & run

No third-party dependencies for analysis (Python 3.9+, standard library only).

```bash
git clone https://github.com/dr34mhacks/privmapper
cd privmapper
python privmapper.py --input examples/sample_graph --output ./report
```

This analyses the bundled example graph and serves the report at `http://127.0.0.1:1337` (add `--no-server` to only write files).

PrivMapper ships in **two equivalent forms** from one source (byte-identical output, pick either):

```bash
python privmapper.py ...                 # single self-contained file, drop-in
PYTHONPATH=src python -m privmapper ...   # modular package (src/privmapper/)
pip install .  &&  privmapper ...         # installed CLI on PATH
pip install ".[pmapper]"                  # + principalmapper, for live --profile collection
```

## Usage

```bash
python privmapper.py --input ~/.local/share/principalmapper/<account>/graph   # your own graph
python privmapper.py --profile prod --profile staging --create-graph          # collect live
python privmapper.py --input ./graph --query "who can do iam:PassRole"        # ad-hoc query
python privmapper.py --input ./graph --preset shadow                          # preset query
```

<details>
<summary><b>All options</b></summary>

```
python privmapper.py (--input PATH... | --profile NAME... | --auto-detect) [options]

Input
  -i, --input PATH        PMapper graph directory (repeatable)
  -p, --profile NAME      AWS profile to collect live via PMapper (repeatable)
  -a, --auto-detect       Discover PMapper graphs under ~/.local/share/principalmapper

Output
  -o, --output DIR        Output directory (default: privmapper_report_<timestamp>)
  -f, --format LIST       html,json,csv (comma-separated, default: html)
      --no-server         Do not start the local viewer after generating
      --port PORT         Viewer port (default: 1337, bound to 127.0.0.1)

Collection (with --profile)
      --create-graph      Auto-detect enabled regions, then run `pmapper graph create`
      --exclude-regions   Regions to skip during graph creation

Queries
  -Q, --query "who can do <action>"
      --preset {privesc,admin,shadow,cross-account,ssm,secrets,s3,dangerous}
```
</details>

## Output

```
report/
├── report.html   # interactive: attack graph, findings, evidence, how-to-report
├── findings.json # structured findings, paths, trusts, credential hygiene
└── findings.csv  # one row per finding-principal and per escalation path
```

The HTML is a single self-contained file: Cytoscape attack graph, collapsible findings, a policy viewer that highlights dangerous permissions, filters, and CSV/JSON export.

<p align="center">
  <img src="docs/screenshot-graph.jpg" alt="Interactive privilege-escalation attack graph" width="900">
  <br><sub>Interactive attack graph: admins (red), shadow admins and roles, with layout, path-highlight and search controls.</sub>
</p>

## How it works

PrivMapper computes each principal's **effective** dangerous permissions, not just what an attached policy says:

- **Allow + Deny.** A broad, unconditional `Deny` (the classic `Deny iam:*` guardrail) is subtracted, so a capped role is not called an admin.
- **`NotAction` / `NotResource`.** `Allow NotAction: iam:*` is treated as the near-admin grant it is; `NotResource` is never silently flipped to `*`.
- **Inline + group policies.** Permissions held only through a group are counted, exactly as IAM evaluates them.
- **AWS-managed policies.** `AdministratorAccess`, `PowerUserAccess`, `*FullAccess` and friends are resolved from a built-in catalog; anything unresolved is flagged per-principal so capabilities are never understated silently.
- **Permissions boundaries.** Effective access is intersected with the boundary when its body is available, otherwise the principal is flagged as boundary-capped.
- **Trust policies.** AWS, Federated (SAML and OIDC, incl. GitHub Actions) and Service principals are analysed. `ExternalId` counts only when actually enforced (equality operator, concrete value). Trust into an admin role is escalated; service confused-deputy is flagged only for services that act on other resources, so ordinary execution roles are not false positives.

Escalation paths are scored on complexity, exposure and blast radius, and mapped to MITRE ATT&CK.

## Limitations

Static-graph analysis. The following are **not** modelled, so confirm findings against the live account before reporting (the report repeats these caveats so they travel with the output):

- SCPs / RCPs, so a finding may be capped by an organization guardrail
- Resource-based policies (S3, KMS, SNS, ...) and session policies
- Runtime conditions (source IP, tags, time): noted, not simulated
- Access-key age, last-used, and unused permissions: use an IAM credential report / Access Analyzer

## Library use

```python
from pathlib import Path
from privmapper import GraphLoader, AnalysisEngine, HTMLExporter

principals, edges, policies = GraphLoader(Path("./graph")).load()
analysis = AnalysisEngine(principals, edges, policies).analyze()

for f in analysis.findings:
    print(f.severity, f.title, len(f.principals))

HTMLExporter.export([analysis], [], Path("report.html"))
```

<details>
<summary><b>Project layout</b></summary>

```
privmapper.py            # single-file build (bundled from the package)
src/privmapper/
├── models.py            # dataclasses (Principal, Policy, Finding, ...)
├── knowledge.py         # dangerous actions, techniques, MITRE, CVSS, guidance
├── managed_policies.py  # AWS-managed policy resolution
├── loader.py            # PMapper graph JSON -> model
├── runner.py            # drive the pmapper CLI (live collection)
├── analysis.py          # the IAM analysis engine
├── queries.py           # "who can do X" query engine
├── remediation.py       # remediation snippets
├── crossaccount.py      # multi-account trust correlation
├── cli.py               # command line / orchestration
└── reporting/           # html / json / csv exporters (+ static CSS/JS assets)
```

`privmapper.py` is the same code bundled into one module for drop-in use; edit the package and re-bundle to keep them in sync.
</details>

## Acknowledgements

Built on [PMapper](https://github.com/nccgroup/PMapper) by NCC Group (which builds the IAM graph), and grew from the original PrivMapper by [Shubham Dubey](https://www.linkedin.com/in/shubham-dubeyy).

## Disclaimer & license

For authorised security assessments only; you are responsible for how you use it. Released under the [MIT License](LICENSE).

<sub>Made by <a href="https://github.com/dr34mhacks">Sid (dr34mhacks)</a></sub>
