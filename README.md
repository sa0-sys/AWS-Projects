# AWS Environment Health & Cost Checker

A small, read-only Python tool that audits an AWS account for common cost, security and operational problems and writes a Markdown report with a suggested fix for each finding.

I built it as a self-directed project to practise the work a Technical Account Manager does for customers: keeping an environment healthy while reducing cost and complexity, and explaining each issue in plain terms.

> **Status:** self-directed lab project. Tested against a mocked AWS account (moto) and run against a free-tier sandbox account. Not production tooling.

## What it checks

| Well-Architected pillar | Check | Severity |
|---|---|---|
| Security | Security groups open to `0.0.0.0/0` or `::/0` on SSH (22), RDP (3389) or all ports | High |
| Security | S3 buckets with no or incomplete Block Public Access settings | High |
| Cost Optimization | Stopped EC2 instances (attached EBS storage still billed) | Medium |
| Cost Optimization | Unattached EBS volumes | Medium |
| Cost Optimization | Unassociated Elastic IPs (public IPv4 addresses are billed) | Medium |
| Operational Excellence | EC2 instances and S3 buckets missing required tags (default: `Owner`, `Environment`) | Low |
| Operational Excellence | S3 buckets without versioning | Low |

## Design choices

- **Read-only.** It only calls Describe, List and Get APIs. The IAM user it runs under needs `ReadOnlyAccess` and nothing more.
- **Fails soft.** If a call is denied, the check is listed under "Checks that could not run" instead of crashing the run.
- **Worst first.** Findings are sorted by severity, then grouped by pillar in the report.

## Setup

```bash
git clone https://github.com/<your-username>/aws-environment-health-check.git
cd aws-environment-health-check
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
aws configure        # use a read-only IAM user, not the root user
```

## Usage

```bash
python aws_health_check.py --region eu-west-1
python aws_health_check.py --region eu-west-1 --required-tags Owner,Environment,CostCenter \
    --output health_report.md --json health_report.json
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The tests build a deliberately messy mocked account and assert that each check fires, and that a tidy account is not flagged.

## Sample output

See [`docs/sample_report.md`](docs/sample_report.md) (from a real run against my sandbox account).

## Limitations

- One region per run for EC2 checks; S3 is account-wide.
- No cost figures. It points at likely waste but does not price it.
- Does not replace AWS Trusted Advisor, Security Hub or Cost Explorer.

## What I would add next

- Multi-region scanning
- Idle load balancers and old snapshots
- IAM checks (unused access keys, users without MFA)
- Scheduled runs with a report sent by email
