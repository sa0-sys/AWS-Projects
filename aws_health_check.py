#!/usr/bin/env python3
"""AWS Environment Health & Cost Checker.

A read-only audit of one AWS region (plus S3, which is global) that flags
common cost, security and operational problems and writes a short report.

It never creates, changes or deletes anything. It only calls Describe/List/Get APIs.
"""
import argparse
import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
PILLARS = ["Security", "Cost Optimization", "Operational Excellence"]
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


@dataclass
class Finding:
    pillar: str      # Well-Architected pillar the finding falls under
    severity: str    # High / Medium / Low
    check: str
    resource: str
    detail: str
    fix: str


def tag_dict(tags):
    return {t["Key"]: t["Value"] for t in (tags or [])}


def name_of(tags):
    return tag_dict(tags).get("Name", "")


# --------------------------------------------------------------------------
# EC2 checks
# --------------------------------------------------------------------------
def check_stopped_instances(ec2):
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    ):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                findings.append(Finding(
                    "Cost Optimization", "Medium", "Stopped EC2 instance",
                    inst["InstanceId"],
                    f"Instance is stopped but its attached EBS volumes are still billed "
                    f"({inst.get('InstanceType', 'unknown type')}).",
                    "Terminate it if it is no longer needed, or snapshot the volumes and "
                    "terminate. If it is needed, schedule start/stop.",
                ))
    return findings


def check_missing_tags(ec2, required_tags):
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name",
                  "Values": ["pending", "running", "stopping", "stopped"]}]
    ):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                present = tag_dict(inst.get("Tags"))
                missing = [t for t in required_tags if t not in present]
                if missing:
                    findings.append(Finding(
                        "Operational Excellence", "Low", "EC2 instance missing required tags",
                        inst["InstanceId"],
                        f"Missing tags: {', '.join(missing)}. Without an owner tag, nobody "
                        "can be asked whether the instance is still needed.",
                        "Add the missing tags and enforce them with a tag policy or SCP.",
                    ))
    return findings


def check_unattached_volumes(ec2):
    findings = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for vol in page["Volumes"]:
            findings.append(Finding(
                "Cost Optimization", "Medium", "Unattached EBS volume",
                vol["VolumeId"],
                f"{vol['Size']} GiB {vol['VolumeType']} volume is not attached to any instance "
                "but is still billed.",
                "Snapshot it if the data matters, then delete the volume.",
            ))
    return findings


def check_unassociated_eips(ec2):
    findings = []
    for addr in ec2.describe_addresses()["Addresses"]:
        if "AssociationId" not in addr:
            findings.append(Finding(
                "Cost Optimization", "Medium", "Unassociated Elastic IP",
                addr.get("PublicIp", addr.get("AllocationId", "unknown")),
                "Elastic IP is allocated but not attached to anything. AWS bills for "
                "public IPv4 addresses whether or not they are in use.",
                "Release the address if it is not needed.",
            ))
    return findings


def check_open_security_groups(ec2):
    findings = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or \
                        any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not world:
                    continue
                proto = perm.get("IpProtocol")
                if proto == "-1":
                    exposed = "all traffic on all ports"
                else:
                    lo, hi = perm.get("FromPort"), perm.get("ToPort")
                    if lo is None or hi is None:
                        continue
                    hits = [f"{n} ({p})" for p, n in ADMIN_PORTS.items() if lo <= p <= hi]
                    if not hits:
                        continue
                    exposed = " and ".join(hits)
                findings.append(Finding(
                    "Security", "High", "Security group open to the internet",
                    f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                    f"Allows {exposed} from 0.0.0.0/0 or ::/0.",
                    "Restrict the source to known IP ranges, or use Systems Manager "
                    "Session Manager instead of exposing admin ports.",
                ))
    return findings


# --------------------------------------------------------------------------
# S3 checks
# --------------------------------------------------------------------------
def bucket_client(session, name):
    """S3 is global but each bucket lives in a region; use a client for that region."""
    base = session.client("s3")
    loc = base.get_bucket_location(Bucket=name).get("LocationConstraint")
    region = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)
    return session.client("s3", region_name=region)


def check_s3(session, required_tags, notes):
    findings = []
    s3 = session.client("s3")
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            c = bucket_client(session, name)
        except ClientError as e:
            notes.append(f"Could not read location for bucket {name}: {e.response['Error']['Code']}")
            continue

        # Public access block
        try:
            cfg = c.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            off = [k for k, v in cfg.items() if not v]
            if off:
                findings.append(Finding(
                    "Security", "High", "S3 public access block incomplete", name,
                    f"These protections are off: {', '.join(off)}.",
                    "Turn on all four Block Public Access settings unless the bucket is "
                    "intentionally public."))
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(Finding(
                    "Security", "High", "S3 bucket has no public access block", name,
                    "No bucket-level Block Public Access configuration exists.",
                    "Enable Block Public Access on the bucket (and at account level)."))
            else:
                notes.append(f"Could not check public access block on {name}: {code}")

        # Versioning
        try:
            status = c.get_bucket_versioning(Bucket=name).get("Status")
            if status != "Enabled":
                findings.append(Finding(
                    "Operational Excellence", "Low", "S3 versioning not enabled", name,
                    "Overwritten or deleted objects cannot be recovered.",
                    "Enable versioning on buckets that hold data you cannot recreate."))
        except ClientError as e:
            notes.append(f"Could not check versioning on {name}: {e.response['Error']['Code']}")

        # Tags
        try:
            present = tag_dict(c.get_bucket_tagging(Bucket=name).get("TagSet"))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                present = {}
            else:
                notes.append(f"Could not read tags on {name}: {e.response['Error']['Code']}")
                continue
        missing = [t for t in required_tags if t not in present]
        if missing:
            findings.append(Finding(
                "Operational Excellence", "Low", "S3 bucket missing required tags", name,
                f"Missing tags: {', '.join(missing)}.",
                "Add the missing tags so ownership and cost can be traced."))
    return findings


# --------------------------------------------------------------------------
# Run and report
# --------------------------------------------------------------------------
def run_checks(session, required_tags):
    ec2 = session.client("ec2")
    notes = []
    findings = []
    ec2_checks = [
        ("stopped instances", lambda: check_stopped_instances(ec2)),
        ("unattached volumes", lambda: check_unattached_volumes(ec2)),
        ("unassociated Elastic IPs", lambda: check_unassociated_eips(ec2)),
        ("open security groups", lambda: check_open_security_groups(ec2)),
        ("instance tags", lambda: check_missing_tags(ec2, required_tags)),
    ]
    for label, fn in ec2_checks:
        try:
            findings += fn()
        except ClientError as e:
            notes.append(f"Skipped {label}: {e.response['Error']['Code']}")
    try:
        findings += check_s3(session, required_tags, notes)
    except ClientError as e:
        notes.append(f"Skipped S3 checks: {e.response['Error']['Code']}")
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], PILLARS.index(f.pillar), f.resource))
    return findings, notes


def render_markdown(findings, notes, account, region, required_tags):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    out = [
        "# AWS Environment Health Report",
        "",
        f"- Account: `{account}`",
        f"- Region: `{region}` (S3 buckets are account-wide)",
        f"- Generated: {now}",
        f"- Required tags checked: {', '.join(required_tags) or 'none'}",
        "",
        f"**{len(findings)} findings:** {counts['High']} high, {counts['Medium']} medium, "
        f"{counts['Low']} low.",
        "",
    ]
    for pillar in PILLARS:
        group = [f for f in findings if f.pillar == pillar]
        out += [f"## {pillar} ({len(group)})", ""]
        if not group:
            out += ["No findings.", ""]
            continue
        out += ["| Severity | Check | Resource | What was found | Suggested fix |",
                "|---|---|---|---|---|"]
        for f in group:
            row = [f.severity, f.check, f"`{f.resource}`", f.detail, f.fix]
            out.append("| " + " | ".join(c.replace("|", "/") for c in row) + " |")
        out.append("")
    if notes:
        out += ["## Checks that could not run", ""] + [f"- {n}" for n in notes] + [""]
    out += ["---", "Read-only audit. No resources were created, changed or deleted.", ""]
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only AWS cost, security and operations checker.")
    p.add_argument("--region", help="AWS region to audit (default: your configured region)")
    p.add_argument("--profile", help="AWS CLI profile name")
    p.add_argument("--required-tags", default="Owner,Environment",
                   help="Comma-separated tag keys every resource should have")
    p.add_argument("--output", default="health_report.md", help="Markdown report path")
    p.add_argument("--json", dest="json_path", help="Also write findings as JSON to this path")
    args = p.parse_args(argv)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    region = session.region_name
    if not region:
        sys.exit("No region set. Pass --region or run `aws configure`.")
    required = [t.strip() for t in args.required_tags.split(",") if t.strip()]

    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except ClientError as e:
        sys.exit(f"Could not authenticate: {e.response['Error']['Code']}")

    findings, notes = run_checks(session, required)
    report = render_markdown(findings, notes, account, region, required)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2)
    print(f"{len(findings)} findings written to {args.output}")


if __name__ == "__main__":
    main()
