"""
cost_scanner.py — AWS Cost Optimization Scanner
Scans AWS account for idle/wasteful resources and generates saving recommendations
Triggered daily by EventBridge | Reports via SNS + stores in DynamoDB
"""
import json
import os
import boto3
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN  = os.environ["SNS_TOPIC_ARN"]
DYNAMO_TABLE   = os.environ["DYNAMODB_TABLE"]
REPORT_BUCKET  = os.environ["REPORT_BUCKET"]
AWS_REGION     = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

ec2     = boto3.client("ec2",        region_name=AWS_REGION)
rds     = boto3.client("rds",        region_name=AWS_REGION)
cw      = boto3.client("cloudwatch", region_name=AWS_REGION)
ce      = boto3.client("ce",         region_name=AWS_REGION)
sns     = boto3.client("sns",        region_name=AWS_REGION)
s3      = boto3.client("s3",         region_name=AWS_REGION)
dynamo  = boto3.resource("dynamodb", region_name=AWS_REGION)


@dataclass
class Finding:
    resource_id:   str
    resource_type: str
    issue:         str
    estimated_monthly_saving_usd: float
    recommendation: str
    region:        str = AWS_REGION
    severity:      str = "MEDIUM"   # LOW | MEDIUM | HIGH


def lambda_handler(event, context):
    """Entry point — run all checks and publish report."""
    logger.info("Starting AWS cost optimization scan...")
    findings: List[Finding] = []

    findings += check_idle_ec2_instances()
    findings += check_unattached_ebs_volumes()
    findings += check_unused_elastic_ips()
    findings += check_old_snapshots()
    findings += check_underutilized_rds()

    total_saving = sum(f.estimated_monthly_saving_usd for f in findings)
    report = build_report(findings, total_saving)

    save_to_dynamo(report)
    save_to_s3(report)
    send_sns_alert(findings, total_saving)

    logger.info(f"Scan complete. Found {len(findings)} issues. "
                f"Potential saving: ${total_saving:.2f}/month")
    return {"statusCode": 200, "findings": len(findings), "total_saving_usd": total_saving}


# ── EC2 ───────────────────────────────────────────────────
def check_idle_ec2_instances() -> List[Finding]:
    """Flag EC2 instances with avg CPU < 5% over last 7 days."""
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=7)

    for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id   = instance["InstanceId"]
                instance_type = instance["InstanceType"]

                metrics = cw.get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName="CPUUtilization",
                    Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                    StartTime=start, EndTime=end,
                    Period=86400, Statistics=["Average"]
                )

                if not metrics["Datapoints"]:
                    continue

                avg_cpu = sum(d["Average"] for d in metrics["Datapoints"]) / len(metrics["Datapoints"])

                if avg_cpu < 5.0:
                    name = next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        instance_id
                    )
                    findings.append(Finding(
                        resource_id=instance_id,
                        resource_type="EC2 Instance",
                        issue=f"Idle instance — avg CPU {avg_cpu:.1f}% over 7 days ({name}, {instance_type})",
                        estimated_monthly_saving_usd=EC2_MONTHLY_COST.get(instance_type, 30.0),
                        recommendation=f"Stop or terminate {instance_id} ({name}). "
                                       f"Consider Reserved Instance or Savings Plan if needed.",
                        severity="HIGH" if avg_cpu < 1.0 else "MEDIUM"
                    ))

    logger.info(f"EC2 check: {len(findings)} idle instances found")
    return findings


# ── EBS ───────────────────────────────────────────────────
def check_unattached_ebs_volumes() -> List[Finding]:
    """Find EBS volumes in 'available' state (not attached to any instance)."""
    findings = []
    paginator = ec2.get_paginator("describe_volumes")

    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for volume in page["Volumes"]:
            vol_id    = volume["VolumeId"]
            size_gb   = volume["Size"]
            vol_type  = volume["VolumeType"]
            age_days  = (datetime.now(timezone.utc) - volume["CreateTime"]).days

            if age_days < 1:  # Skip brand-new volumes
                continue

            # EBS gp3: ~$0.08/GB/month
            monthly_cost = size_gb * 0.08 if vol_type == "gp3" else size_gb * 0.10

            findings.append(Finding(
                resource_id=vol_id,
                resource_type="EBS Volume",
                issue=f"Unattached EBS volume — {size_gb}GB {vol_type}, unused for {age_days} days",
                estimated_monthly_saving_usd=monthly_cost,
                recommendation=f"Delete {vol_id} after creating a snapshot if data is needed. "
                               f"Command: aws ec2 delete-volume --volume-id {vol_id}",
                severity="HIGH" if age_days > 30 else "LOW"
            ))

    logger.info(f"EBS check: {len(findings)} unattached volumes found")
    return findings


# ── ELASTIC IPs ───────────────────────────────────────────
def check_unused_elastic_ips() -> List[Finding]:
    """Find Elastic IPs not associated with any resource."""
    findings = []
    response = ec2.describe_addresses()

    for addr in response["Addresses"]:
        if "AssociationId" not in addr:  # Not associated
            findings.append(Finding(
                resource_id=addr["AllocationId"],
                resource_type="Elastic IP",
                issue=f"Unused Elastic IP: {addr['PublicIp']} — costs $3.65/month when idle",
                estimated_monthly_saving_usd=3.65,
                recommendation=f"Release {addr['PublicIp']} if not needed. "
                               f"Command: aws ec2 release-address --allocation-id {addr['AllocationId']}",
                severity="LOW"
            ))

    logger.info(f"Elastic IP check: {len(findings)} unused IPs found")
    return findings


# ── SNAPSHOTS ─────────────────────────────────────────────
def check_old_snapshots() -> List[Finding]:
    """Flag EBS snapshots older than 90 days."""
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    paginator = ec2.get_paginator("describe_snapshots")

    for page in paginator.paginate(OwnerIds=["self"]):
        for snap in page["Snapshots"]:
            if snap["StartTime"] < cutoff:
                age_days = (datetime.now(timezone.utc) - snap["StartTime"]).days
                monthly_cost = snap["VolumeSize"] * 0.05  # $0.05/GB/month

                findings.append(Finding(
                    resource_id=snap["SnapshotId"],
                    resource_type="EBS Snapshot",
                    issue=f"Old snapshot — {snap['VolumeSize']}GB, {age_days} days old",
                    estimated_monthly_saving_usd=monthly_cost,
                    recommendation=f"Delete {snap['SnapshotId']} if backup is no longer needed. "
                                   f"Command: aws ec2 delete-snapshot --snapshot-id {snap['SnapshotId']}",
                    severity="LOW"
                ))

    logger.info(f"Snapshot check: {len(findings)} old snapshots found")
    return findings


# ── RDS ───────────────────────────────────────────────────
def check_underutilized_rds() -> List[Finding]:
    """Flag RDS instances with < 1 connection/day on average."""
    findings = []
    response = rds.describe_db_instances()
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=7)

    for db in response["DBInstances"]:
        db_id    = db["DBInstanceIdentifier"]
        db_class = db["DBInstanceClass"]

        metrics = cw.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="DatabaseConnections",
            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
            StartTime=start, EndTime=end,
            Period=86400, Statistics=["Average"]
        )

        if not metrics["Datapoints"]:
            continue

        avg_connections = sum(d["Average"] for d in metrics["Datapoints"]) / len(metrics["Datapoints"])

        if avg_connections < 1.0:
            findings.append(Finding(
                resource_id=db_id,
                resource_type="RDS Instance",
                issue=f"Underutilized RDS — avg {avg_connections:.2f} connections/day ({db_class})",
                estimated_monthly_saving_usd=RDS_MONTHLY_COST.get(db_class, 50.0),
                recommendation=f"Stop {db_id} when not in use, or downsize instance class. "
                               f"Command: aws rds stop-db-instance --db-instance-identifier {db_id}",
                severity="HIGH"
            ))

    logger.info(f"RDS check: {len(findings)} underutilized instances found")
    return findings


# ── Helpers ───────────────────────────────────────────────
def build_report(findings: List[Finding], total_saving: float) -> dict:
    return {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "total_monthly_saving_usd": round(total_saving, 2),
        "findings_by_severity": {
            "HIGH":   [asdict(f) for f in findings if f.severity == "HIGH"],
            "MEDIUM": [asdict(f) for f in findings if f.severity == "MEDIUM"],
            "LOW":    [asdict(f) for f in findings if f.severity == "LOW"],
        },
        "all_findings": [asdict(f) for f in findings]
    }


def save_to_dynamo(report: dict):
    table = dynamo.Table(DYNAMO_TABLE)
    table.put_item(Item={
        "scan_date": report["scan_date"],
        "total_finding": str(report["total_findings"]),
        "total_saving":  str(report["total_monthly_saving_usd"]),
        "report_json":   json.dumps(report)
    })


def save_to_s3(report: dict):
    date_str = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    key = f"reports/{date_str}/cost-report.json"
    s3.put_object(
        Bucket=REPORT_BUCKET,
        Key=key,
        Body=json.dumps(report, indent=2),
        ContentType="application/json"
    )
    logger.info(f"Report saved: s3://{REPORT_BUCKET}/{key}")


def send_sns_alert(findings: List[Finding], total_saving: float):
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    top5 = sorted(findings, key=lambda x: x.estimated_monthly_saving_usd, reverse=True)[:5]

    lines = [
        f"☁️ AWS Cost Optimization Report — {datetime.now().strftime('%Y-%m-%d')}",
        f"",
        f"💰 Total Potential Saving: ${total_saving:.2f}/month",
        f"🔴 High Priority Issues:   {high_count}",
        f"📊 Total Findings:         {len(findings)}",
        f"",
        f"Top 5 Savings Opportunities:",
    ]
    for i, f in enumerate(top5, 1):
        lines.append(f"  {i}. [{f.resource_type}] {f.resource_id} — ${f.estimated_monthly_saving_usd:.2f}/mo")
        lines.append(f"     → {f.recommendation[:100]}...")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"AWS Cost Report — Save ${total_saving:.0f}/month identified",
        Message="\n".join(lines)
    )


# ── Pricing reference (approximate on-demand) ─────────────
EC2_MONTHLY_COST = {
    "t3.micro": 7.50, "t3.small": 15.18, "t3.medium": 30.37,
    "t3.large": 60.74, "t3.xlarge": 121.47, "m5.large": 70.08,
    "m5.xlarge": 140.16, "m5.2xlarge": 280.32, "c5.large": 61.20,
}

RDS_MONTHLY_COST = {
    "db.t3.micro": 14.60, "db.t3.small": 29.20, "db.t3.medium": 58.40,
    "db.m5.large": 140.16, "db.m5.xlarge": 280.32,
}
