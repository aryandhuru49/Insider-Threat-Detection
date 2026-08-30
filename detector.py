"""
Insider Threat Detection Engine.

Correlates signals from GuardDuty, Security Hub, IAM Access Analyzer,
CloudTrail, and VPC Flow Logs to score potential insider threat activity
for a given IAM user, then raises a Security Hub finding and SNS alert.
"""
import os
import json
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
ACCOUNT_ID = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
FLOW_LOG_GROUP = os.environ.get("FLOW_LOG_GROUP", "/vpc/insider-threat-flowlogs")
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18
LARGE_TRANSFER_BYTES = 100 * 1024 * 1024  # 100MB
ALERT_SCORE_THRESHOLD = int(os.environ.get("ALERT_SCORE_THRESHOLD", "60"))


def _client(service):
    return boto3.client(service, region_name=REGION)


# ---------------------------------------------------------------------------
# Step 2a: baseline builder
# ---------------------------------------------------------------------------
def build_user_baseline(cloudtrail_events):
    """
    Build a per-user behavioral baseline from a list of CloudTrail event dicts
    (as returned by lookup_events / CloudTrail Lake / S3-delivered logs).

    Returns:
        { username: {
            "s3_buckets": set(),
            "iam_roles": set(),
            "regions": set(),
            "active_hours": set(),  # hours 0-23 the user is normally active
        }}
    """
    baseline = {}

    for event in cloudtrail_events:
        username = (
            event.get("Username")
            or event.get("userIdentity", {}).get("userName")
            or "unknown"
        )
        user_entry = baseline.setdefault(
            username,
            {"s3_buckets": set(), "iam_roles": set(), "regions": set(), "active_hours": set()},
        )

        raw = event.get("CloudTrailEvent")
        detail = json.loads(raw) if isinstance(raw, str) else event

        event_source = detail.get("eventSource", "")
        event_name = detail.get("eventName", "")
        request_params = detail.get("requestParameters") or {}

        if event_source == "s3.amazonaws.com":
            bucket = request_params.get("bucketName")
            if bucket:
                user_entry["s3_buckets"].add(bucket)

        if event_source == "sts.amazonaws.com" and event_name == "AssumeRole":
            role_arn = request_params.get("roleArn")
            if role_arn:
                user_entry["iam_roles"].add(role_arn)

        region = detail.get("awsRegion")
        if region:
            user_entry["regions"].add(region)

        event_time = detail.get("eventTime")
        if event_time:
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                user_entry["active_hours"].add(dt.hour)
            except ValueError:
                pass

    return baseline


# ---------------------------------------------------------------------------
# Step 2b: live signal correlation
# ---------------------------------------------------------------------------
def correlate_signals(username, baseline=None):
    """
    Pull live signals from GuardDuty, Security Hub, IAM Access Analyzer,
    CloudTrail, and VPC Flow Logs for the given username over the last 24h.

    Each source is wrapped independently so a single unavailable service
    (e.g. GuardDuty not yet activated on a new account) degrades that one
    signal to empty rather than failing the whole correlation.
    """
    baseline = baseline or {}
    user_baseline = baseline.get(username, {})
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    correlation = {
        "username": username,
        "guardduty_findings": [],
        "securityhub_findings": [],
        "access_analyzer_findings": [],
        "cloudtrail_events": [],
        "large_transfers": [],
        "buckets_accessed": set(),
        "roles_assumed": set(),
        "regions_used": set(),
        "off_hours_activity": False,
    }

    # GuardDuty: findings with severity > 4 in the last 24h
    try:
        gd = _client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        for detector_id in detectors:
            finding_ids = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "severity": {"Gt": 4},
                        "updatedAt": {"Gte": int(since.timestamp() * 1000)},
                    }
                },
            ).get("FindingIds", [])
            if finding_ids:
                findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
                for f in findings.get("Findings", []):
                    if username in json.dumps(f.get("Resource", {}), default=str):
                        correlation["guardduty_findings"].append(f)
    except ClientError as e:
        print(f"[correlate_signals] GuardDuty unavailable: {e}")

    # Security Hub: findings referencing this username in the last 24h
    try:
        sh = _client("securityhub")
        asff_fmt = "%Y-%m-%dT%H:%M:%SZ"
        resp = sh.get_findings(
            Filters={
                "UpdatedAt": [{"Start": since.strftime(asff_fmt), "End": now.strftime(asff_fmt)}],
            },
            MaxResults=100,
        )
        correlation["securityhub_findings"] = [
            f for f in resp.get("Findings", [])
            if username in json.dumps(f.get("Resources", []), default=str)
        ]
    except ClientError as e:
        print(f"[correlate_signals] Security Hub unavailable: {e}")

    # IAM Access Analyzer: cross-account / public access findings
    try:
        aa = _client("accessanalyzer")
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
        for analyzer in analyzers:
            findings = aa.list_findings(
                analyzerArn=analyzer["arn"],
                filter={"status": {"eq": ["ACTIVE"]}},
            ).get("findings", [])
            for f in findings:
                if f.get("isPublic") or f.get("resourceOwnerAccount") != ACCOUNT_ID:
                    correlation["access_analyzer_findings"].append(f)
    except ClientError as e:
        print(f"[correlate_signals] Access Analyzer unavailable: {e}")

    # CloudTrail: last 50 events for this username
    try:
        ct = _client("cloudtrail")
        resp = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": username}],
            StartTime=since,
            EndTime=now,
            MaxResults=50,
        )
        events = resp.get("Events", [])
        correlation["cloudtrail_events"] = events

        for event in events:
            detail = json.loads(event["CloudTrailEvent"])
            event_source = detail.get("eventSource", "")
            event_name = detail.get("eventName", "")
            request_params = detail.get("requestParameters") or {}

            if event_source == "s3.amazonaws.com":
                bucket = request_params.get("bucketName")
                if bucket:
                    correlation["buckets_accessed"].add(bucket)

            if event_source == "sts.amazonaws.com" and event_name == "AssumeRole":
                role_arn = request_params.get("roleArn")
                if role_arn:
                    correlation["roles_assumed"].add(role_arn)

            region = detail.get("awsRegion")
            if region:
                correlation["regions_used"].add(region)

            event_time = detail.get("eventTime")
            if event_time:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                if not (BUSINESS_HOURS_START <= dt.hour < BUSINESS_HOURS_END):
                    correlation["off_hours_activity"] = True
    except ClientError as e:
        print(f"[correlate_signals] CloudTrail unavailable: {e}")

    # VPC Flow Logs: large outbound transfers (>100MB) in the last 24h
    try:
        logs = _client("logs")
        query = (
            "fields @timestamp, srcAddr, dstAddr, bytes "
            f"| filter bytes > {LARGE_TRANSFER_BYTES} "
            "| sort bytes desc "
            "| limit 20"
        )
        start_query = logs.start_query(
            logGroupName=FLOW_LOG_GROUP,
            startTime=int(since.timestamp()),
            endTime=int(now.timestamp()),
            queryString=query,
        )
        query_id = start_query["queryId"]

        import time
        for _ in range(10):
            result = logs.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled"):
                break
            time.sleep(1)

        if result["status"] == "Complete":
            for row in result.get("results", []):
                correlation["large_transfers"].append(
                    {field["field"]: field["value"] for field in row}
                )
    except ClientError as e:
        print(f"[correlate_signals] VPC Flow Logs unavailable: {e}")

    # Baseline deviations
    correlation["buckets_outside_baseline"] = correlation["buckets_accessed"] - set(
        user_baseline.get("s3_buckets", set())
    )
    correlation["roles_outside_baseline"] = correlation["roles_assumed"] - set(
        user_baseline.get("iam_roles", set())
    )
    correlation["new_regions"] = correlation["regions_used"] - set(
        user_baseline.get("regions", set())
    )

    return correlation


# ---------------------------------------------------------------------------
# Step 2c: threat scoring
# ---------------------------------------------------------------------------
def score_threat(correlation):
    """
    Apply the point-based scoring rules to a correlation dict and return
    the total score, severity, and the list of triggered signal names.
    """
    score = 0
    triggered = []

    if correlation.get("guardduty_findings"):
        score += 30
        triggered.append("guardduty_finding")

    if correlation.get("securityhub_findings"):
        score += 20
        triggered.append("securityhub_finding")

    if correlation.get("access_analyzer_findings"):
        score += 25
        triggered.append("cross_account_access_flagged")

    if correlation.get("buckets_outside_baseline"):
        score += 20
        triggered.append("s3_access_outside_baseline")

    if correlation.get("roles_outside_baseline"):
        score += 25
        triggered.append("role_assumption_outside_baseline")

    if correlation.get("off_hours_activity"):
        score += 15
        triggered.append("off_hours_activity")

    if correlation.get("large_transfers"):
        score += 20
        triggered.append("large_outbound_transfer")

    if correlation.get("new_regions"):
        score += 10
        triggered.append("new_region_activity")

    if score > 80:
        severity = "HIGH"
    elif score > 60:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {"score": score, "severity": severity, "triggered_signals": triggered}


# ---------------------------------------------------------------------------
# Step 2d: Security Hub finding creation
# ---------------------------------------------------------------------------
def create_security_hub_finding(username, threat_result, correlation):
    """
    Build an ASFF finding summarizing the triggered signals and import it
    into Security Hub via BatchImportFindings.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    finding_id = f"insider-threat-{username}-{int(datetime.now(timezone.utc).timestamp())}"

    signal_summary = ", ".join(threat_result["triggered_signals"]) or "no signals triggered"
    description = (
        f"User '{username}' scored {threat_result['score']} "
        f"({threat_result['severity']} severity). Triggered signals: {signal_summary}."
    )

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default",
        "GeneratorId": "insider-threat-detector",
        "AwsAccountId": ACCOUNT_ID,
        "Types": ["Unusual Behaviors/User"],
        "CreatedAt": now_iso,
        "UpdatedAt": now_iso,
        "Severity": {"Label": threat_result["severity"], "Normalized": min(threat_result["score"], 100)},
        "Title": "Insider Threat Detected",
        "Description": description,
        "Resources": [
            {
                "Type": "AwsIamUser",
                "Id": f"arn:aws:iam::{ACCOUNT_ID}:user/{username}",
                "Partition": "aws",
                "Region": REGION,
            }
        ],
        "RecordState": "ACTIVE",
    }

    sh = _client("securityhub")
    response = sh.batch_import_findings(Findings=[finding])
    return finding, response


# ---------------------------------------------------------------------------
# Step 2e: alerting
# ---------------------------------------------------------------------------
def send_alert(username, threat_result):
    """Publish an SNS alert if the score exceeds ALERT_SCORE_THRESHOLD."""
    if threat_result["score"] <= ALERT_SCORE_THRESHOLD or not SNS_TOPIC_ARN:
        return None

    sns = _client("sns")
    message = {
        "username": username,
        "score": threat_result["score"],
        "severity": threat_result["severity"],
        "triggered_signals": threat_result["triggered_signals"],
    }
    return sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Insider Threat Alert: {username} ({threat_result['severity']})",
        Message=json.dumps(message, indent=2),
    )


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context=None):
    """
    Entry point for EventBridge. Extracts the username from a CloudTrail
    event (or a direct test payload), runs the full detection pipeline,
    and returns the Security Hub finding that was created.
    """
    username = (
        event.get("username")
        or event.get("detail", {}).get("userIdentity", {}).get("userName")
        or "unknown"
    )

    baseline_events = event.get("baseline_events", [])
    baseline = build_user_baseline(baseline_events) if baseline_events else {}

    demo_correlation = event.get("demo_correlation")
    if demo_correlation:
        # Demo/interview path: score a hand-built correlation dict instead of
        # pulling live signals, so a HIGH-severity result can be produced on
        # demand without depending on live findings existing for a test user.
        demo_correlation.setdefault("username", username)
        for key in ("buckets_outside_baseline", "roles_outside_baseline", "new_regions"):
            if key in demo_correlation and isinstance(demo_correlation[key], list):
                demo_correlation[key] = set(demo_correlation[key])
        correlation = demo_correlation
    else:
        correlation = correlate_signals(username, baseline)
    threat_result = score_threat(correlation)
    finding, sh_response = create_security_hub_finding(username, threat_result, correlation)
    send_alert(username, threat_result)

    return {
        "username": username,
        "threat_result": threat_result,
        "finding": finding,
        "securityhub_response": sh_response,
    }
