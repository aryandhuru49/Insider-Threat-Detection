# Insider Threat Detection System

Automated, serverless detection pipeline on AWS that identifies when an employee's legitimate credentials are being misused — correlating signals across 5 AWS security services into a single, explainable risk score.

## The Problem

Perimeter security tools (firewalls, WAFs, IDS) are built to catch *outside* attackers. They're structurally blind to a different, harder problem: a legitimate employee, using their own valid credentials, doing something they shouldn't. No single action in that scenario looks malicious in isolation — accessing a file, working late, assuming a role are all normal, individually. The signal only becomes visible when several weak indicators show up together, for the same person, in the same short window. Most organizations either lack that correlation entirely, or do it manually — a security analyst cross-referencing five different consoles after the fact, hours or days too late.

## Business Requirement

Build a system that:
- Continuously monitors user behavior across identity, storage, and network activity
- Establishes a behavioral baseline per user (what's "normal" for them specifically)
- Correlates real-time signals against that baseline and against managed AWS threat intelligence
- Produces a single, explainable risk score rather than raw, disconnected alerts
- Automatically escalates only when evidence is strong enough to warrant human attention — minimizing alert fatigue
- Uses AWS-native services exclusively, with no third-party SIEM dependency, for lower operational overhead and faster deployment

## The Solution

A serverless pipeline, triggered on a schedule (and extensible to real-time, event-driven triggering), that pulls signals from CloudTrail, GuardDuty, Security Hub, VPC Flow Logs, and IAM Access Analyzer, applies a weighted additive risk model, and writes results back into Security Hub as a standardized finding — with automatic email alerting when risk crosses a configurable threshold.

## Architecture
                ┌─────────────────────┐
    ┌──────────▶│   Amazon EventBridge │  (6-hour schedule; also
    │           │   (trigger rules)     │   supports event-driven
    │           └──────────┬───────────┘   triggering on new
    │                      │                CloudTrail activity)
    │                      ▼
    │           ┌─────────────────────┐
    │           │   AWS Lambda          │
    │           │   (detection engine)  │
    │           └──────────┬───────────┘
    │                      │  boto3 API calls
    │      ┌───────────────┼───────────────┬──────────────┬─────────────┐
    │      ▼               ▼               ▼              ▼             ▼
    │  CloudTrail      VPC Flow Logs    GuardDuty     Security Hub   IAM Access
    │  (user activity) (via CloudWatch) (ML threat     (existing     Analyzer
    │                  (data exfil)     detection)     findings)    (exposure)
    │      │               │               │              │             │
    │      └───────────────┴───────┬───────┴──────────────┴─────────────┘
    │                              ▼
    │                   ┌─────────────────────┐
    │                   │  Weighted Risk        │
    │                   │  Scoring Engine        │
    │                   └──────────┬───────────┘
    │                              │
    │              ┌───────────────┴────────────────┐
    │              ▼                                 ▼
    │   ┌─────────────────────┐            ┌─────────────────────┐
    │   │   Security Hub        │            │   Amazon SNS          │
    │   │   (finding written,   │            │   (email alert, only  │
    └───│    every run)         │            │    if score > 60)     │
        └─────────────────────┘            └─────────────────────┘


## Tech Stack

| Layer | Technology |
|---|---|
| Compute | AWS Lambda (Python 3.11) |
| SDK | boto3 |
| Trigger / Orchestration | Amazon EventBridge |
| Identity & Activity | AWS CloudTrail, IAM, IAM Access Analyzer |
| Threat Intelligence | Amazon GuardDuty |
| Findings Aggregation | AWS Security Hub (ASFF format) |
| Network Telemetry | Amazon VPC Flow Logs → CloudWatch Logs (Logs Insights) |
| Storage | Amazon S3 (log storage, access logging) |
| Alerting | Amazon SNS |
| Perimeter Security | AWS WAF |
| Vulnerability Scanning | Amazon Inspector v2 |
| Deployment | AWS CLI (native IaC-free deployment) |

## How Detection Works

1. **Baseline building** — from historical CloudTrail activity, establishes per-user normal behavior: typical S3 buckets, IAM roles, regions, and active hours.
2. **Signal correlation** — pulls live data from all 5 sources for the target user over a 24-hour window, diffing current activity against baseline to surface deviations.
3. **Risk scoring** — an additive weighted model (e.g., GuardDuty finding +30, IAM role assumption outside baseline +25, off-hours activity +15, large outbound transfer +20). Deliberately additive, not single-trigger: no individual weak signal fires an alert, but several compounding do — mirroring how real insider risk actually presents.
4. **Finding generation** — every run writes a structured ASFF finding to Security Hub, regardless of score, preserving a complete audit trail.
5. **Alerting** — an SNS email fires only when the combined score crosses a configurable threshold, keeping signal-to-noise high.

## Design Considerations at Scale

Built and validated as a working proof of concept; extending to production/enterprise scale would involve:
- Persisting user baselines in DynamoDB rather than recomputing per invocation
- Moving from per-user live API calls to a centralized batch/streaming model (e.g., Security Lake + Athena) to avoid CloudTrail API rate limits at high user counts
- Delegated administrator accounts for GuardDuty/Security Hub and an AWS Organizations trail for multi-account coverage
- VPC-deployed Lambda, KMS-encrypted storage, and least-privilege custom IAM policies in place of managed policies used for development speed

---

Built as an independent project to demonstrate applied cloud security engineering — detection logic design, AWS-native security service integration, and automation, deployed and verified end-to-end using only the AWS CLI and boto3.
