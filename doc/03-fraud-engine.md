# Task 03 — Fraud Risk Scoring and Detection Engine

## Goal
Turn raw click/session data into risk and confidence scores that identify suspicious traffic without relying on a single signal.

## Current status in repo
Implemented:
- Core `FraudEngine` computes risk and confidence from combined signals.
- Signals include click velocity, IP reputation, VPN/proxy, datacenter, and behavior anomalies.
- Verdict logic distinguishes SAFE, MONITOR, and FRAUD.
- Fraud event rows are persisted with trigger reasons.

Still missing:
- Real-time historical IP reputation database / service.
- Queryable fraud timeline and explanations for each decision.
- Additional behavioral scoring for device mismatch, inconsistent browsing, bot signatures, and replay.
- ML-ready feature extraction and labeling pipeline.
- Client feedback loop for legitimate vs fraudulent sessions.

## Deliverables
- Rules for fraud signals and score contributions.
- Confidence model based on signal diversity and severity.
- Fraud event explanation records with rule names and reason codes.
- Monitoring and alerting for high-risk traffic patterns.

## Acceptance criteria
- A session with suspicious click velocity and a risky IP scores above threshold.
- A low-risk session remains SAFE even when one weak signal appears alone.
- High-confidence fraudulent sessions generate fraud reason metadata.
- Scores can be reviewed in reporting and manually corrected with user feedback.

## Dependencies
- Task 02
