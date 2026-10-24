# Chrontinal — Cognitive Log Investigation Framework

**Public frontend:** [Chrontinal SOC website](https://akash120405.github.io/Chrontinal/) · [Deployment guide](DEPLOYMENT.md)

For GitHub publishing and a live HTTPS deployment of the full stack, see
[DEPLOYMENT.md](DEPLOYMENT.md).

<p align="center">
<strong>An Agentic SIEM Platform with Autonomous AI Threat Detection, Investigation, and Explainable Verdicts</strong>
</p>

<p align="center">
<em>High-throughput distributed log pipeline (Vector → Redpanda → ClickHouse → MinIO), Go-based Kafka consumers,<br>
multi-agent AI investigation pipeline (Triage → Hunter → Verifier) with SHAP-based XAI,<br>
Merkle evidence chain for forensic integrity, and a 17-page SOC analyst dashboard.</em>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement & Value Proposition](#problem-statement--value-proposition)
- [Innovation & Differentiators](#innovation--differentiators)
- [System Architecture](#system-architecture)
- [Pipeline Data Flow](#pipeline-data-flow)
- [Infrastructure Components](#infrastructure-components)
  - [Log Collection — Vector](#log-collection--vector)
  - [Message Streaming — Redpanda](#message-streaming--redpanda)
  - [Columnar Storage — ClickHouse](#columnar-storage--clickhouse)
  - [Object Storage — MinIO](#object-storage--minio)
  - [Kafka→ClickHouse — Go Consumer](#kafkaclickhouse--go-consumer)
- [AI Agent Pipeline](#ai-agent-pipeline)
  - [Triage Agent (v8)](#triage-agent-v8)
  - [Hunter Agent (v7)](#hunter-agent-v7)
  - [Verifier Agent (v7)](#verifier-agent-v7)
  - [XAI Service](#xai-service)
  - [Merkle Evidence Chain](#merkle-evidence-chain)
- [Similarity Search — LanceDB](#similarity-search--lancedb)
- [SOC Dashboard](#soc-dashboard)
- [Monitoring & Observability](#monitoring--observability)
- [ClickHouse Schema Reference](#clickhouse-schema-reference)
- [Deployment Architecture](#deployment-architecture)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Benchmark Results](#benchmark-results)
- [Validated Pipeline Metrics](#validated-pipeline-metrics)
- [Test Suite](#test-suite)
- [Quick Start](#quick-start)
- [Architecture Decisions](#architecture-decisions)
- [File Layout](#file-layout)
- [Team & Future Scope](#team--future-scope)

---

## Overview

Chrontinal (Cognitive Log Investigation Framework) is a full-stack, production-grade Security Information and Event Management (SIEM) platform built from scratch. It implements an **agentic AI architecture** where specialized autonomous agents — Triage, Hunter, Verifier, and XAI — collaborate through a Kafka-based event bus to detect, investigate, verify, and explain security threats in real time with zero human intervention.

### Key Capabilities

| Capability | Implementation |
|---|---|
| **Multi-format log ingestion** | Vector aggregator with VRL transforms — syslog (RFC 3164/5424), JSON, CEF; 10 log types, 20+ source types |
| **Stream processing** | Redpanda 3-node cluster, 14 Kafka topics, 12 partitions, RF=3, LZ4 compression |
| **Columnar analytics** | ClickHouse 2-node replicated cluster, 26+ tables, sub-100ms queries |
| **AI-powered triage** | 60-feature LightGBM+Autoencoder ensemble, 10 log types with per-type thresholds, 4 replicas, ONNX Runtime |
| **Autonomous investigation** | Hunter agent with Sigma rules, SPC anomaly detection, entity graph, temporal correlation |
| **Forensic verification** | Verifier agent with evidence integrity, IOC correlation, timeline reconstruction, FP analysis |
| **Explainable AI** | SHAP TreeExplainer with per-feature attribution, waterfall charts, drift monitoring |
| **Evidence integrity** | SHA-256 Merkle trees with S3 Object Lock for forensic chain of custody |
| **Semantic search** | LanceDB with all-MiniLM-L6-v2 embeddings (384-dim), IVF-PQ indexing |
| **SOC dashboard** | Next.js 14 standalone app, 17 pages, 40 API routes, real-time polling |
| **Monitoring** | Prometheus (11 scrape targets) + Grafana dashboards + alert rules |
| **Tiered storage** | Hot (ClickHouse) → Warm (S3) → Cold (S3 archive) with configurable TTLs |
| **Kubernetes-ready** | Kustomize base + overlays (development, production), PodDisruptionBudget |

### Production-Validated Results

| Metric | Value |
|---|---|
| Sustained throughput | **35,586 EPS** |
| Triage scores processed | **3.88M** |
| Hunter investigations | **7,476** |
| Verifier verdicts | **1,365** (100% XAI coverage) |
| Evidence anchors | **51** (SHA-256 Merkle roots) |
| Data loss | **0.0%** (2.5M/2.5M events verified) |
| Query avg latency | **61.4 ms** |
| Query P95 latency | **87.4 ms** |
| Consumer lag | **0 messages** |

---

## Problem Statement & Value Proposition

### The Problem

Security Operations Center (SOC) analysts are drowning. The average enterprise SOC receives **over 10,000 alerts per day**, yet studies show that **45% are false positives** (Ponemon Institute, 2023). Analysts spend hours manually triaging, investigating, and cross-referencing alerts across disconnected tools — leading to **alert fatigue**, missed real threats, and a global **Mean Time to Respond (MTTR) of 287 days** for data breaches (IBM Cost of a Data Breach Report).

Traditional SIEMs like Splunk, QRadar, and ArcSight provide powerful log search and correlation, but they still leave the hardest part — investigation and decision-making — entirely to humans. When a critical alert fires at 3 AM, the response depends on whoever is on-call, their experience level, and whether they can manually piece together the attack story before it's too late.

### The Solution

Chrontinal eliminates this bottleneck by deploying **autonomous AI agents** that handle the full investigation lifecycle — from initial triage through deep investigation to forensic verification — with **zero human intervention required**. Instead of flooding analysts with thousands of raw alerts, Chrontinal delivers:

- **Analyst-ready verdicts** — Every escalated threat arrives with a clear verdict (`true_positive`, `false_positive`, `inconclusive`), a priority level (P1–P4), and a full forensic narrative explaining *why*
- **Explainable decisions** — SHAP-based feature attribution shows exactly which log fields drove each score, so analysts can trust and audit the AI's reasoning
- **Tamper-proof evidence** — SHA-256 Merkle trees with S3 Object Lock create a cryptographic chain of custody that holds up in audits and legal proceedings
- **Sub-minute response** — The full pipeline (ingest → triage → investigate → verify → verdict) completes in ~25 seconds, turning hours of manual work into automated, continuous monitoring

> **Bottom line:** Chrontinal shifts SOC analysts from being reactive investigators to proactive decision-makers. They review AI-generated case files instead of raw logs — reducing MTTR from hours to seconds and ensuring zero real threats slip through the cracks.

---

## Innovation & Differentiators

Chrontinal is not just another SIEM with ML bolted on. It introduces several architectural innovations that set it apart:

- **Agentic AI architecture** — Four specialized agents (Triage, Hunter, Verifier, XAI) operate autonomously through a Kafka event bus. Unlike monolithic ML models, each agent has a focused responsibility, can scale independently, and the pipeline self-improves through a feedback loop. The Hunter agent even auto-retrains its CatBoost scorer every 6 hours using self-supervised labels.

- **Explainable AI (XAI) as a first-class citizen** — Every ML prediction comes with full SHAP TreeExplainer attribution. Analysts don't just see "score: 0.94" — they see that the score was driven by `dst_port_bin` (unusual port), `auth_status_is_fail` (repeated login failures), and `is_off_hours` (3 AM activity). This transparency builds trust and satisfies regulatory audit requirements.

- **Cryptographic evidence chain** — Merkle tree anchoring with SHA-256 hashing and S3 Object Lock creates an immutable, blockchain-style evidence trail. Every batch of processed events gets a verifiable root hash, making it mathematically provable that evidence was not tampered with — critical for compliance (SOC 2, HIPAA, PCI-DSS) and legal proceedings.

- **Multi-model ensemble with leakage auditing** — The Triage agent uses a 2-model ensemble (LightGBM + Autoencoder) that catches both known attack patterns and zero-day anomalies. The v8 model went through 7 rounds of data leakage discovery and fixing — a level of ML rigor rarely seen in security products.

- **Full-stack, end-to-end ownership** — Unlike commercial SIEMs that require dozens of third-party integrations, Chrontinal owns every layer: log ingestion (Vector), streaming (Redpanda), storage (ClickHouse + MinIO), AI pipeline (custom agents), vector search (LanceDB), and analyst interface (Next.js dashboard with SOAR capabilities). This means no vendor lock-in and full control over data flow.

- **Production-validated at scale** — Not a prototype. Chrontinal has processed **3.88M triage scores**, generated **7,476 autonomous investigations**, and delivered **1,365 forensic verdicts** with **zero data loss** at **26,586 EPS** sustained throughput — all on commodity hardware (two 16 GB machines).

- **Built-in SOAR capabilities** — The dashboard includes automated response actions (block attacker IP, isolate compromised accounts) that feed back into the detection pipeline, enabling closed-loop threat response without switching tools.

---

## System Architecture

```

┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Log Producers                                      │
│    Syslog (RFC 3164/5424) │ JSON HTTP │ Docker stdout │ File tails              │
└────────────────────────┬────────────────────────────────────────────────────────┘
                         │  TCP 1514 / TCP 9514
                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Vector Aggregator  (Rust-native, 3.0 CPU cores)                                │
│                                                                                 │
│  Sources:  syslog_tcp (RFC 5424, 10K conn)  │  tcp_json (NDJSON, 8MB buffer)   │
│  Transform: mega_transform (VRL)                                                │
│    • JSON parse + hostname/IP/level normalization                                │
│    • Event-type classification → security / process / network / raw             │
│    • Timestamp normalization + message body extraction                           │
│  Sinks: Route by type → 4 Kafka topics (acks=1, linger=5ms, 10 retries)        │
└────────────────────────┬────────────────────────────────────────────────────────┘
                         │  Kafka protocol
                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Redpanda Cluster  (3 brokers, C++ native, Kafka-compatible)                    │
│                                                                                 │
│  14 Topics:                                                                     │
│    Ingestion (12 partitions, RF=3, 7d):  raw-logs │ security-events │           │
│      process-events │ network-events                                            │
│    Triage (12 partitions):  templated-logs │ triage-scores │ anomaly-alerts     │
│    Agent (6 partitions):  hunter-tasks │ hunter-results │ verifier-tasks │      │
│      verifier-results                                                           │
│    Operational (3 partitions, 28d):  feedback-labels │ dead-letter │            │
│      pipeline-commands                                                          │
│  Config: LZ4 compression, max 10 MB messages, cleanup=delete                   │
└───────┬─────────────────────────────────┬───────────────────────────────────────┘
        │                                 │
        ▼                                 ▼
┌──────────────────────────┐   ┌─────────────────────────────────────────────────┐
│  Go Consumer ×2          │   │  Triage Agent ×4  (v8 ML Ensemble)              │
│                          │   │                                                  │
│  • 7-topic subscription  │   │  LightGBM ONNX (85%) + Autoencoder (15%)        │
│  • 500K-row batch inserts│   │  60 features: Core(9) + Network(15) + Auth(8)   │
│  • LZ4 + async inserts   │   │    + DNS(8) + Web(7) + Email(7) + Cloud(6)      │
│  • UUID5 deterministic   │   │  Score fusion → kill-chain/cross-host boosts    │
│  • Zero parse drops      │   │  SHAP explainability on escalated events        │
│  • Exponential backoff   │   │  Drain3 template mining + drift monitoring      │
│  • 4 flush workers       │   │  ≥0.90 → escalate │ 0.40–0.89 → monitor        │
└──────────┬───────────────┘   └──────┬──────────────────────────────────────────┘
           │                          │ escalated (score ≥ 0.90)
           │                          ▼
           │                   ┌─────────────────────────────────────────────────┐
           │                   │  Hunter Agent ×2  (v7 Investigation Engine)     │
           │                   │                                                  │
           │                   │  L1 Parallel: Sigma │ SPC │ Graph │ Temporal    │
           │                   │  L2 Parallel: MITRE Mapping │ Campaign Detection│
           │                   │  Scorer: Heuristic → CatBoost (auto-retrain)   │
           │                   │  Fusion → finding_type + severity + narrative   │
           │                   └──────┬──────────────────────────────────────────┘
           │                          │ hunter-results
           │                          ▼
           │                   ┌─────────────────────────────────────────────────┐
           │                   │  Verifier Agent  (Forensic Verification)        │
           │                   │                                                  │
           │                   │  Parallel: Evidence integrity │ IOC correlation │
           │                   │    Timeline reconstruction │ FP similarity      │
           │                   │  Verdict engine: true_positive │ false_positive │
           │                   │    inconclusive + confidence + priority P1–P4   │
           │                   │  Summary + forensic narrative + attack graph    │
           │                   └──────┬──────────────────────────────────────────┘
           │                          │
           ▼                          ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  ClickHouse Cluster  (2-node replicated shard)                                   │
│                                                                                  │
│  Core Tables:     raw_logs │ security_events │ process_events │ network_events  │
│  AI Tables:       triage_scores │ hunter_investigations │ verifier_results       │
│  Evidence:        evidence_anchors │ entity_baselines │ sigma_rule_hits         │
│  Aggregations:    events_per_minute (MV) │ security_severity_hourly (MV)        │
│  Engine:          ReplicatedMergeTree, ZSTD, daily partitions, S3 tiering       │
│  Tiered Storage:  hot (7d) → warm (30d, S3) → cold (90–365d) → delete          │
└──────────┬───────────────────────┬──────────────────────────────────────────────┘
           │ S3 API                │ HTTP 8123 / Native 9000
           ▼                       ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────────────────────┐
│  MinIO (3-node)     │  │  XAI Service        │  │  Merkle Evidence Agent       │
│  Erasure coded      │  │  SHAP TreeExplainer │  │  SHA-256 batch trees         │
│  Buckets:           │  │  /explain endpoint  │  │  30s daemon cycle            │
│   clif-cold-logs    │  │  Waterfall charts   │  │  S3 Object Lock archival     │
│   clif-backups      │  │  19 features v7     │  │  Chain: prev_merkle_root     │
│   clif-evidence-    │  │  Port 8200          │  │  evidence_anchors table      │
│     archive         │  └─────────────────────┘  └──────────────────────────────┘
└─────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  SOC Dashboard  (Next.js 14 Standalone)                                          │
│                                                                                  │
│  17 Pages:  Dashboard │ Alerts │ Investigations │ Live Feed │ Search │           │
│    AI Agents │ Threat Intel │ Evidence │ System Health │ Reports │               │
│    Explainability │ Attack Graph │ Chat │ Settings │ Chain-of-Custody           │
│  40 API Routes:  /api/metrics │ /api/alerts │ /api/events/stream │              │
│    /api/ai/agents │ /api/threat-intel │ /api/evidence/chain │ etc.              │
│  Real-time: 2s–15s polling, ClickHouse + Prometheus data sources               │
│  Port 3001, standalone Docker image                                              │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Data Flow

The end-to-end data flow from raw log ingestion to analyst-ready verdicts:

```
                         RAW LOGS (any format)
                                │
                    ┌───────────┴───────────┐
                    │  Vector VRL Transform  │
                    │  Parse → Classify      │
                    │  → Route by type       │
                    └───────────┬───────────┘
                                │
         ┌──────────────┬───────┼───────┬──────────────┐
         ▼              ▼       ▼       ▼              │
    raw-logs    security-events │  network-events      │
    (12 part)    (12 part)      │   (12 part)          │
         │              │      │       │               │
         │              │  process-events              │
         │              │   (12 part)  │               │
         │              │      │       │               │
         │       ┌──────┘      │       │               │
         │       ▼             ▼       │               │
         │  ┌─────────────────────┐    │               │
         │  │ TRIAGE (×4)         │    │               │
         │  │ 60 features         │    │               │
         │  │ LGBM(85%)+AE(15%)  │    │               │
         │  │ score → action      │    │               │
         │  └──┬──────────┬──────┘    │               │
         │     │          │ ≥0.90     │               │
         │     │          ▼           │               │
         │     │  ┌────────────────────┐              │
         │     │  │ HUNTER (×2)        │              │
         │     │  │ Sigma + SPC + Graph│              │
         │     │  │ + Temporal + MITRE │              │
         │     │  │ CatBoost scoring   │              │
         │     │  └──────┬─────────────┘              │
         │     │         │ findings                    │
         │     │         ▼                             │
         │     │  ┌────────────────────┐              │
         │     │  │ VERIFIER           │              │
         │     │  │ Evidence integrity │              │
         │     │  │ IOC correlation    │              │
         │     │  │ Timeline recon     │              │
         │     │  │ FP analysis        │              │
         │     │  │ → Verdict + P1–P4  │              │
         │     │  └──────┬─────────────┘              │
         │     │         │                             │
         ▼     ▼         ▼                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │            Go Consumer → ClickHouse                      │
  │  raw_logs │ security_events │ process_events │           │
  │  network_events │ triage_scores │                        │
  │  hunter_investigations │ verifier_results                │
  └──────────────────────────┬──────────────────────────────┘
                             │
                     ┌───────┴────────┐
                     ▼                ▼
              ┌──────────┐     ┌──────────────┐
              │ Merkle   │     │ MinIO S3     │
              │ Anchoring│────▶│ Object Lock  │
              │ SHA-256  │     │ Cold Storage │
              └──────────┘     └──────────────┘
```

### Streaming Topics vs. Model Log Types

The **4 Kafka topics** are high-level routing buckets that prioritize event processing. The **10 log types** are the model's internal classification that determines which of the 7 feature layers activate. These are two independent classification axes:

```
                    ┌─────────────────────────────────────────────┐
                    │      VECTOR VRL CLASSIFICATION              │
                    │                                             │
                    │  Phase 1: Route to Kafka topic              │
                    │   ┌───────────────────────────────────┐     │
                    │   │ 4 Streaming Topics (routing)      │     │
                    │   │  security-events  │ process-events│     │
                    │   │  network-events   │ raw-logs      │     │
                    │   └───────────────────────────────────┘     │
                    │                                             │
                    │  Phase 2: Detect log_type for model         │
                    │   ┌───────────────────────────────────┐     │
                    │   │ 10 Log Types (ML feature layers)  │     │
                    │   │  syslog │ windows │ firewall │ ad │     │
                    │   │  dns │ cloud │ web │ netflow  │   │     │
                    │   │  ids │ email                  │   │     │
                    │   └───────────────────────────────────┘     │
                    │                                             │
                    │  Phase 3: Identify source_type metadata     │
                    │   ┌───────────────────────────────────┐     │
                    │   │ 20+ Source Types (calibration)    │     │
                    │   │  sshd, sysmon, nginx, snort,      │     │
                    │   │  suricata, auditd, cloudtrail,    │     │
                    │   │  zeek, docker_logs, k8s_audit ... │     │
                    │   └───────────────────────────────────┘     │
                    └─────────────────────────────────────────────┘
```

**Why the separation matters:** A DNS tunneling alert routes to `security-events` (Kafka topic) but is scored using DNS features (domain entropy, bigram frequency, TLD risk). An SSH brute-force from Sysmon routes to `process-events` but activates Auth features (fail_rate, unique_targets). The topics organize the stream; the log types drive the ML.

**10 Log Types → Feature Layer Activation:**

| Log Type | Examples | Active Layers | Covers |
|---|---|---|---|
| `syslog` | sshd, sudo, auditd, PAM, journald, docker | Core + Auth | Linux/Unix system logs |
| `windows` | Windows Event Log, Sysmon, WinLogBeat | Core + Auth | Windows endpoint logs |
| `firewall` | iptables, pfSense, CEF-format rules | Core + Network | Firewall rule hits |
| `ad` | Active Directory, LDAP | Core + Auth | Identity & access management |
| `dns` | DNS queries, responses, BIND logs | Core + DNS | DGA detection, DNS tunneling |
| `cloud` | AWS CloudTrail, K8s audit, GCP audit | Core + Cloud | Cloud API audit trails |
| `web` | Nginx, Apache, HAProxy, WAF | Core + Web | SQL injection, XSS, path traversal |
| `netflow` | NetFlow v5/v9, IPFIX, sFlow | Core + Network | Network flow analysis |
| `ids` | Zeek, Snort, Suricata | Core + Network | IDS/IPS alert correlation |
| `email` | SMTP headers, email body analysis | Core + Email | Phishing, BEC detection |

> **Note:** Feature layers not relevant to a log type are zero-filled. The model learned these mappings during training — a DNS event's Network layer is all zeros, so those features have no influence on its score.

**20+ Source Types** (fine-grained producer metadata) are used for per-source Autoencoder threshold calibration — each source type has its own p99 reconstruction-error baseline.

### Validated Data Chain

```
raw_logs (461,911)
    ↓  Vector parsing + event-type routing
security_events (816,245) + network_events (2,483,606)
    ↓  Triage scoring (4 replicas, v8, 60 features, LGBM+AE)
triage_scores (3,882,816) → escalated: 1,085,889 (score ≥ 0.90)
    ↓  Hunter investigation (Sigma + SPC + Graph + Temporal + CatBoost)
hunter_investigations (7,476) → BEHAVIOURAL_ANOMALY / CONFIRMED_ATTACK / ACTIVE_CAMPAIGN
    ↓  Verifier validation (Evidence + IOC + Timeline + FP analysis)
verifier_results (1,365) → true_positive (728) / inconclusive (637)
    ↓  Merkle anchoring (SHA-256 batch trees → MinIO S3 Object Lock)
evidence_anchors (51) → forensic chain of custody
```

---

## Infrastructure Components

### Log Collection — Vector

[Vector](https://vector.dev/) is a Rust-native observability pipeline that handles all log ingestion, parsing, and routing.

| Parameter | Value |
|---|---|
| **Version** | Latest (official Docker image) |
| **CPU allocation** | 3.0 cores (limit), 1.5 cores (reserved) |
| **Memory** | 1 GB limit, 512 MB reserved |
| **Sources** | `syslog_tcp` (port 1514, RFC 5424, 10K connections) and `tcp_json` (port 9514, NDJSON, 8 MB buffer) |
| **Transform** | Single VRL `mega_transform`: JSON parse, timestamp normalization, hostname/IP/level extraction, event-type classification |
| **Routing** | Events classified as `security`, `process`, `network`, or `raw` → routed to corresponding Kafka topics |
| **Sinks** | 4 Kafka sinks (one per topic) → Redpanda brokers, acks=1, linger=5ms |
| **Delivery** | At-least-once (ClickHouse deduplicates via ReplacingMergeTree) |

### Message Streaming — Redpanda

[Redpanda](https://redpanda.com/) provides Kafka-compatible streaming without JVM overhead (C++ native).

| Parameter | Value |
|---|---|
| **Cluster** | 3 brokers (`redpanda01`, `redpanda02`, `redpanda03`) |
| **Resources per broker** | 1.0 CPU, 1.75 GB RAM, 1 SMP thread, 1500 MB memory |
| **External ports** | 17092, 29092, 39092 (Kafka), 18082, 28082, 38082 (Admin) |
| **Topics** | 14 total (see table below) |
| **Compression** | LZ4 (producer-managed) |
| **Max message** | 10 MB |
| **Cleanup** | Delete policy (not compaction) |

**Topic Configuration:**

| Category | Topics | Partitions | RF | Retention |
|---|---|---|---|---|
| **Ingestion** | `raw-logs`, `security-events`, `process-events`, `network-events` | 12 | 3 | 7 days |
| **Triage** | `templated-logs`, `triage-scores`, `anomaly-alerts` | 12 | 3 | 7 days |
| **Agent** | `hunter-tasks`, `hunter-results`, `verifier-tasks`, `verifier-results` | 6 | 3 | 7 days |
| **Operational** | `feedback-labels`, `dead-letter`, `pipeline-commands` | 3 | 3 | 28 days |

### Columnar Storage — ClickHouse

[ClickHouse](https://clickhouse.com/) serves as the primary analytical data store with columnar compression and SQL interface.

| Parameter | Value |
|---|---|
| **Cluster** | `clif_cluster`, 2 nodes (1 shard, 2 replicas) |
| **Node 1** | `clickhouse01` — ports 8123 (HTTP), 9000 (native TCP), 9363 (metrics) — 2.0 CPU, 2.5 GB RAM |
| **Node 2** | `clickhouse02` — ports 8124, 9001, 9364 — 0.5 CPU, 1.5 GB RAM |
| **Keeper** | `clickhouse-keeper` on port 2181 (ZooKeeper-compatible consensus) |
| **Engine** | `ReplicatedMergeTree` with ZSTD compression, daily partitions |
| **Database** | `clif_logs` |
| **Tables** | 26+ tables including 4 materialized views |
| **Replication** | ZooKeeper path: `/clickhouse/tables/{shard}/{table}/{replica}` |
| **Storage tiering** | `clif_tiered` policy: hot (local SSD) → warm (S3/MinIO) → cold (S3 archive) |
| **Deduplication** | `ReplacingMergeTree` ensures exactly-once semantics with at-least-once delivery |

### Object Storage — MinIO

[MinIO](https://min.io/) provides S3-compatible distributed object storage for cold data tiering and evidence archival.

| Parameter | Value |
|---|---|
| **Cluster** | 3 nodes (`minio1`, `minio2`, `minio3`), erasure coded |
| **Resources per node** | 0.5 CPU, 768 MB RAM |
| **Data port** | 9002 |
| **Console** | 9003 |
| **Buckets** | `clif-cold-logs`, `clif-backups`, `clif-evidence-archive` |
| **Object Lock** | Enabled on `clif-evidence-archive` for forensic integrity |

### Kafka→ClickHouse — Go Consumer

A custom high-performance Go binary that subscribes to Redpanda topics and writes to ClickHouse in optimized batches.

| Parameter | Value |
|---|---|
| **Instances** | 2 consumers (`clif-consumer`, `clif-consumer-2`) |
| **Consumer group** | `clif-clickhouse-consumer` |
| **Resources** | 1.0 CPU, 1 GB RAM per instance |
| **Batch size** | 500,000 rows |
| **Flush interval** | 0.5–2.0 seconds |
| **Poll batch** | 50,000 rows |
| **Flush workers** | 4 concurrent |
| **Compression** | LZ4 |
| **Insert mode** | Async (non-blocking), 4 max insert threads, 100 MB max data size |
| **Retry** | Exponential backoff (2^n seconds, capped at 30s) with jitter |

**Topics → Tables Mapping:**

| Kafka Topic | ClickHouse Table | ID Generation |
|---|---|---|
| `raw-logs` | `raw_logs` | UUID5 deterministic |
| `security-events` | `security_events` | UUID5 deterministic |
| `process-events` | `process_events` | UUID5 deterministic |
| `network-events` | `network_events` | UUID5 deterministic |
| `triage-scores` | `triage_scores` | Passthrough |
| `hunter-results` | `hunter_investigations` | Passthrough |
| `verifier-results` | `verifier_results` | Passthrough |
| `feedback-labels` | `feedback_labels` | Passthrough |

**UUID5 namespace:** `c71f0000-e1d0-4a6b-b5c3-deadbeef0042` — deterministic from `topic:partition:offset` for idempotent joins.

**Writer Architecture:**
- `WriterPool` — channel-based pool for concurrent flush goroutines
- `TableBuffer` — per-table columnar accumulator with zero-alloc snapshot swap
- `FlushAllParallel` — snapshots non-empty buffers and flushes concurrently via worker semaphore

---

## AI Agent Pipeline

Chrontinal's core differentiator: four specialized AI agents that autonomously detect, investigate, verify, and explain security threats through a Kafka-mediated pipeline. All agents are fully integrated, deployed, and production-validated.

### Triage Agent (v8)

The first-line ML scoring engine. Processes every security event through a 60-feature ensemble to classify threat level and route for investigation. Rebuilt from scratch with 18 real-world datasets, multi-round leakage auditing, and Optuna hyperparameter optimization.

**Architecture:**

| Component | Details |
|---|---|
| **Model version** | v8 (2-model ensemble, trained from scratch) |
| **Model 1 — LightGBM** | Weight: 0.85, 742 trees, ONNX Runtime (4.32 MB) |
| **Model 2 — Autoencoder** | Weight: 0.15, 60→192→128→16→128→192→60, ONNX Runtime (0.30 MB) |
| **Training data** | 18 datasets, 706,744 samples (60/20/20 split), z-scaled + clipped [-10, 10] |
| **Replicas** | 4 (ports 8300–8303) |
| **Resources per replica** | 1.5 CPU, 2.5 GB RAM |
| **Batch processing** | 2,000 events/batch, 500ms timeout, 4 inference workers |
| **Total scored** | 3,882,816 events |

**Model Performance (v8):**

| Metric | LightGBM | Autoencoder | Ensemble |
|---|---|---|---|
| **Accuracy** | 96.52% | — | 96.32% |
| **F1 Score** | 0.9447 | — | 0.9450 |
| **AUC-ROC** | 0.9957 | 0.8052 | — |
| **PR-AUC** | — | 0.7693 | — |
| **Train-Test Gap** | 1.42% | — | — |
| **Separation ratio** | — | 444.71× | — |

**Speed Benchmark (real data, 176,686 test logs):**

| Metric | Result |
|---|---|
| **Single-event latency** | 654 µs median |
| **Batch throughput (4096)** | 336 µs/event (2,973 EPS) |
| **Sustained throughput** | 335.7 µs/event (2,979 EPS) |
| **Feature extraction** | 17.2 µs/event (58,140 EPS) |
| **Full pipeline estimate** | 353 µs/event (~2,834 EPS) |

**60-Feature Vector (7 layers):**

| Layer | Count | Features | Description |
|---|---|---|---|
| **Shared Core** | 9 | `hour_sin/cos`, `dow_sin/cos`, `is_off_hours`, `log_type`, `severity_numeric`, `message_length_log`, `message_entropy` | Temporal encoding, event metadata — works on ANY log format. `log_type` encodes the detected type (0–9) so the model knows which layers matter. |
| **Network** | 15 | `dst_port_bin`, `protocol_numeric`, `total_bytes_log`, `byte_ratio`, `total_packets_log`, `packet_ratio`, `flow_duration_log`, `avg_pkt_size`, `pkt_size_variance`, `iat_mean/stddev`, `tcp_syn/rst/fin_flag`, `retransmit_ratio` | Activates for: firewall, netflow, ids. Zero-filled for non-network log types. |
| **Auth** | 8 | `auth_type_encoded`, `status_is_fail`, `is_admin`, `src_dst_match`, `is_remote`, `fail_rate`, `unique_targets`, `event_frequency` | Activates for: syslog, windows, ad. Authentication and access patterns. |
| **DNS** | 8 | `domain_length`, `domain_entropy`, `subdomain_depth`, `digit_ratio`, `max_consonant_run`, `bigram_frequency`, `has_hex_pattern`, `tld_risk` | Activates for: dns. DGA/tunneling detection via domain analysis. |
| **Web** | 7 | `url_length`, `url_entropy`, `query_param_count`, `has_sql_pattern`, `has_xss_pattern`, `has_traversal`, `http_method` | Activates for: web. HTTP request analysis for injection attacks. |
| **Email** | 7 | `subject_length`, `body_length_log`, `subject_entropy`, `url_count`, `caps_ratio`, `has_urgency`, `has_financial` | Activates for: email. Phishing and BEC detection. |
| **Cloud** | 6 | `event_name_encoded`, `is_sensitive_service`, `is_read_only`, `has_error`, `identity_type_encoded`, `is_root` | Activates for: cloud. AWS CloudTrail / K8s audit features. |

**Leakage Auditing (v8):**
- 7 rounds of leakage discovery and fixing: severity leaks (×7), SSH tautological features, CREMEv2 is_fail/fail_rate, 55K train-test overlaps, post-clip re-split bug, Windows schema leakage
- Final honest model validated with no data leakage artifacts

**Autoencoder Architecture:**
- Optuna-optimized: 13 trials → bottleneck=16, hidden=(192,128), LR=0.003587, dropout=0.0
- Trained on normal traffic only; detects anomalies via reconstruction error
- Per-source-type calibration (19 source types) using p99 thresholds

**Score Fusion & Routing:**

| Stage | Operation |
|---|---|
| 1. Model inference | LightGBM (0.85) + Autoencoder (0.15) → combined_score |
| 2. Kill-chain boost | Up to 1.5× multiplier if multi-stage attack progression detected |
| 3. Cross-host boost | 1.2× multiplier if correlated alerts span multiple hosts |
| 4. IOC boost | +0.05 to +0.20 context-aware scaling for known indicators |
| 5. Disagreement escalation | Forced to 0.95 if LGBM/AE disagree beyond threshold |
| 6. Route | ≥0.90 → `escalate` (anomaly-alerts + hunter-tasks) |
| | 0.40–0.89 → `monitor` (triage-scores, dashboard visible) |
| | <0.40 → `discard` (triage-scores, audit only) |

**Drift Monitoring:**
- PSI (Population Stability Index) with 10 bins, 5,000-score window
- Warning at PSI > 0.1, critical at PSI > 0.25
- Checked every 500 batches

### Hunter Agent (v7)

Autonomous investigation engine that performs deep analysis on escalated events using multiple parallel investigation engines and a self-training ML scorer.

**Architecture:**

| Component | Details |
|---|---|
| **Replicas** | 2 (HA, ports 8400–8401) |
| **Score gate** | `adjusted_score > 0.80` (raised from 0.70 — v8 triage is better-calibrated) |
| **Investigation window** | ±15 minutes around alert |
| **Concurrency** | 8 parallel investigations |
| **Dedup window** | 300 seconds |
| **Consumer** | aiokafka with snappy compression, resilient auto-restart loop |
| **Total investigations** | 7,476 |

**Triple-Layer Investigation Pipeline:**

| Layer | Engines | Description |
|---|---|---|
| **L1 — Parallel** | Sigma, SPC, Graph, Temporal, Similarity | 5 concurrent investigation engines |
| **L2 — Parallel** | MITRE Mapper, Campaign Detector | Tactical classification and multi-host campaign detection |
| **Scoring** | Heuristic → CatBoost | Automatic transition to ML scoring after 100 training samples; auto-retrain every 6 hours |

**Investigation Engines:**

| Engine | Output Features | Logic |
|---|---|---|
| **Sigma Engine** | Rule matches, severity, tactic, technique | Custom Sigma rule matching against log patterns |
| **SPC Engine** | `spc_z_score`, `spc_is_anomaly`, `spc_baseline_mean`, `spc_baseline_stddev` | Statistical Process Control: per-entity event-frequency baselines with 3σ threshold, 24h window, 60s refresh |
| **Graph Builder** | 8 dims: `unique_destinations`, `unique_src_ips`, `has_ioc_neighbor`, `hop_count`, `high_risk_neighbors`, `escalation_count`, `lateral_movement_score`, `c2_candidate_score` | Entity relationship graph construction from ±15min ClickHouse queries; noisy-IP filtering (>50 escalations + no IOC) |
| **Temporal Correlator** | `escalation_count`, `unique_categories`, `tactic_diversity`, `mean_score` | Time-series pattern detection: looks for higher-scored alerts in the investigation window |
| **Campaign Detector** | `campaign_host_count`, `campaign_tactic_count` | Fires when ≥3 network events AND ≥2 hosts AND ≥2 distinct MITRE tactics in window |

**Fusion & Output:**
- `FusionEngine` → `finding_type` + `hunter_score` + 42-feature investigation vector
- `NarrativeBuilder` → human-readable summary + severity + recommended action
- Finding types: `BEHAVIOURAL_ANOMALY` (4,205), `CONFIRMED_ATTACK` (2,962), `ACTIVE_CAMPAIGN` (308)
- Self-supervised training write to `hunter_training_data` table

**Drift Monitoring:**
- KL-divergence threshold: 0.1
- PSI threshold: 0.25
- Look-back: 7-day baseline vs 1-day current window

### Verifier Agent (v7)

Final-stage forensic verification that validates Hunter findings through evidence integrity checks, threat intelligence correlation, and timeline analysis. Produces analyst-ready verdicts with full narrative reports.

**Architecture:**

| Component | Details |
|---|---|
| **Port** | 8500 |
| **Resources** | 1.0 CPU, 512 MB RAM |
| **Consumer** | aiokafka, resilient loop with auto-restart |
| **Total verdicts** | 1,365 (100% XAI coverage) |

**Parallel Verification Pipeline:**

```python
await asyncio.gather(
    verify(),        # Merkle chain integrity validation
    correlate(),     # IOC database correlation (72h lookback)
    build(),         # Timeline reconstruction (24h window)
    analyze(),       # FP similarity analysis (LanceDB, threshold=0.3)
)
```

| Stage | Description |
|---|---|
| **Evidence Integrity** | Validates Merkle chain: re-computes SHA-256 root from leaf hashes, compares against stored `merkle_root` in `evidence_anchors` |
| **IOC Correlation** | Queries `network_events` for known IOC matches (IP, domain, hash) with 72-hour lookback |
| **Timeline Reconstruction** | Assembles 24-hour timeline from `raw_logs`, `triage_scores`, and `hunter_investigations` for the involved entities |
| **FP Analysis** | Uses LanceDB vector similarity search to find past false-positive patterns; threshold 0.3 |

**Verdict Decision Matrix:**

| Verdict | Confidence Range | Priority | Criteria |
|---|---|---|---|
| `true_positive` | 0.50–1.00 | P1–P2 | Evidence integrity + IOC match + suspicious timeline |
| `false_positive` | 0.30–0.70 | P3–P4 | FP similarity match + clean timeline + no IOC correlation |
| `inconclusive` | 0.30–0.60 | P2–P3 | Mixed signals or insufficient evidence |

**Output Artifacts:**
- `analyst_summary` — human-readable field notes
- `report_narrative` — full forensic story
- `evidence_json` — structured attack graph (Mermaid diagram)
- Published to `verifier-results` Kafka topic → Go consumer → `verifier_results` table

**Production Results:**
- true_positive: 728 (avg confidence: 0.524)
- inconclusive: 637 (avg confidence: 0.417)
- 2,092 Verifier→Hunter linked records

### XAI Service

Dedicated SHAP-based explainability microservice providing per-feature attribution for any ML prediction.

| Parameter | Value |
|---|---|
| **Port** | 8200 |
| **Backend** | SHAP TreeExplainer for LightGBM |
| **Model** | `lgbm_v8.onnx` |
| **Features** | 60 (matching Triage v8 feature vector) |
| **Top-K** | 10 most influential features per explanation |

**Endpoints:**

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Service readiness + model version |
| `/xai/status` | GET | Model version, F1 score, feature count |
| `/model/features` | GET | All features with importance scores |
| `/explain` | POST | Full SHAP attribution: waterfall chart, category breakdown, prediction drivers |

### Merkle Evidence Chain

Cryptographic evidence anchoring service for forensic chain-of-custody integrity.

| Parameter | Value |
|---|---|
| **Algorithm** | SHA-256 Merkle tree |
| **Daemon mode** | One batch every 30 seconds |
| **Scope** | 4 ClickHouse tables (raw_logs, security_events, process_events, network_events) |
| **Storage** | Merkle root → `evidence_anchors` table; proof object → MinIO with S3 Object Lock |
| **Chain linking** | Each anchor stores `prev_merkle_root` for blockchain-style chain |
| **Verified anchors** | 51 batches to date |
| **Retention** | 365 days |

**Verification command:**
```bash
python merkle_anchor.py --verify BATCH_ID    # Re-verify a specific batch
python merkle_anchor.py --daemon             # Continuous anchoring (30s cycle)
```

---

## Similarity Search — LanceDB

[LanceDB](https://lancedb.github.io/lancedb/) provides vector-based semantic search for the Hunter's similarity analysis and the dashboard's AI search.

| Parameter | Value |
|---|---|
| **Port** | 8100 |
| **Embedding model** | `all-MiniLM-L6-v2` (Sentence-Transformers, local inference) |
| **Embedding dimension** | 384 |
| **Index type** | IVF-PQ (Inverted File with Product Quantization) |
| **Vector tables** | 4 (mapping to ClickHouse event tables) |
| **Sync interval** | 30 seconds from ClickHouse |
| **Sync batch size** | 1,000 rows |
| **API** | FastAPI: `/search`, `/similar`, `/ingest`, `/stats` |
| **CORS** | Allowed origin: `localhost:3001` |

**Key Dependencies:** `lancedb ≥ 0.6.0`, `sentence-transformers ≥ 2.7`, `pyarrow ≥ 15.0`, `clickhouse-driver[lz4] ≥ 0.2.7`

---

## SOC Dashboard

A production-grade Security Operations Center dashboard built with Next.js 14 (standalone mode), providing real-time visibility into the entire Chrontinal pipeline.

**Stack:** Next.js 14.2.35, React 18, TypeScript 5, Tailwind CSS 3.4, Recharts 3.7, React Flow 12.10

### Pages (17)

| Page | Route | Data Source | Description |
|---|---|---|---|
| Landing | `/` | — | Navigation hub |
| **Dashboard** | `/dashboard` | ClickHouse (5s poll) | KPI cards (total events, ingest rate, active alerts, risk score, MTTR), severity distribution, event timeline, MITRE heatmap, top sources, risky entities |
| **Alerts** | `/alerts` | ClickHouse (5s poll) | Alert table with severity summary (critical/high/medium/low counts), MITRE technique labels, confidence scores, hostname + category filters |
| **Investigations** | `/investigations` | ClickHouse + Mock fallback | Investigation case list with severity, MITRE tags, assigned analyst, event counts, hosts, and users |
| **Live Feed** | `/live-feed` | ClickHouse (2s poll) | Real-time scrolling event stream with pause/resume, per-event detail expansion, source filtering |
| **Search** | `/search` | ClickHouse + LanceDB | Keyword + AI semantic search, time range and severity filters, combined results |
| **AI Agents** | `/ai-agents` | Agent health probes | Live agent status cards (triage, hunter, verifier, xai), cases processed, accuracy, response times |
| **Threat Intel** | `/threat-intel` | ClickHouse | IOC table (IPs, domains, hashes), MITRE ATT&CK pattern analysis, threat statistics |
| **Evidence** | `/evidence` | ClickHouse | Merkle evidence batches, event counts, SHA-256 roots, S3 keys |
| **System Health** | `/system` | Prometheus + Docker | Infrastructure service status, container health, latency metrics |
| **Reports** | `/reports` | Templates | Report generation interface with MITRE, ML model, and Sigma report templates |
| **Explainability** | `/explainability` | XAI service | SHAP waterfall charts, feature importance, model fairness, boundary analysis, drift monitoring |
| **Attack Graph** | `/attack-graph` | ClickHouse | React Flow visualization of attack paths and entity relationships |
| **Chat** | `/chat` | — | SOC analyst chat interface |
| **Settings** | `/settings` | — | User preferences and system configuration |
| **Chain of Custody** | `/chain-of-custody` | ClickHouse | Evidence chain timeline and verification status |
| **Investigation Detail** | `/investigations/[id]` | ClickHouse | Full investigation view with timeline, evidence, MITRE mapping |

### API Routes (37)

| Category | Routes | Description |
|---|---|---|
| **Metrics** | `/api/metrics` | 17 parallel ClickHouse queries: totalEvents, ingestRate, activeAlerts, severityDistribution, eventsTimeline, uptime (Prometheus), riskScore, MTTR, topSources, mitreTacticHeatmap, riskyEntities, tableCounts, evidenceBatches |
| **Alerts** | `/api/alerts` | Security events + triage scores JOIN, severity GROUP BY for summary counts, mapped to Alert type |
| **Events** | `/api/events/stream`, `/api/events/search` | UNION ALL across 4 event tables with normalized columns; full-text search |
| **AI** | `/api/ai/agents`, `/api/ai/chat`, `/api/ai/classify`, `/api/ai/investigate`, `/api/ai/investigations/list`, `/api/ai/investigations/[id]`, `/api/ai/leaderboard`, `/api/ai/xai`, `/api/ai/xai/*` (6 sub-routes) | Agent health probes, investigation listing, XAI sub-routes (boundary, drift, fairness, freshness, interactions, radar) |
| **Threat Intel** | `/api/threat-intel` | IOC extraction, MITRE stats, threat pattern analysis from security_events + triage_scores |
| **Evidence** | `/api/evidence/chain`, `/api/evidence/verify` | Evidence batch listing, Merkle verification |
| **Investigation** | `/api/investigations`, `/api/investigations/[id]` | Investigation queries from hunter_investigations table |
| **Search** | `/api/semantic-search`, `/api/similar-events`, `/api/lancedb` | LanceDB-proxied semantic search and event similarity |
| **Reports** | `/api/reports`, `/api/reports/download`, `/api/reports/history`, `/api/reports/ml`, `/api/reports/sigma` | Report generation and retrieval |
| **System** | `/api/system` | Service health from Prometheus + direct container checks |
| **SOAR** | `/api/block-ip`, `/api/block-user` | Block/unblock attacker IPs or compromised user accounts — automated response actions |
| **Auth** | `/api/auth` | Dashboard authentication |

**Dashboard Configuration:**
- Standalone Docker build (multi-stage: deps → builder → runner)
- `node:20-alpine` base image
- HSTS headers (1 year, includeSubDomains)
- Static asset caching (immutable, 1 year)
- CSP headers configured for Recharts/Next.js compatibility
- Port 3001

---

## Monitoring & Observability

### Prometheus

| Parameter | Value |
|---|---|
| **Port** | 9090 |
| **Scrape interval** | 15 seconds (30s for LanceDB and dashboard) |
| **Global labels** | `cluster=clif-siem`, `environment=production` |

**Scrape Targets (11):**

| Job | Target(s) | Metrics Path |
|---|---|---|
| `clickhouse-01` | `clickhouse01:9363` | `/metrics` |
| `clickhouse-02` | `clickhouse02:9363` | `/metrics` |
| `redpanda` | 3 brokers on port 9644 | `/public_metrics` |
| `minio` | `minio1:9000` | `/minio/v2/metrics/cluster` |
| `minio-node` | `minio1:9000` | `/minio/v2/metrics/node` |
| `vector` | `clif-vector:9598` | `/metrics` |
| `grafana` | `grafana:3000` | `/metrics` |
| `prometheus` | `localhost:9090` | self-scrape |
| `lancedb` | `clif-lancedb:8100` | `/stats` |
| `dashboard` | `clif-dashboard:3001` | `/api/system` |

### Grafana

| Parameter | Value |
|---|---|
| **Port** | 3002 |
| **Version** | v11.1.4 |
| **Dashboards** | Auto-provisioned JSON dashboard |
| **Data sources** | Prometheus (auto-configured) |

### Alert Rules

Custom Prometheus alerting rules for pipeline health monitoring configured in `monitoring/alert_rules.yml`.

---

## ClickHouse Schema Reference

### Core Event Tables

All core tables use `ReplicatedMergeTree` engine, ZSTD compression, and daily partitioning on `timestamp`.

| Table | Columns | Key Indexes | TTL Policy |
|---|---|---|---|
| **`raw_logs`** | 12 cols: `event_id`, `timestamp`, `level`, `source`, `message`, `metadata`, `user_id`, `ip_address`, `request_id`, `anchor_tx_id`, `anchor_batch_hash` | `message` (tokenbf), `user_id` (bloom), `ip_address` (minmax), `request_id` (bloom) | 7d hot → 30d warm → 90d delete |
| **`security_events`** | 16 cols: + `category`, `severity`, `hostname`, `source_ip`, `dst_ip`, `mitre_tactic`, `mitre_technique`, `ai_confidence`, `ai_explanation`, `raw_log_event_id` | `category` (set), `severity` (minmax), `mitre_tactic` (set), `user_id` (bloom), `source_ip` (minmax), `description` (tokenbf) | 180d delete |
| **`process_events`** | 20 cols: `pid`, `ppid`, `uid`, `gid`, `binary_path`, `arguments`, `cwd`, `exit_code`, `container_id`, `pod_name`, `namespace`, `syscall`, `is_suspicious`, `detection_rule` | `binary_path` (tokenbf), `pid` (minmax), `container_id` (bloom), `namespace` (set), `syscall` (set) | 90d delete |
| **`network_events`** | 20 cols: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `direction`, `bytes_sent`, `bytes_received`, `duration_ms`, `dns_query`, `geo_country`, `is_suspicious`, `detection_rule` | `src_ip` (minmax), `dst_ip` (minmax), `dst_port` (minmax), `protocol` (set), `dns_query` (tokenbf), `container_id` (bloom) | 90d delete |

### AI Pipeline Tables

| Table | Key Columns | TTL |
|---|---|---|
| **`triage_scores`** | `score_id`, `event_id`, `combined_score`, `lgbm_score`, `adjusted_score`, `action` (discard/monitor/escalate), `ioc_match`, `mitre_tactic`, `mitre_technique`, `shap_top_features`, `disagreement_flag`, `score_std_dev` | 7d → 30d → 90d |
| **`hunter_investigations`** | `investigation_id`, `alert_id`, `status` (pending/running/completed/failed/timeout), `trigger_score`, `severity` (info–critical), `finding_type`, `summary`, `evidence_json`, `correlated_events` (Array), `mitre_tactics` (Array), `mitre_techniques` (Array), `recommended_action`, `confidence` | 30d → 90d → 365d |
| **`verifier_results`** | `verification_id`, `investigation_id`, `alert_id`, `verdict` (true_positive/false_positive/inconclusive), `confidence`, `evidence_verified` (bool), `merkle_batch_ids` (Array), `timeline_json`, `ioc_correlations`, `priority` (P1–P4), `analyst_summary`, `report_narrative`, `evidence_json` | 30d → 90d → 365d |
| **`evidence_anchors`** | `batch_id`, `table_name`, `time_from`, `time_to`, `event_count`, `merkle_root`, `merkle_depth`, `leaf_hashes` (Array), `s3_key`, `s3_version_id`, `status`, `prev_merkle_root` | 365d |

### Hunter Support Tables

| Table | Purpose | TTL |
|---|---|---|
| **`entity_baselines`** | SPC per-entity behavioral baselines (hostname × metric_name → mean, std, sample_count) | 7d |
| **`sigma_rule_hits`** | Audit trail of Sigma rule matches (rule_id, hostname, severity, MITRE mapping) | 90d |
| **`hunter_training_data`** | Self-supervised CatBoost training data (feature_vector, label, label_source, confidence) | 30d rolling |
| **`hunter_model_health`** | Drift detection metrics (KL divergence, PSI, triage divergence, sample_count) | 90d |

### Materialized Views

| View | Source → Target | Aggregation |
|---|---|---|
| `events_per_minute` | `raw_logs` → `events_per_minute` | Per-minute count by source and level (30d TTL) |
| `events_per_minute_security_mv` | `security_events` → `events_per_minute` | Security events rolled up per minute |
| `events_per_minute_process_mv` | `process_events` → `events_per_minute` | Process events with suspicious/normal flag |
| `security_severity_hourly` | `security_events` → `security_severity_hourly` | Per-hour count by category and severity (90d TTL) |

All tables have corresponding `*_dist` distributed variants for cross-shard queries.

---

## Deployment Architecture

Chrontinal uses a **2-machine split deployment** optimized for resource utilization:

### PC1 — Data & Ingestion Tier

| Machine | OS | CPU | RAM | Role |
|---|---|---|---|---|
| **PC1** | Windows | i5-13420H (8C/12T) | 16 GB | Data collection, streaming, storage |

**13 Containers:**

| Service | Port(s) | CPU (limit) | RAM (limit) | Description |
|---|---|---|---|---|
| `clif-vector` | 1514, 8686, 9514, 9598 | 3.0 | 1 GB | Log aggregator (Rust) |
| `clif-clickhouse-keeper` | 2181 | 0.3 | 512 MB | Replication consensus |
| `clif-clickhouse01` | 8123, 9000, 9363 | 2.0 | 2.5 GB | Primary ClickHouse replica |
| `clif-clickhouse02` | 8124, 9001, 9364 | 0.5 | 1.5 GB | Secondary replica |
| `clif-redpanda01` | 17092, 18082 | 1.0 | 1.75 GB | Kafka broker (seed) |
| `clif-redpanda02` | 29092, 28082 | 1.0 | 1.75 GB | Kafka broker |
| `clif-redpanda03` | 39092, 38082 | 1.0 | 1.75 GB | Kafka broker |
| `clif-minio1` | 9002, 9003 | 0.5 | 768 MB | S3 storage (data port + console) |
| `clif-minio2` | — | 0.5 | 768 MB | S3 cluster member |
| `clif-minio3` | — | 0.5 | 768 MB | S3 cluster member |
| `clif-consumer` | — | 1.0 | 1 GB | Go Kafka→ClickHouse writer |
| `clif-consumer-2` | — | 1.0 | 1 GB | Go Kafka→ClickHouse writer |
| `clif-dashboard` | 3001 | — | — | Next.js SOC dashboard |

**Resource budget:** ~12.3 CPU / 12 cores, ~15.1 GB / 16 GB RAM

### PC2 — AI Compute & Monitoring Tier

| Machine | OS | CPU | RAM | Role |
|---|---|---|---|---|
| **PC2** | Windows | 10 cores | 16 GB | ML inference, investigation, monitoring |

**13 Containers:**

| Service | Port(s) | CPU (limit) | RAM (limit) | Description |
|---|---|---|---|---|
| `clif-triage-agent` | 8300 | 1.5 | 2.5 GB | Triage ML ensemble (replica 1) |
| `clif-triage-agent-2` | 8301 | 1.5 | 2.5 GB | Triage (replica 2) |
| `clif-triage-agent-3` | 8302 | 1.5 | 2.5 GB | Triage (replica 3) |
| `clif-triage-agent-4` | 8303 | 1.5 | 2.5 GB | Triage (replica 4) |
| `clif-hunter-agent` | 8400 | 1.75 | 2 GB | Hunter investigation engine (primary) |
| `clif-hunter-agent-2` | 8401 | 1.0 | 1.5 GB | Hunter (HA replica) |
| `clif-verifier-agent` | 8500 | 1.0 | 512 MB | Forensic verifier |
| `clif-xai-service` | 8200 | 0.5 | 512 MB | SHAP explainability |
| `clif-merkle` | — | 0.5 | 256 MB | Evidence anchoring |
| `lancedb` | 8100 | 0.5 | 512 MB | Vector similarity search |
| `clif-prometheus` | 9090 | 0.5 | 512 MB | Metrics collection |
| `clif-grafana` | 3002 | 0.25 | 256 MB | Monitoring dashboards |
| `clif-redpanda-console` | 8080 | 0.25 | 256 MB | Redpanda admin UI |

**Resource budget:** ~12.25 CPU / 12 cores, ~16.3 GB / 16 GB RAM

### Cross-Machine Communication

```
PC1 (Data)                          PC2 (AI Compute)
─────────────────                   ─────────────────
Redpanda ◄────── Kafka protocol ──────► Triage/Hunter/Verifier
ClickHouse ◄──── Native TCP 9000 ──────► Hunter/Verifier/Merkle
MinIO ◄────────── S3 API (9002) ───────► Merkle Agent
Dashboard ◄────── HTTP healthcheck ────► Prometheus scrape
```

Environment variable `DATA_IP` on PC2 points to PC1's IP address for cross-machine Redpanda/ClickHouse connectivity.

### GCP Deployment

Chrontinal also supports Google Cloud Platform deployment with dedicated compose files:

- **Single-node** (`docker-compose.gcp.yml`): All services on one VM — deploy with `deploy-gcp.sh`
- **2-node** (`docker-compose.gcp-node1.yml` + `docker-compose.gcp-node2.yml`): Same PC1/PC2 split on GCP VMs — deploy with `deploy-gcp-2node.sh`

GCP-specific environment files (`.env.gcp`, `.env.gcp-2node`) and cluster scripts (`cluster/gcp/`, `cluster/gcp-2node/`) handle VM-specific networking and resource tuning.

---

## Kubernetes Deployment

Chrontinal includes a complete Kubernetes deployment using [Kustomize](https://kustomize.io/) with environment-specific overlays.

**Base resources** (`k8s/base/`):
- ConfigMaps, Secrets, Deployments, StatefulSets, Services, PVCs, RBAC, HPA, NetworkPolicies, Namespace

**Overlays:**
- `k8s/overlays/development/` — development cluster settings
- `k8s/overlays/production/` — production hardening + PodDisruptionBudget

**Deploy:**
```bash
# Development
kubectl apply -k k8s/overlays/development/

# Production
kubectl apply -k k8s/overlays/production/
```

---

## Benchmark Results

2-machine cluster benchmark: PC1 (Intel i5-13420H, 16 GB) data tier + PC2 AI compute.

| Metric | Result | Enterprise Target | Status |
|---|---|---|---|
| **Sustained Throughput** | **26,586 EPS** | ≥10,000 EPS | **PASS** |
| **Triage Scores Written** | **3,882,816** | — | **PASS** |
| **Hunter Investigations** | **7,476** | — | **PASS** |
| **Verifier Verdicts** | **1,365** | — | **PASS** |
| **Evidence Anchors** | **51** | — | **PASS** |
| **Data Loss** | **0.0%** | 0% | **PASS** |
| **Consumer Lag** | **0 messages** | <10,000 | **PASS** |
| **Query Avg Response** | **61.4 ms** | <200 ms | **PASS** |
| **Query P95 Response** | **87.4 ms** | <500 ms | **PASS** |
| **Zero Data Loss** | **2.5M / 2.5M events** | Zero loss | **PASS** |

---

## Validated Pipeline Metrics

Full 12-test pipeline validation report (2026-03-07):

| Test Category | Result | Details |
|---|---|---|
| Infrastructure (Containers) | **PASS** | 23/23 containers healthy |
| Redpanda Cluster | **PASS** | 3 brokers, 0 lag, 14 topics created |
| ClickHouse Cluster | **PASS** | 2-node replicated, 0 replication lag, 26 tables |
| Go Consumer Pipeline | **PASS** | 0 errors, 0 parse drops, 0 consumer lag |
| Triage ML v8 | **PASS** | 60 features, LGBM+AE ensemble, F1=0.9450, 4 replicas |
| Hunter Agent v7 | **PASS** | Sigma + SPC + Graph + Temporal, 7,476 investigations |
| Verifier Agent v7 | **PASS** | 1,365 verdicts, 100% XAI coverage |
| XAI Service | **PASS** | SHAP waterfall + category attribution |
| Merkle Evidence Chain | **PASS** | 51 SHA-256 anchors, S3 Object Lock |
| Monitoring (Prometheus) | **PASS** | 11 scrape targets (9 UP) |
| End-to-End Flow | **PASS** | ~25 sec full pipeline latency |
| Dashboard | **PASS** | 17 pages, 40 API routes, real-time data |

---

## Test Suite

Chrontinal includes a comprehensive test suite covering infrastructure, data integrity, performance, resilience, accuracy, and explainability.

**Test runner:** pytest with shared fixtures (ClickHouse host, Redpanda broker, MinIO endpoint)

| Category | Test Files | Focus |
|---|---|---|
| **Infrastructure** | `test_infrastructure.py`, `test_ch_port.py` | Cluster health, schema validation, port connectivity |
| **E2E Pipeline** | `test_triage_e2e.py`, `test_log_flow.py`, `pipeline_test.py` | Full pipeline validation (41 tests) |
| **Performance** | `performance_test.py`, `eps_benchmark.py`, `enterprise_benchmark.py` | Throughput, latency, burst handling, concurrent queries |
| **Data Integrity** | `test_data_integrity.py`, `test_lancedb.py` | Event counts, deduplication, semantic search accuracy |
| **Accuracy** | `test_model_accuracy_audit.py` | ML model F1/precision/recall, attack detection coverage |
| **Resilience** | `test_resilience.py`, `resilience_test.sh` | Fault tolerance: node kills, network partitions, recovery |
| **XAI** | `test_xai.py`, `test_shap_import.py` | SHAP explanation correctness, import validation |

**Running tests:**
```bash
pip install -r tests/requirements.txt

# Full suite
pytest tests/ -v --tb=short

# By category
pytest tests/test_infrastructure.py -v
pytest tests/test_data_integrity.py -v
pytest tests/test_performance.py -v -s
pytest tests/test_resilience.py -v -s

# Enterprise benchmark (2M events, burst, latency probes)
python tests/enterprise_benchmark.py
```

### Utility Scripts

The `scripts/` directory contains operational utilities:

| Category | Scripts |
|---|---|
| **Training** | `train_lgbm_v8.py`, `train_autoencoder_v8.py`, `train_v7.py`, `retrain_*.py`, `calibrate_*.py` |
| **Feature Engineering** | `extract_features_v8.py` (60 features from 18 datasets), `normalize_labels.py` |
| **Data** | `extract_auth_diverse*.py`, `bootstrap_*.py`, `seed_lancedb.py`, `generate_k8s_audit.py` |
| **Load testing** | `load_gen_multiproc.py` |
| **Surveys** | `survey_datasets.py`, `survey2.py`, `survey3.py` |

---

## Quick Start

### Prerequisites

- **Docker** ≥ 24.0 and **Docker Compose** v2
- **Go** ≥ 1.21 (for consumer build)
- **Python** ≥ 3.11 (for agents and scripts)
- **2 machines** recommended (one for data tier, one for AI compute)

### 1. Clone & Configure

```bash
git clone <repository-url>
cd CLIF
# Edit .env with your passwords and IP addresses
```

### 2. Start Data Tier (PC1)

```bash
docker compose -f docker-compose.pc1.yml up -d
```

This starts (in dependency order):
1. ClickHouse Keeper → ClickHouse nodes (26 tables auto-applied)
2. Redpanda brokers (3-node cluster, 14 topics auto-created)
3. MinIO nodes (3-node erasure coded)
4. Vector (log aggregator)
5. Go Consumers (×2, Kafka→ClickHouse writers)
6. Dashboard (Next.js, port 3001)

### 3. Start AI Compute (PC2)

```bash
docker compose -f docker-compose.pc2.yml up -d
```

This starts:
1. Triage Agent (×4 replicas, LightGBM+Autoencoder ensemble)
2. Hunter Agent (×2, Sigma + SPC + Graph + CatBoost)
3. Verifier Agent (forensic verification)
4. XAI Service (SHAP explainability)
5. Merkle Agent (SHA-256 evidence anchoring)
6. LanceDB (vector similarity search)
7. Prometheus + Grafana (monitoring)
8. Redpanda Console (admin UI)

### 4. Verify Health

```bash
# Check all containers
docker compose -f docker-compose.pc1.yml ps    # PC1
docker compose -f docker-compose.pc2.yml ps    # PC2

# ClickHouse
curl "http://localhost:8123/?query=SELECT+version()"

# Redpanda
rpk cluster health --brokers localhost:17092

# AI Agents
curl http://<PC2_IP>:8300/health    # Triage
curl http://<PC2_IP>:8400/health    # Hunter
curl http://<PC2_IP>:8500/health    # Verifier
curl http://<PC2_IP>:8200/health    # XAI
```

### 5. Access Web UIs

| Service | URL | Notes |
|---|---|---|
| **SOC Dashboard** | `http://localhost:3001` | Main analyst interface |
| **Grafana** | `http://<PC2_IP>:3002` | Monitoring dashboards |
| **Redpanda Console** | `http://<PC2_IP>:8080` | Topic management |
| **MinIO Console** | `http://localhost:9003` | S3 storage management |
| **Prometheus** | `http://<PC2_IP>:9090` | Raw metrics |
| **ClickHouse HTTP** | `http://localhost:8123` | SQL query interface |

---

## Architecture Decisions

### Why ClickHouse over Elasticsearch?

- **10–20× better compression** on structured log data (columnar + ZSTD vs inverted index)
- **Sub-second analytical queries** on billions of rows vs Elasticsearch's multi-second aggregation
- **Built-in S3 tiering** — automatic hot→warm→cold data movement, 90% cost reduction
- **SQL interface** — no proprietary query DSL learning curve for SOC analysts
- **ReplicatedMergeTree** — async replication with built-in deduplication for exactly-once semantics

### Why Redpanda over Apache Kafka?

- **C++ native** — no JVM overhead, 10× lower tail latency, predictable performance
- **Kafka-compatible** — drop-in replacement, all client libraries (Go, Python) work unchanged
- **No ZooKeeper** — simplified operations, single binary per broker
- **Thread-per-core architecture** — maximizes hardware utilization on modern CPUs

### Why Go for the Consumer?

- **Performance** — compiled binary with near-zero GC overhead, minimal memory footprint
- **Concurrency** — goroutine-based flush workers, channel-based writer pools
- **Control** — manual offset commit after confirmed ClickHouse insert (exactly-once guarantee)
- **Reliability** — exponential backoff with jitter, automatic reconnect, structured error handling
- **Horizontal scaling** — 2 instances consuming 12 Redpanda partitions (6 each)

### Why LanceDB for Vector Search?

- **Embedded-first** — runs as a lightweight sidecar, no cluster to manage
- **Fast ANN search** — IVF-PQ indexing for sub-millisecond similarity queries
- **Auto-sync** — continuously indexes new ClickHouse events (30s cycle)
- **Sentence-Transformers** — `all-MiniLM-L6-v2` for high-quality 384-dim embeddings

### Why MinIO over Cloud S3?

- **Fully offline-capable** — identical S3 API without cloud dependency
- **Erasure coding** — data durability across 3 nodes without replication overhead
- **Swap-ready** — change one endpoint URL to move to AWS S3 / GCS / Azure Blob in production

### Why Merkle Trees for Evidence?

- **Forensic integrity** — SHA-256 trees prove no event was added, removed, or modified
- **Chain linking** — `prev_merkle_root` creates a blockchain-style evidence chain
- **S3 Object Lock** — WORM (Write Once Read Many) compliance for regulatory requirements
- **Efficient verification** — re-verify any batch in O(n) by recomputing tree from leaf hashes

### Why a 2-Model Ensemble (v8)?

- **LightGBM (85%)** — 742 trees, strong on known attack patterns (F1=0.9447, AUC=0.9957), interpretable feature importance
- **Autoencoder (15%)** — 60→16→60 bottleneck, reconstruction error detects novel/zero-day attacks not in training data (AUC-ROC=0.8052, 444.71× separation)
- **v8 improvements over v7**: 60 features (was 32), 18 datasets (was fewer), 7-round leakage audit, Optuna-tuned AE, per-source-type calibration, train-test gap of 1.42%
- **Result**: Broader coverage, better calibration, sustained ~3,000 EPS single-threaded

---

## File Layout

```
CLIF/
├── docker-compose.pc1.yml            # PC1 data tier (13 services)
├── docker-compose.pc2.yml            # PC2 AI compute (13 services)
├── docker-compose.mac.yml            # macOS deployment
├── docker-compose.gcp.yml            # GCP single-node deployment
├── docker-compose.gcp-node1.yml      # GCP 2-node: Node 1 (data tier)
├── docker-compose.gcp-node2.yml      # GCP 2-node: Node 2 (AI compute)
├── deploy-gcp.sh                     # GCP single-node deploy script
├── deploy-gcp-2node.sh               # GCP 2-node deploy script
├── README.md                         # This file
│
├── agents/                           # AI Agent Pipeline
│   ├── triage/                       # Triage Agent (×4 replicas)
│   │   ├── app.py                    # TriageProcessor + FastAPI health/stats
│   │   ├── config.py                 # Model paths, thresholds, weights
│   │   ├── model_ensemble.py         # LightGBM + Autoencoder ONNX ensemble
│   │   ├── feature_extractor.py      # 60-feature extraction (7 layers)
│   │   ├── score_fusion.py           # Weighted fusion, boosts, routing
│   │   ├── shap_explainer.py         # Async SHAP TreeExplainer
│   │   ├── drain3_miner.py           # Thread-safe Drain3 template mining
│   │   ├── Dockerfile                # Python 3.11-slim, healthcheck
│   │   ├── requirements.txt          # onnxruntime, numpy, drain3, confluent-kafka
│   │   └── models/                   # lgbm_v8.onnx, autoencoder_v8.onnx, scalers, calibration
│   ├── hunter/                       # Hunter Agent (×2 HA)
│   │   ├── app.py                    # FastAPI + resilient aiokafka loop
│   │   ├── config.py                 # Score gate, concurrency, drift thresholds
│   │   ├── investigation/            # Investigation engines:
│   │   │   ├── sigma_engine.py       #   Sigma rule matching
│   │   │   ├── spc_engine.py         #   Statistical Process Control
│   │   │   ├── graph_builder.py      #   Entity relationship graph
│   │   │   ├── temporal_correlator.py#   Time-series correlation
│   │   │   ├── campaign_detector.py  #   Multi-host campaign detection
│   │   │   ├── similarity_searcher.py#   LanceDB similarity search
│   │   │   └── mitre_mapper.py       #   MITRE ATT&CK mapping
│   │   ├── Dockerfile                # Python 3.11-slim, port 8400
│   │   └── requirements.txt          # fastapi, aiokafka, catboost, clickhouse-connect
│   ├── verifier/                     # Verifier Agent
│   │   ├── app.py                    # Evidence/IOC/Timeline/FP verification pipeline
│   │   ├── config.py                 # Timeline windows, thresholds, HMAC settings
│   │   ├── Dockerfile                # Python 3.11-slim, port 8500
│   │   └── requirements.txt          # fastapi, aiokafka, clickhouse-connect, httpx
│   ├── xai-service/                  # XAI Explainability Service
│   │   ├── app.py                    # /health /explain /model/features endpoints
│   │   ├── Dockerfile                # Python 3.11-slim, port 8200
│   │   └── requirements.txt          # shap, onnxruntime, fastapi
│   └── Data/                         # Training datasets
│       └── Latest_Dataset/           # Current training corpus
│
├── consumer/                         # Python Kafka→ClickHouse Consumer (legacy)
│   ├── app.py                        # Python consumer application
│   ├── Dockerfile                    # Python service
│   └── requirements.txt              # Python dependencies
│
├── consumer-go/                      # Go Kafka→ClickHouse Consumer (×2)
│   ├── main.go                       # Configuration, Kafka consumer loop
│   ├── consumer.go                   # Topic subscription, message dispatch
│   ├── schema.go                     # Table schemas, column mappings, UUID5
│   ├── writer.go                     # WriterPool, TableBuffer, batch inserts
│   ├── go.mod                        # Go module definition
│   └── Dockerfile                    # Multi-stage Go build
│
├── merkle-service/                   # Merkle Evidence Chain
│   ├── merkle_anchor.py              # SHA-256 batch trees, S3 archive, daemon mode
│   ├── Dockerfile                    # Python service
│   └── requirements.txt              # clickhouse-connect, boto3, orjson
│
├── lancedb-service/                  # Vector Similarity Search
│   ├── app.py                        # FastAPI: /search /similar /ingest /stats
│   ├── Dockerfile                    # Python + sentence-transformers
│   └── requirements.txt              # lancedb, sentence-transformers, pyarrow
│
├── demo/                             # Demo Environment
│   ├── securebank/                   # SecureBank vulnerable web app
│   │   ├── app.py                    # Flask banking app with SOAR (block-IP)
│   │   ├── attack.py                 # 7-phase attack simulator
│   │   ├── Dockerfile                # Python Flask service
│   │   └── templates/                # HTML templates
│   ├── benchmark.py                  # Demo benchmark script
│   └── docker-compose.demo.yml       # Demo environment compose
│
├── clickhouse/                       # ClickHouse Configuration
│   ├── schema.sql                    # 26 tables + 4 materialized views
│   ├── hunter_schema.sql             # Hunter-specific tables (baselines, Sigma hits)
│   ├── keeper_config.xml             # ClickHouse Keeper settings
│   ├── node01_config.xml             # Replica 1 cluster config
│   ├── node02_config.xml             # Replica 2 cluster config
│   ├── storage_policy.xml            # S3 tiered storage policy
│   └── users.xml                     # Auth configuration
│
├── vector/                           # Vector Log Aggregator
│   └── vector.yaml                   # Sources, transforms (VRL), sinks, routing
│
├── redpanda/                         # Redpanda Configuration
│   ├── topics.sh                     # 14 topic creation script
│   └── console-config.yml            # Redpanda Console web UI config
│
├── monitoring/                       # Prometheus + Grafana
│   ├── prometheus.yml                # 11 scrape targets, 15s interval
│   ├── alert_rules.yml               # Alerting rules
│   ├── grafana-dashboard.json        # Auto-provisioned dashboard
│   ├── grafana-dashboards.yml        # Dashboard provisioning config
│   └── grafana-datasources.yml       # Prometheus data source config
│
├── dashboard/                        # SOC Dashboard (Next.js 14)
│   ├── Dockerfile                    # Multi-stage standalone build
│   ├── next.config.mjs               # Standalone output, HSTS, CSP, caching
│   ├── package.json                  # 27 deps: React 18, Recharts, React Flow
│   ├── tailwind.config.ts            # Tailwind CSS configuration
│   ├── tsconfig.json                 # TypeScript 5 strict config
│   └── src/
│       ├── app/                      # 17 pages + 40 API routes
│       ├── components/               # Reusable UI components (shadcn/ui)
│       ├── hooks/                    # usePolling, useDebounce, etc.
│       └── lib/                      # Types, utilities, mock data, ClickHouse client
│
├── tests/                            # Test Suite
│   ├── conftest.py                   # Shared pytest fixtures
│   ├── test_infrastructure.py        # Cluster health, schema, configs
│   ├── test_data_integrity.py        # E2E data validation
│   ├── test_triage_e2e.py            # Triage agent end-to-end
│   ├── enterprise_benchmark.py       # 2M event enterprise benchmark
│   └── ... (35 test files total)
│
├── scripts/                          # Operational Utilities
│   ├── train_lgbm_v8.py              # LightGBM v8 training pipeline
│   ├── train_autoencoder_v8.py       # Autoencoder v8 training (Optuna)
│   ├── extract_features_v8.py        # 60-feature extraction from 18 datasets
│   ├── calibrate_*.py                # Threshold calibration
│   ├── bootstrap_*.py                # Data bootstrapping
│   └── ...
│
├── k8s/                              # Kubernetes Deployment (Kustomize)
│   ├── base/                         # Deployments, StatefulSets, Services, PVCs, RBAC, HPA
│   └── overlays/
│       ├── development/              # Dev cluster config
│       └── production/               # Prod config + PodDisruptionBudget
│
└── cluster/                          # Cluster Management Scripts
    ├── setup.ps1                     # Windows setup automation
    ├── setup-mac.sh                  # Mac setup automation
    ├── health-check.ps1              # Windows health check
    ├── health-check-mac.sh           # Mac health check
    ├── firewall-pc1.ps1              # Windows firewall rules
    ├── gcp/                          # GCP single-node cluster configs
    ├── gcp-2node/                    # GCP 2-node cluster configs
    └── monitoring/                   # Additional monitoring configs

├── sysmon/                           # Sysmon Log Collection (Windows)
│   ├── sysmonconfig-clif.xml         # Custom Sysmon configuration
│   ├── Install-ClifSysmon.ps1       # Sysmon installation script
│   ├── Uninstall-ClifSysmon.ps1     # Sysmon removal script
│   ├── Get-ClifSysmonStatus.ps1     # Sysmon status check
│   └── vector-agent-windows.yaml    # Vector agent config for Windows endpoints
│
└── tools/                            # Utility Tools
    └── tcpblaster/                   # TCP load testing utility
```

---

## Troubleshooting

### ClickHouse Not Starting

```bash
# Check keeper health first
docker logs clif-clickhouse-keeper
echo ruok | nc localhost 2181    # should return "imok"
# Then check node logs
docker logs clif-clickhouse01
```

### Redpanda Topics Not Created

```bash
# Verify topics
rpk topic list --brokers localhost:17092
# Re-run topic creation
docker exec -it clif-redpanda01 bash /etc/redpanda/topics.sh
```

### Consumer Lag Building Up

```bash
# Check consumer group
rpk group describe clif-clickhouse-consumer --brokers localhost:17092
# Check consumer logs
docker logs clif-consumer -f --tail 100
```

### AI Agents Not Responding

```bash
# Health check each agent
curl http://<PC2_IP>:8300/health    # Triage
curl http://<PC2_IP>:8400/health    # Hunter
curl http://<PC2_IP>:8500/health    # Verifier
curl http://<PC2_IP>:8200/health    # XAI

# Check logs
docker logs clif-triage-agent -f --tail 100
docker logs clif-hunter-agent -f --tail 100
```

### Dashboard Showing Empty Data

```bash
# Verify ClickHouse has data
curl "http://localhost:8123/?query=SELECT+count()+FROM+clif_logs.security_events"
# Check API response
curl http://localhost:3001/api/metrics
curl http://localhost:3001/api/alerts
```

### Tear Down

```bash
# Stop everything and remove volumes (fresh start)
docker compose -f docker-compose.pc1.yml down -v
docker compose -f docker-compose.pc2.yml down -v

# Stop but keep data
docker compose -f docker-compose.pc1.yml down
docker compose -f docker-compose.pc2.yml down
```

---
### Future Scope

If development continues, the following enhancements are planned:

| Area | Enhancement | Impact |
|---|---|---|
| **SOAR Integration** | Deep integration with SOAR platforms (Palo Alto XSOAR, Splunk SOAR) for automated playbook execution beyond IP blocking | Fully automated incident response workflows |
| **Federated Learning** | Privacy-preserving model training across multiple Chrontinal deployments without sharing raw log data | Cross-organization threat intelligence without data exposure |
| **LLM-Powered Analyst Chat** | GPT-4/Claude integration in the SOC chat for natural-language threat investigation ("Show me all lateral movement from 10.0.0.5 this week") | Democratize threat hunting for junior analysts |
| **Real-Time MITRE Navigator** | Interactive ATT&CK coverage map showing live detection gaps and attack surface evolution | Continuous security posture assessment |
| **Cloud-Native Deployment** | Helm charts for EKS/GKE/AKS with auto-scaling based on EPS load and GPU nodes for model inference | Elastic scaling for enterprise deployments |
| **Threat Intelligence Feeds** | Integration with STIX/TAXII feeds (AlienVault OTX, MISP, VirusTotal) for real-time IOC enrichment | Faster detection of known threats and campaigns |
| **Multi-Tenant Support** | Namespace isolation for MSP/MSSP deployments serving multiple customers from a single cluster | SaaS-ready architecture |

---

<p align="center">
<strong>Chrontinal — Cognitive Log Investigation Framework — v8.0</strong><br>
<em>Agentic SIEM with Autonomous AI Investigation</em>
</p>
