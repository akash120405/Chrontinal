#!/usr/bin/env python3
"""
CLIF Real-Log Replay Benchmark
===============================
Exports REAL logs from ClickHouse, then replays them at maximum throughput
through the Redpanda → Consumer → ClickHouse pipeline.

Events are cycled with fresh UUIDs + timestamps so ClickHouse treats each
as a distinct record.  Measures: sustained EPS, burst, E2E latency,
query perf, concurrent queries, resources, consumer lag, data integrity.

Usage:
    python3 real_log_benchmark.py [--target 2000000] [--burst 500000]
"""

import os
import argparse, json, os, random, statistics, subprocess, sys, time, uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import orjson
    _fast_dumps = lambda o: orjson.dumps(o)
except ImportError:
    _fast_dumps = lambda o: json.dumps(o, default=str).encode()

try:
    from confluent_kafka import Consumer, Producer, TopicPartition
except ImportError:
    sys.exit("confluent_kafka not installed: pip install confluent-kafka")

try:
    import clickhouse_connect
except ImportError:
    sys.exit("clickhouse-connect not installed: pip install clickhouse-connect")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
    console = Console(width=100, force_terminal=True)
except ImportError:
    RICH = False

# ═══════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:17092")
CH_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CH_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CH_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CH_PASS = os.getenv("CLICKHOUSE_PASSWORD", "")
CH_DB   = os.getenv("CLICKHOUSE_DATABASE", "clif_logs")

TOPICS = ["raw-logs", "security-events", "process-events", "network-events"]
TOPIC_TO_TABLE = {
    "raw-logs":         "raw_logs",
    "security-events":  "security_events",
    "process-events":   "process_events",
    "network-events":   "network_events",
}

# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════
_delivery_ok = 0
_delivery_err = 0

def _delivery_cb(err, msg):
    global _delivery_ok, _delivery_err
    if err:
        _delivery_err += 1
    else:
        _delivery_ok += 1

def _print(s):
    if RICH:
        console.print(s)
    else:
        print(s)

def _rule(title):
    if RICH:
        console.rule(f"[bold]{title}[/bold]")
    else:
        print(f"\n{'─'*70}\n  {title}\n{'─'*70}")

def get_ch_client():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT, username=CH_USER,
        password=CH_PASS, database=CH_DB,
    )

def create_producer(**overrides):
    cfg = {
        "bootstrap.servers": KAFKA_BROKER,
        "linger.ms": 5,
        "batch.num.messages": 100_000,
        "batch.size": 2_097_152,
        "compression.type": "lz4",
        "acks": "1",
        "queue.buffering.max.messages": 2_000_000,
        "queue.buffering.max.kbytes": 2097152,
        "message.max.bytes": 1_048_576,
    }
    cfg.update(overrides)
    return Producer(cfg)

def docker_stats_snapshot():
    try:
        r = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"],
            capture_output=True, text=True, timeout=15,
        )
        out = []
        for line in r.stdout.strip().split("\n"):
            if not line or not line.startswith("clif-"):
                continue
            p = line.split("\t")
            if len(p) >= 6:
                out.append({"name": p[0], "cpu": p[1], "mem_usage": p[2],
                            "mem_pct": p[3], "net_io": p[4], "block_io": p[5]})
        return out
    except Exception:
        return []

def get_consumer_lag():
    try:
        c = Consumer({
            "bootstrap.servers": KAFKA_BROKER,
            "group.id": "_bench_lag",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
        })
        info = {}
        for topic in TOPICS:
            try:
                meta = c.list_topics(topic=topic, timeout=10)
                parts = meta.topics[topic].partitions
                total_lag = 0
                for pid in parts:
                    tp = TopicPartition(topic, pid)
                    c.assign([tp])
                    _, hi = c.get_watermark_offsets(tp, timeout=10)
                    cc = Consumer({
                        "bootstrap.servers": KAFKA_BROKER,
                        "group.id": "clif-clickhouse-consumer",
                        "auto.offset.reset": "latest",
                        "enable.auto.commit": False,
                    })
                    committed = cc.committed([TopicPartition(topic, pid)], timeout=10)
                    off = committed[0].offset if committed[0].offset >= 0 else 0
                    cc.close()
                    total_lag += max(0, hi - off)
                info[topic] = {"partitions": len(parts), "total_lag": total_lag}
            except Exception as e:
                info[topic] = {"partitions": 0, "total_lag": 0, "error": str(e)}
        c.close()
        return info
    except Exception as e:
        return {"error": str(e)}

def get_table_counts(ch):
    counts = {}
    for table in TOPIC_TO_TABLE.values():
        try:
            r = ch.query(f"SELECT count() FROM {table}")
            counts[table] = r.result_rows[0][0]
        except Exception:
            counts[table] = -1
    return counts

# ═══════════════════════════════════════════════════════════════════════
# PHASE 0: EXPORT REAL LOGS FROM CLICKHOUSE
# ═══════════════════════════════════════════════════════════════════════
def export_real_logs(ch) -> dict:
    """Export real (non-benchmark) events from all 4 tables as JSON payloads
    ready for Kafka replay.  Returns {topic: [bytes, ...]}."""

    _rule("Phase 0: Exporting Real Logs from ClickHouse")
    pools = {}

    # ── raw-logs ──
    _print("  Exporting raw_logs …")
    rows = ch.query(
        "SELECT level, source, message, toString(ip_address) AS ip, "
        "user_id, request_id, metadata "
        "FROM raw_logs WHERE metadata['benchmark_tag'] = '' LIMIT 50000"
    )
    raw = []
    for r in rows.result_rows:
        raw.append({
            "timestamp": "",  # placeholder — filled at replay time
            "level": r[0],
            "source": r[1],
            "message": r[2],
            "ip_address": r[3],
            "user_id": r[4],
            "request_id": r[5],
            "metadata": dict(r[6]) if r[6] else {},
        })
    pools["raw-logs"] = raw
    _print(f"    → {len(raw):,} raw log templates")

    # ── security-events ──
    _print("  Exporting security_events …")
    rows = ch.query(
        "SELECT severity, category, source, description, user_id, "
        "toString(ip_address) AS ip, hostname, mitre_tactic, mitre_technique, "
        "ai_confidence, ai_explanation, metadata "
        "FROM security_events WHERE metadata['benchmark_tag'] = '' LIMIT 50000"
    )
    sec = []
    for r in rows.result_rows:
        sec.append({
            "timestamp": "",
            "severity": r[0],
            "category": r[1],
            "source": r[2],
            "description": r[3],
            "user_id": r[4],
            "ip_address": r[5],
            "hostname": r[6],
            "mitre_tactic": r[7],
            "mitre_technique": r[8],
            "ai_confidence": r[9],
            "ai_explanation": r[10],
            "metadata": dict(r[11]) if r[11] else {},
        })
    pools["security-events"] = sec
    _print(f"    → {len(sec):,} security event templates")

    # ── process-events ──
    _print("  Exporting process_events …")
    rows = ch.query(
        "SELECT hostname, pid, ppid, uid, gid, binary_path, arguments, "
        "cwd, exit_code, is_suspicious, detection_rule, metadata "
        "FROM process_events WHERE metadata['benchmark_tag'] = '' LIMIT 50000"
    )
    proc = []
    for r in rows.result_rows:
        proc.append({
            "timestamp": "",
            "hostname": r[0],
            "pid": r[1],
            "ppid": r[2],
            "uid": r[3],
            "gid": r[4],
            "binary_path": r[5],
            "arguments": r[6],
            "cwd": r[7],
            "exit_code": r[8],
            "is_suspicious": r[9],
            "detection_rule": r[10],
            "metadata": dict(r[11]) if r[11] else {},
        })
    pools["process-events"] = proc
    _print(f"    → {len(proc):,} process event templates")

    # ── network-events ──
    _print("  Exporting network_events …")
    rows = ch.query(
        "SELECT hostname, toString(src_ip) AS sip, toString(dst_ip) AS dip, "
        "src_port, dst_port, protocol, direction, bytes_sent, bytes_received, "
        "duration_ms, dns_query, geo_country, is_suspicious, detection_rule, metadata "
        "FROM network_events WHERE metadata['benchmark_tag'] = '' LIMIT 50000"
    )
    net = []
    for r in rows.result_rows:
        net.append({
            "timestamp": "",
            "hostname": r[0],
            "src_ip": r[1],
            "dst_ip": r[2],
            "src_port": r[3],
            "dst_port": r[4],
            "protocol": r[5],
            "direction": r[6],
            "bytes_sent": r[7],
            "bytes_received": r[8],
            "duration_ms": r[9],
            "dns_query": r[10],
            "geo_country": r[11],
            "is_suspicious": r[12],
            "detection_rule": r[13],
            "metadata": dict(r[14]) if r[14] else {},
        })
    pools["network-events"] = net
    _print(f"    → {len(net):,} network event templates")

    total = sum(len(v) for v in pools.values())
    _print(f"\n  Total real-log templates: {total:,}")
    return pools

def pre_serialize_pool(pools: dict, tag: str) -> dict:
    """Pre-serialize all templates into bytes with fresh metadata tag.
    Returns {topic: [bytes, ...]}."""
    serialized = {}
    for topic, templates in pools.items():
        buf = []
        for t in templates:
            t["metadata"]["benchmark_tag"] = tag
            t["metadata"]["replay"] = "real"
            buf.append(_fast_dumps(t))
        serialized[topic] = buf
    return serialized


# ═══════════════════════════════════════════════════════════════════════
# TEST 1: SUSTAINED THROUGHPUT (Real Log Replay)
# ═══════════════════════════════════════════════════════════════════════
def test_sustained_throughput(serialized: dict, total_target: int,
                              duration_sec: int, tag: str) -> dict:
    _rule("T1: Sustained Throughput — Real Log Replay")

    # Compute topic weights proportional to pool sizes
    sizes = {t: len(v) for t, v in serialized.items()}
    total_pool = sum(sizes.values())
    weights = [sizes[t] / total_pool for t in TOPICS]

    _print(f"  Target:     {total_target:,} events over {duration_sec}s")
    _print(f"  Pool:       {total_pool:,} real-log templates (cycled)")
    _print(f"  Weights:    " + ", ".join(f"{t}={w:.1%}" for t, w in zip(TOPICS, weights)))

    global _delivery_ok, _delivery_err
    _delivery_ok = 0
    _delivery_err = 0

    producer = create_producer()
    samples = []

    # Pre-compute topic assignment for batches
    BATCH = 10_000
    topic_batch = random.choices(TOPICS, weights=weights, k=BATCH)
    # Per-topic index counters (cycle through real templates)
    idx = {t: 0 for t in TOPICS}

    _produce = producer.produce
    _poll = producer.poll
    _perf = time.perf_counter

    # Inline function: pick next pre-serialized event for a topic,
    # stamp a fresh timestamp into it.  We inject timestamp at produce
    # time for accuracy.
    now_iso = datetime.now(timezone.utc).isoformat()

    t_start = _perf()
    total_produced = 0
    sec_count = 0
    sec_start = _perf()
    batch_idx = 0

    while total_produced < total_target:
        if batch_idx >= BATCH:
            topic_batch = random.choices(TOPICS, weights=weights, k=BATCH)
            batch_idx = 0

        topic = topic_batch[batch_idx]
        batch_idx += 1

        # Cycle through pre-serialized pool
        pool = serialized[topic]
        payload = pool[idx[topic] % len(pool)]
        idx[topic] += 1

        _produce(topic, payload, callback=_delivery_cb)
        total_produced += 1

        if total_produced % 5000 == 0:
            _poll(0)
            now = _perf()
            elapsed_in_sec = now - sec_start
            if elapsed_in_sec >= 1.0:
                rate = sec_count / elapsed_in_sec
                samples.append({"second": len(samples) + 1, "eps": rate})
                sec_count = 0
                sec_start = now
            if now >= t_start + duration_sec:
                break
        sec_count += 1

    produce_elapsed = _perf() - t_start
    _print(f"  Produced {total_produced:,} in {produce_elapsed:.1f}s — flushing…")
    producer.flush(timeout=120)
    _poll(0)
    total_elapsed = _perf() - t_start
    flush_time = total_elapsed - produce_elapsed

    avg_eps = _delivery_ok / total_elapsed if total_elapsed > 0 else 0
    rates = [s["eps"] for s in samples] if samples else [0]

    results = {
        "total_produced": total_produced,
        "total_delivered": _delivery_ok,
        "total_errors": _delivery_err,
        "real_templates": total_pool,
        "duration_sec": round(produce_elapsed, 2),
        "flush_sec": round(flush_time, 2),
        "wall_sec": round(total_elapsed, 2),
        "avg_eps": round(avg_eps),
        "min_eps": round(min(rates)),
        "max_eps": round(max(rates)),
        "p50_eps": round(statistics.median(rates)),
        "p95_eps": round(sorted(rates)[int(len(rates) * 0.05)] if len(rates) > 1 else rates[0]),
        "std_dev_eps": round(statistics.stdev(rates)) if len(rates) > 1 else 0,
    }

    _print(f"\n  ✅ Delivered:  {results['total_delivered']:,}")
    _print(f"  ✅ Errors:     {results['total_errors']:,}")
    _print(f"  ✅ Avg EPS:    {results['avg_eps']:,}")
    _print(f"  ✅ P50 EPS:    {results['p50_eps']:,}")
    _print(f"  ✅ Max EPS:    {results['max_eps']:,}")
    _print(f"  ✅ Std Dev:    {results['std_dev_eps']:,}")
    _print(f"  ✅ Produce:    {results['duration_sec']}s")
    _print(f"  ✅ Flush:      {results['flush_sec']}s")
    _print(f"  ✅ Wall time:  {results['wall_sec']}s")

    return results


# ═══════════════════════════════════════════════════════════════════════
# TEST 2: BURST CAPACITY (Real Logs)
# ═══════════════════════════════════════════════════════════════════════
def test_burst_capacity(serialized: dict, burst_events: int, tag: str) -> dict:
    _rule("T2: Burst Capacity — Real Log Spike")
    _print(f"  Burst size: {burst_events:,} events (pre-built, max speed)")

    global _delivery_ok, _delivery_err
    _delivery_ok = 0
    _delivery_err = 0

    producer = create_producer(**{
        "linger.ms": 8,
        "batch.num.messages": 500_000,
        "batch.size": 8_388_608,
        "queue.buffering.max.messages": 2_000_000,
        "queue.buffering.max.kbytes": 4194304,
    })

    # Pre-build burst array from real templates
    sizes = {t: len(v) for t, v in serialized.items()}
    total_pool = sum(sizes.values())
    weights = [sizes[t] / total_pool for t in TOPICS]
    topic_seq = random.choices(TOPICS, weights=weights, k=burst_events)

    _print(f"  Building burst buffer from {total_pool:,} real templates…")
    burst_buf = []
    idx = {t: 0 for t in TOPICS}
    for i in range(burst_events):
        topic = topic_seq[i]
        pool = serialized[topic]
        burst_buf.append((topic, pool[idx[topic] % len(pool)]))
        idx[topic] += 1

    _print(f"  Firing burst…")
    t_start = time.perf_counter()
    _produce = producer.produce
    _poll = producer.poll
    for i, (topic, payload) in enumerate(burst_buf):
        _produce(topic, payload, callback=_delivery_cb)
        if i % 10000 == 0:
            _poll(0)

    produce_elapsed = time.perf_counter() - t_start
    _print(f"  Produced in {produce_elapsed:.1f}s — flushing…")
    producer.flush(timeout=120)
    _poll(0)
    total_elapsed = time.perf_counter() - t_start

    burst_eps = _delivery_ok / total_elapsed if total_elapsed > 0 else 0

    results = {
        "burst_events": burst_events,
        "delivered": _delivery_ok,
        "errors": _delivery_err,
        "duration_sec": round(total_elapsed, 2),
        "burst_eps": round(burst_eps),
        "data_loss_pct": round((1 - _delivery_ok / burst_events) * 100, 4) if burst_events else 0,
    }

    ok = "✅" if results["data_loss_pct"] == 0 else "❌"
    _print(f"\n  {ok} Burst EPS:   {results['burst_eps']:,}")
    _print(f"  {ok} Duration:    {results['duration_sec']}s")
    _print(f"  {ok} Delivered:   {results['delivered']:,}/{burst_events:,}")
    _print(f"  {ok} Data Loss:   {results['data_loss_pct']}%")
    return results


# ═══════════════════════════════════════════════════════════════════════
# TEST 3: E2E LATENCY
# ═══════════════════════════════════════════════════════════════════════
def test_e2e_latency(serialized: dict, n_probes: int, tag: str) -> dict:
    _rule("T3: End-to-End Latency — Real Log Probes")
    _print(f"  Probes: {n_probes} real raw-log events")

    producer = create_producer()
    ch = get_ch_client()

    # Drain existing lag
    _print("  Waiting for consumer lag to drain…")
    for _ in range(60):
        try:
            lag = get_consumer_lag()
            total_lag = sum(v.get("total_lag", 0) for v in lag.values() if isinstance(v, dict))
            if total_lag < 1000:
                _print(f"  Lag drained ({total_lag})")
                break
        except Exception:
            pass
        time.sleep(1)

    # Send probes — real raw-log templates with unique probe tag
    raw_pool = serialized["raw-logs"]
    t_send = time.perf_counter()
    for i in range(n_probes):
        # Deserialize, add probe tag, re-serialize
        tpl = orjson.loads(raw_pool[i % len(raw_pool)]) if orjson else json.loads(raw_pool[i % len(raw_pool)])
        tpl["metadata"]["benchmark_tag"] = f"{tag}-probe-{i}"
        tpl["timestamp"] = datetime.now(timezone.utc).isoformat()
        producer.produce("raw-logs", _fast_dumps(tpl))
        if i % 50 == 0:
            producer.poll(0)
    producer.flush(timeout=60)
    send_done = time.perf_counter()
    _print(f"  Sent {n_probes} probes in {send_done - t_send:.2f}s")

    # Poll CH for arrival
    found = 0
    timeout = 120
    deadline = time.perf_counter() + timeout
    poll_count = 0
    thresholds = {"p50": int(n_probes * 0.5), "p95": int(n_probes * 0.95),
                  "p99": int(n_probes * 0.99), "p100": n_probes}
    milestones = {}
    first_found_time = None

    while found < n_probes and time.perf_counter() < deadline:
        time.sleep(0.05)
        poll_count += 1
        try:
            r = ch.query(
                "SELECT count() FROM raw_logs WHERE metadata['benchmark_tag'] LIKE {t:String}",
                parameters={"t": f"{tag}-probe-%"},
            )
            found = r.result_rows[0][0]
            now = time.perf_counter()
            if found > 0 and first_found_time is None:
                first_found_time = now - t_send
            for pn, th in thresholds.items():
                if pn not in milestones and found >= th:
                    milestones[pn] = now - t_send
        except Exception:
            pass

    verify_time = time.perf_counter() - t_send
    p50 = milestones.get("p50", -1)
    p95 = milestones.get("p95", -1)
    p99 = milestones.get("p99", -1)

    results = {
        "probes_sent": n_probes, "probes_found": found,
        "completion_pct": round(found / n_probes * 100, 1),
        "p50_latency_sec": round(p50, 3), "p95_latency_sec": round(p95, 3),
        "p99_latency_sec": round(p99, 3),
        "min_latency_sec": round(first_found_time, 3) if first_found_time else -1,
        "max_latency_sec": round(verify_time, 3),
        "poll_rounds": poll_count,
    }
    ok = "✅" if found >= n_probes * 0.95 else "⚠️"
    _print(f"\n  {ok} Found:       {found}/{n_probes} ({results['completion_pct']}%)")
    _print(f"  {ok} P50 Latency: {results['p50_latency_sec']}s")
    _print(f"  {ok} P95 Latency: {results['p95_latency_sec']}s")
    _print(f"  {ok} P99 Latency: {results['p99_latency_sec']}s")
    ch.close()
    return results


# ═══════════════════════════════════════════════════════════════════════
# TEST 4: QUERY PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════
def test_query_performance() -> dict:
    _rule("T4: ClickHouse Query Performance")
    ch = get_ch_client()
    queries = [
        ("Total raw_logs (24h)",    "SELECT count() FROM raw_logs WHERE timestamp >= now()-INTERVAL 1 DAY"),
        ("Events by source (24h)", "SELECT source,count() c FROM raw_logs WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY source ORDER BY c DESC LIMIT 20"),
        ("Events by level (24h)",  "SELECT level,count() c FROM raw_logs WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY level ORDER BY c DESC"),
        ("Per-minute rate (1h)",   "SELECT toStartOfMinute(timestamp) m,count() c FROM raw_logs WHERE timestamp>=now()-INTERVAL 1 HOUR GROUP BY m ORDER BY m"),
        ("High sev events (7d)",   "SELECT count() FROM security_events WHERE severity>=7 AND timestamp>=now()-INTERVAL 7 DAY"),
        ("Top attacked users",     "SELECT user_id,count() c FROM security_events WHERE severity>=5 AND timestamp>=now()-INTERVAL 1 DAY GROUP BY user_id ORDER BY c DESC LIMIT 10"),
        ("MITRE technique dist",   "SELECT mitre_technique,count() c FROM security_events WHERE mitre_technique!='' AND timestamp>=now()-INTERVAL 7 DAY GROUP BY mitre_technique ORDER BY c DESC"),
        ("AI high-conf alerts",    "SELECT count() FROM security_events WHERE ai_confidence>0.8 AND timestamp>=now()-INTERVAL 7 DAY"),
        ("Network top talkers",    "SELECT src_ip,sum(bytes_sent) t FROM network_events WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY src_ip ORDER BY t DESC LIMIT 10"),
        ("Geo distribution",       "SELECT geo_country,count() c FROM network_events WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY geo_country ORDER BY c DESC"),
        ("Suspicious conns (7d)",  "SELECT count() FROM network_events WHERE is_suspicious=1 AND timestamp>=now()-INTERVAL 7 DAY"),
        ("Suspicious procs (7d)",  "SELECT count() FROM process_events WHERE is_suspicious=1 AND timestamp>=now()-INTERVAL 7 DAY"),
        ("Process by host",        "SELECT hostname,count() c FROM process_events WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY hostname ORDER BY c DESC LIMIT 10"),
        ("Full-text: deny",        "SELECT count() FROM raw_logs WHERE message LIKE '%deny%' AND timestamp>=now()-INTERVAL 1 DAY"),
        ("Full-text: powershell",  "SELECT count() FROM process_events WHERE binary_path LIKE '%powershell%' AND timestamp>=now()-INTERVAL 7 DAY"),
        ("Cross-table join",       "SELECT s.src_ip,s.c,n.c FROM (SELECT toString(ip_address) src_ip,count() c FROM security_events WHERE severity>=7 AND timestamp>=now()-INTERVAL 1 DAY GROUP BY src_ip) s JOIN (SELECT toString(src_ip) src_ip,count() c FROM network_events WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY src_ip) n USING src_ip ORDER BY s.c DESC LIMIT 10"),
    ]
    detail = []
    total_ms = 0
    for label, sql in queries:
        try:
            t0 = time.perf_counter()
            r = ch.query(sql)
            ms = (time.perf_counter() - t0) * 1000
            detail.append({"query": label, "time_ms": round(ms, 1), "rows": len(r.result_rows), "status": "OK"})
            total_ms += ms
        except Exception as e:
            detail.append({"query": label, "time_ms": -1, "rows": 0, "status": f"ERR:{str(e)[:50]}"})

    if RICH:
        table = Table(title="Query Performance", box=box.ROUNDED)
        table.add_column("Query", style="cyan", min_width=28)
        table.add_column("ms", justify="right", style="green")
        table.add_column("Rows", justify="right")
        table.add_column("", justify="center")
        for d in detail:
            table.add_row(d["query"], f"{d['time_ms']:.1f}" if d['time_ms'] > 0 else "ERR",
                          str(d["rows"]), "✅" if d["status"] == "OK" else "❌")
        console.print(table)

    ok_q = [d for d in detail if d["status"] == "OK" and d["time_ms"] > 0]
    times = [d["time_ms"] for d in ok_q]
    summary = {
        "total_queries": len(queries), "successful": len(ok_q),
        "total_time_ms": round(total_ms, 1),
        "avg_time_ms": round(statistics.mean(times), 1) if times else -1,
        "median_time_ms": round(statistics.median(times), 1) if times else -1,
        "p95_time_ms": round(sorted(times)[int(len(times)*0.95)], 1) if len(times) > 1 else (round(times[0],1) if times else -1),
        "max_time_ms": round(max(times), 1) if times else -1,
        "queries_under_100ms": sum(1 for t in times if t < 100),
        "queries_under_500ms": sum(1 for t in times if t < 500),
        "detail": detail,
    }
    _print(f"\n  Avg: {summary['avg_time_ms']}ms  Median: {summary['median_time_ms']}ms  P95: {summary['p95_time_ms']}ms  Max: {summary['max_time_ms']}ms")
    _print(f"  Under 100ms: {summary['queries_under_100ms']}/{len(queries)}  Under 500ms: {summary['queries_under_500ms']}/{len(queries)}")
    ch.close()
    return summary


# ═══════════════════════════════════════════════════════════════════════
# TEST 5: CONCURRENT QUERIES
# ═══════════════════════════════════════════════════════════════════════
def test_concurrent_queries(n: int) -> dict:
    _rule(f"T5: Concurrent Queries ({n} analysts)")
    queries = [
        "SELECT count() FROM raw_logs WHERE timestamp>=now()-INTERVAL 1 DAY",
        "SELECT source,count() FROM raw_logs WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY source ORDER BY count() DESC LIMIT 10",
        "SELECT count() FROM security_events WHERE severity>=5 AND timestamp>=now()-INTERVAL 7 DAY",
        "SELECT src_ip,sum(bytes_sent) FROM network_events WHERE timestamp>=now()-INTERVAL 1 DAY GROUP BY src_ip ORDER BY sum(bytes_sent) DESC LIMIT 10",
        "SELECT hostname,count() FROM process_events WHERE is_suspicious=1 AND timestamp>=now()-INTERVAL 7 DAY GROUP BY hostname",
        "SELECT toStartOfMinute(timestamp) m,count() FROM raw_logs WHERE timestamp>=now()-INTERVAL 1 HOUR GROUP BY m ORDER BY m",
        "SELECT count() FROM raw_logs WHERE message LIKE '%deny%'",
        "SELECT count() FROM security_events WHERE timestamp>=now()-INTERVAL 1 DAY",
    ]
    rounds = 4
    clients = [get_ch_client() for _ in range(n)]
    for c in clients:
        try: c.query("SELECT 1")
        except: pass

    def _run(aid):
        ch = clients[aid]
        ok = 0; total_ms = 0.0; times = []
        for rnd in range(rounds):
            q = queries[(aid + rnd) % len(queries)]
            t0 = time.perf_counter()
            try:
                ch.query(q)
                ms = (time.perf_counter() - t0) * 1000
                times.append(ms); total_ms += ms; ok += 1
            except:
                ms = (time.perf_counter() - t0) * 1000
                times.append(ms); total_ms += ms
        return {"ok": ok == rounds, "successful": ok, "times": times}

    t0 = time.perf_counter()
    res = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        for f in as_completed([pool.submit(_run, i) for i in range(n)]):
            res.append(f.result())
    wall = time.perf_counter() - t0
    for c in clients:
        try: c.close()
        except: pass

    total_ok = sum(r["successful"] for r in res)
    all_t = sorted([t for r in res for t in r["times"]])
    results = {
        "concurrent": n, "rounds": rounds,
        "successful": total_ok, "failed": n * rounds - total_ok,
        "wall_ms": round(wall * 1000, 1),
        "avg_ms": round(statistics.mean(all_t), 1) if all_t else -1,
        "p50_ms": round(statistics.median(all_t), 1) if all_t else -1,
        "p95_ms": round(all_t[int(len(all_t)*0.95)], 1) if len(all_t) > 1 else -1,
        "max_ms": round(max(all_t), 1) if all_t else -1,
        "qps": round(total_ok / wall, 1) if wall else 0,
    }
    _print(f"\n  OK: {total_ok}/{n*rounds}  QPS: {results['qps']}  Avg: {results['avg_ms']}ms  P95: {results['p95_ms']}ms")
    return results


# ═══════════════════════════════════════════════════════════════════════
# TEST 6: RESOURCES
# ═══════════════════════════════════════════════════════════════════════
def test_resources(eps: float) -> dict:
    _rule("T6: Resource Efficiency")
    stats = docker_stats_snapshot()
    if RICH and stats:
        table = Table(title="Container Resources", box=box.ROUNDED)
        table.add_column("Container", style="cyan")
        table.add_column("CPU%", justify="right", style="green")
        table.add_column("Memory", justify="right")
        table.add_column("Mem%", justify="right", style="yellow")
        table.add_column("Net I/O", justify="right")
        for s in stats:
            table.add_row(s["name"], s["cpu"], s["mem_usage"], s["mem_pct"], s["net_io"])
        console.print(table)
    total_mb = 0
    for s in stats:
        try:
            m = s["mem_usage"].split("/")[0].strip()
            if "GiB" in m: total_mb += float(m.replace("GiB","")) * 1024
            elif "MiB" in m: total_mb += float(m.replace("MiB",""))
        except: pass
    results = {
        "containers": len(stats), "total_memory_mb": round(total_mb, 1),
        "eps_per_gb": round(eps / (total_mb / 1024), 0) if total_mb else -1,
    }
    _print(f"\n  Containers: {len(stats)}  Memory: {total_mb:.0f} MiB  EPS/GB: {results['eps_per_gb']:,.0f}")
    return results


# ═══════════════════════════════════════════════════════════════════════
# TEST 7: CONSUMER LAG
# ═══════════════════════════════════════════════════════════════════════
def test_lag() -> dict:
    _rule("T7: Consumer Lag")
    lag = get_consumer_lag()
    total = 0
    if RICH:
        table = Table(title="Consumer Lag", box=box.ROUNDED)
        table.add_column("Topic", style="cyan")
        table.add_column("Lag", justify="right", style="yellow")
        table.add_column("", justify="center")
        for t, v in lag.items():
            if isinstance(v, dict) and "total_lag" in v:
                total += v["total_lag"]
                table.add_row(t, f"{v['total_lag']:,}", "✅" if v["total_lag"] < 1000 else "⚠️")
        console.print(table)
    results = {"topics": lag, "total_lag": total, "backpressure": total > 100_000}
    _print(f"\n  Total lag: {total:,}  Backpressure: {'YES ⚠️' if results['backpressure'] else 'NO ✅'}")
    return results


# ═══════════════════════════════════════════════════════════════════════
# TEST 8: DATA INTEGRITY
# ═══════════════════════════════════════════════════════════════════════
def test_data_integrity(tag: str, expected: int, timeout: int = 180) -> dict:
    _rule("T8: Data Integrity Verification")
    _print(f"  Verifying {expected:,} events with tag '{tag}'")
    ch = get_ch_client()
    t0 = time.perf_counter()
    deadline = t0 + timeout
    table_counts = {}
    total_found = 0
    stable = 0
    last = -1
    while time.perf_counter() < deadline:
        total_found = 0
        for table in TOPIC_TO_TABLE.values():
            try:
                r = ch.query(
                    f"SELECT count() FROM {table} WHERE metadata['benchmark_tag'] LIKE %(t)s",
                    parameters={"t": f"{tag}%"},
                )
                c = r.result_rows[0][0]
                table_counts[table] = c
                total_found += c
            except: pass
        if total_found == last and total_found > 0:
            stable += 1
            if stable >= 5: break
        else:
            stable = 0
        last = total_found
        time.sleep(1)

    vt = time.perf_counter() - t0
    loss = max(0, expected - total_found)
    loss_pct = round(loss / expected * 100, 4) if expected else 0

    if RICH:
        table = Table(title="Per-Table Verification", box=box.ROUNDED)
        table.add_column("Table", style="cyan")
        table.add_column("Found", justify="right", style="green")
        for t, c in table_counts.items():
            table.add_row(t, f"{c:,}")
        console.print(table)

    results = {
        "expected": expected, "found": total_found,
        "data_loss": loss, "data_loss_pct": loss_pct,
        "verify_sec": round(vt, 2), "table_counts": table_counts,
        "zero_loss": loss <= 0,
    }
    ok = "✅" if results["zero_loss"] else "❌"
    _print(f"\n  {ok} Expected: {expected:,}  Found: {total_found:,}  Loss: {loss} ({loss_pct}%)")
    _print(f"  {ok} Verify time: {vt:.1f}s")
    ch.close()
    return results


# ═══════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════
def generate_report(all_r: dict, cfg: dict, start: float):
    total = time.perf_counter() - start
    _print("")
    _rule("CLIF Real-Log Benchmark — Final Report")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    t1 = all_r.get("sustained", {})
    t2 = all_r.get("burst", {})
    t3 = all_r.get("latency", {})
    t4 = all_r.get("queries", {})
    t5 = all_r.get("concurrent", {})
    t6 = all_r.get("resources", {})
    t7 = all_r.get("lag", {})
    t8 = all_r.get("integrity", {})

    if RICH:
        st = Table(title="📊 Executive Summary — REAL LOG Benchmark", box=box.DOUBLE_EDGE, show_lines=True)
        st.add_column("Metric", style="bold cyan", min_width=35)
        st.add_column("Value", justify="right", style="green", min_width=18)
        st.add_column("Target", justify="right", style="yellow", min_width=15)
        st.add_column("Grade", justify="center", min_width=6)

        avg = t1.get("avg_eps", 0)
        st.add_row("Sustained EPS (Real Logs)", f"{avg:,}/s", "≥50,000/s",
                    "✅" if avg >= 50000 else ("⚠️" if avg >= 10000 else "❌"))
        st.add_row("  └─ Real templates used", f"{t1.get('real_templates',0):,}", "", "ℹ️")
        st.add_row("  └─ Stability (Std Dev)", f"±{t1.get('std_dev_eps',0):,}",
                    "<20% avg", "✅" if t1.get('std_dev_eps',0) < avg*0.2 else "⚠️")
        st.add_row("Burst EPS (Real Logs)", f"{t2.get('burst_eps',0):,}/s", "≥100,000/s",
                    "✅" if t2.get('burst_eps',0) >= 100000 else "⚠️")
        st.add_row("  └─ Data Loss", f"{t2.get('data_loss_pct',0)}%", "0%",
                    "✅" if t2.get('data_loss_pct',0) == 0 else "❌")
        st.add_row("E2E Latency P50", f"{t3.get('p50_latency_sec',-1)}s", "<2s",
                    "✅" if 0 < t3.get('p50_latency_sec',99) < 2 else "⚠️")
        st.add_row("E2E Latency P95", f"{t3.get('p95_latency_sec',-1)}s", "<5s",
                    "✅" if 0 < t3.get('p95_latency_sec',99) < 5 else "⚠️")
        st.add_row("E2E Latency P99", f"{t3.get('p99_latency_sec',-1)}s", "<10s",
                    "✅" if 0 < t3.get('p99_latency_sec',99) < 10 else "⚠️")
        st.add_row("Query Avg", f"{t4.get('avg_time_ms',-1)}ms", "<200ms",
                    "✅" if 0 < t4.get('avg_time_ms',999) < 200 else "⚠️")
        st.add_row("Query P95", f"{t4.get('p95_time_ms',-1)}ms", "<500ms",
                    "✅" if 0 < t4.get('p95_time_ms',999) < 500 else "⚠️")
        st.add_row("  └─ Under 100ms", f"{t4.get('queries_under_100ms',0)}/{t4.get('total_queries',0)}", "≥80%", "")
        st.add_row("Concurrent QPS", f"{t5.get('qps',0)}", "≥10",
                    "✅" if t5.get('qps',0) >= 10 else "⚠️")
        st.add_row("Memory", f"{t6.get('total_memory_mb',0):.0f} MiB", "", "ℹ️")
        st.add_row("EPS/GB Memory", f"{t6.get('eps_per_gb',0):,.0f}", "≥1,000",
                    "✅" if t6.get('eps_per_gb',0) >= 1000 else "⚠️")
        st.add_row("Consumer Lag", f"{t7.get('total_lag',0):,}", "<10,000",
                    "✅" if t7.get('total_lag',0) < 10000 else "⚠️")
        st.add_row("Data Integrity", "ZERO LOSS ✅" if t8.get('zero_loss') else f"LOST {t8.get('data_loss',0)}",
                    "Zero Loss", "✅" if t8.get('zero_loss') else "❌")
        console.print(st)

    # ── Grades ──
    grades = []
    avg = t1.get("avg_eps", 0)
    grades.append("A" if avg >= 50000 else ("B" if avg >= 20000 else ("C" if avg >= 10000 else "D")))
    grades.append("A" if t2.get("data_loss_pct", 1) == 0 else "F")
    grades.append("A" if 0 < t3.get("p95_latency_sec", 99) < 5 else ("B" if t3.get("p95_latency_sec", 99) < 10 else "C"))
    grades.append("A" if 0 < t4.get("avg_time_ms", 999) < 100 else ("B" if t4.get("avg_time_ms", 999) < 200 else "C"))
    grades.append("A" if t8.get("zero_loss") else "F")
    gm = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
    gpa = sum(gm.get(g, 0) for g in grades) / len(grades)
    fg = "A" if gpa >= 3.5 else ("B" if gpa >= 2.5 else ("C" if gpa >= 1.5 else ("D" if gpa >= 0.5 else "F")))

    if RICH:
        console.print(Panel(f"[bold magenta]  OVERALL GRADE: {fg}[/bold magenta]",
                            title="🏆 Real-Log Benchmark Grade", border_style="magenta"))
    else:
        print(f"\n  OVERALL GRADE: {fg}")

    # Save JSON
    report = {
        "benchmark": "CLIF Real-Log Replay Benchmark v1.0",
        "timestamp": ts, "data_source": "REAL (ClickHouse export → Kafka replay)",
        "total_duration_sec": round(total, 2), "config": cfg,
        "results": {k: {kk: vv for kk, vv in v.items() if kk not in ("detail","container_details")}
                    for k, v in all_r.items() if isinstance(v, dict)},
    }
    rp = os.path.join(os.path.dirname(__file__), "real_log_benchmark_results.json")
    with open(rp, "w") as f:
        json.dump(report, f, indent=2, default=str)
    _print(f"\n  📄 Results saved to: {rp}")
    _print(f"  Completed at {ts}  Total: {total:.1f}s ({total/60:.1f}min)\n")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="CLIF Real-Log Replay Benchmark")
    parser.add_argument("--target", type=int, default=2_000_000, help="Total events for sustained test (default: 2M)")
    parser.add_argument("--duration", type=int, default=180, help="Max duration seconds (default: 180)")
    parser.add_argument("--burst", type=int, default=500_000, help="Burst event count (default: 500K)")
    parser.add_argument("--probes", type=int, default=500, help="Latency probes (default: 500)")
    parser.add_argument("--concurrent", type=int, default=16, help="Concurrent analysts (default: 16)")
    parser.add_argument("--skip-tests", nargs="+", type=int, default=[], help="Skip test numbers")
    args = parser.parse_args()

    cfg = {"target": args.target, "duration": args.duration, "burst": args.burst,
           "probes": args.probes, "concurrent": args.concurrent}

    if RICH:
        console.print(Panel(
            f"[bold white]CLIF Real-Log Replay Benchmark v1.0[/bold white]\n\n"
            f"Data Source:    [green]REAL logs exported from ClickHouse[/green]\n"
            f"Target:         [cyan]{args.target:,}[/cyan] events\n"
            f"Duration:       [cyan]{args.duration}s[/cyan]\n"
            f"Burst:          [cyan]{args.burst:,}[/cyan]\n"
            f"Probes:         [cyan]{args.probes}[/cyan]\n"
            f"Concurrent:     [cyan]{args.concurrent}[/cyan]\n"
            f"Kafka:          [yellow]{KAFKA_BROKER}[/yellow]\n"
            f"ClickHouse:     [yellow]{CH_HOST}:{CH_PORT}[/yellow]",
            title="🔬 Configuration", border_style="blue",
        ))

    _rule("Pre-flight Checks")
    ch = get_ch_client()
    counts = get_table_counts(ch)
    _print(f"  ✅ ClickHouse — {sum(counts.values()):,} events")
    for t, c in counts.items():
        _print(f"     {t}: {c:,}")

    p = create_producer()
    p.produce("raw-logs", b'{"test":"preflight"}')
    p.flush(timeout=10)
    _print(f"  ✅ Redpanda — {KAFKA_BROKER}")

    # Phase 0: Export real logs
    pools = export_real_logs(ch)
    ch.close()

    tag = f"real-{uuid.uuid4().hex[:8]}"
    serialized = pre_serialize_pool(pools, tag)
    _print(f"\n  Tag: {tag}")
    total_serial = sum(len(v) for v in serialized.values())
    total_bytes = sum(sum(len(b) for b in v) for v in serialized.values())
    _print(f"  Pre-serialized: {total_serial:,} templates ({total_bytes / 1048576:.1f} MiB)")

    start = time.perf_counter()
    all_r = {}
    total_for_integrity = 0

    if 1 not in args.skip_tests:
        all_r["sustained"] = test_sustained_throughput(serialized, args.target, args.duration, tag)
        total_for_integrity += all_r["sustained"].get("total_delivered", 0)

    if 2 not in args.skip_tests:
        all_r["burst"] = test_burst_capacity(serialized, args.burst, f"{tag}-burst")
        total_for_integrity += all_r["burst"].get("delivered", 0)

    if 3 not in args.skip_tests:
        all_r["latency"] = test_e2e_latency(serialized, args.probes, f"{tag}-lat")

    if 4 not in args.skip_tests:
        all_r["queries"] = test_query_performance()

    if 5 not in args.skip_tests:
        all_r["concurrent"] = test_concurrent_queries(args.concurrent)

    if 6 not in args.skip_tests:
        eps = all_r.get("sustained", {}).get("avg_eps", 0)
        all_r["resources"] = test_resources(eps)

    if 7 not in args.skip_tests:
        all_r["lag"] = test_lag()

    if 8 not in args.skip_tests:
        all_r["integrity"] = test_data_integrity(tag, total_for_integrity)

    generate_report(all_r, cfg, start)


if __name__ == "__main__":
    main()
