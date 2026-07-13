#!/bin/bash
set -e
BROKER="redpanda01:9092"

echo "=== Deleting all topics ==="
for t in raw-logs security-events process-events network-events templated-logs triage-scores anomaly-alerts hunter-tasks hunter-results verifier-tasks verifier-results feedback-labels dead-letter pipeline-commands; do
  docker exec clif-redpanda01 rpk topic delete "$t" 2>/dev/null || true
  echo "  deleted $t"
done

sleep 2

echo "=== Creating ingestion topics (3 partitions, RF=3) ==="
for t in raw-logs security-events process-events network-events; do
  docker exec clif-redpanda01 rpk topic create "$t" -p 3 -r 3 \
    --topic-config retention.ms=604800000 \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760
  echo "  created $t"
done

echo "=== Creating triage pipeline topics (3 partitions, RF=3) ==="
for t in templated-logs triage-scores anomaly-alerts; do
  docker exec clif-redpanda01 rpk topic create "$t" -p 3 -r 3 \
    --topic-config retention.ms=604800000 \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760
  echo "  created $t"
done

echo "=== Creating agent topics (6 partitions, RF=3) ==="
for t in hunter-tasks hunter-results verifier-tasks verifier-results; do
  docker exec clif-redpanda01 rpk topic create "$t" -p 6 -r 3 \
    --topic-config retention.ms=604800000 \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760
  echo "  created $t"
done

echo "=== Creating operational topics (3 partitions, RF=3) ==="
for t in feedback-labels dead-letter pipeline-commands; do
  docker exec clif-redpanda01 rpk topic create "$t" -p 3 -r 3 \
    --topic-config retention.ms=2419200000 \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760
  echo "  created $t"
done

echo "=== Deleting consumer groups ==="
docker exec clif-redpanda01 rpk group delete clif-clickhouse-consumer 2>/dev/null || true
docker exec clif-redpanda01 rpk group delete clif-triage-consumer 2>/dev/null || true

echo "=== Final topic list ==="
docker exec clif-redpanda01 rpk topic list
echo "DONE"
