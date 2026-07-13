import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";

/** Agent role descriptions */
const AGENT_ROLES: Record<string, string> = {
  triage: "Risk scoring & classification",
  hunter: "Threat hunting & correlation",
  verifier: "Verdict verification",
  xai: "Explainability (SHAP)",
};

/**
 * Probe all agents via the XAI service's /cluster/health endpoint.
 * This works even when the GCP firewall blocks direct access to agent ports,
 * because the XAI service checks them internally on the Docker network.
 */
async function probeAgentsViaCluster(): Promise<
  Array<{ name: string; role: string; status: string; cases_handled: number; avg_response_time: number; error_count: number }>
> {
  try {
    const res = await fetch(`${AI_SERVICE_URL}/cluster/health`, {
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    return (data.agents || []).map((a: { name: string; status: string; health?: Record<string, unknown> }) => ({
      name: a.name,
      role: AGENT_ROLES[a.name] || "Unknown",
      status: a.status,
      cases_handled: Number(a.health?.batches_processed ?? a.health?.events_processed ?? 0),
      avg_response_time: Number(a.health?.avg_batch_time_ms ?? 0),
      error_count: 0,
    }));
  } catch {
    // Fallback: return all agents as unreachable
    return Object.entries(AGENT_ROLES).map(([name, role]) => ({
      name,
      role,
      status: "unreachable",
      cases_handled: 0,
      avg_response_time: 0,
      error_count: 0,
    }));
  }
}

/**
 * GET /api/ai/agents — Get status of all AI agents + recent investigations
 */
export async function GET() {
  try {
    const data = await cached("ai:agents", 120_000, async () => {
      const agents = await probeAgentsViaCluster();

      // Recent investigations from ClickHouse
      let investigations: unknown[] = [];
      try {
        const invRes = await queryClickHouse<{
          investigation_id: string; finding_type: string; severity: string;
          status: string; confidence: string; started_at: string;
        }>(
          `SELECT toString(investigation_id) AS investigation_id, finding_type, severity,
                  status, toString(confidence) AS confidence, started_at
           FROM clif_logs.hunter_investigations
           ORDER BY started_at DESC LIMIT 20`
        );
        investigations = invRes.data.map((r) => ({
          id: r.investigation_id,
          event_type: r.finding_type,
          verdict: r.status,
          confidence: Number(r.confidence),
          severity: r.severity,
          timestamp: r.started_at,
          duration: 0,
        }));
      } catch { /* no investigations table or empty */ }

      // Pipeline stats from ClickHouse
      let pipeline = { totalProcessed: 0, avgLatencyMs: 0, hmacEnabled: true };
      try {
        const countRes = await queryClickHouse<{ cnt: string }>(
          `SELECT toString(sum(rows)) AS cnt FROM system.parts WHERE database = 'clif_logs' AND table = 'triage_scores' AND active = 1`
        );
        pipeline.totalProcessed = Number(countRes.data[0]?.cnt ?? 0);
        const triageAgent = agents.find((a) => a.name === "triage");
        pipeline.avgLatencyMs = triageAgent?.avg_response_time ?? 0;
      } catch { /* fallback to zeros */ }

      // Performance trends — hourly counts for each agent (last 24h)
      let performanceTrends: Array<{ hour: string; triage: number; hunter: number; verifier: number }> = [];
      try {
        const [triageTrend, hunterTrend, verifierTrend] = await Promise.allSettled([
          queryClickHouse<{ hour: string; cnt: string }>(
            `SELECT formatDateTime(toStartOfHour(timestamp), '%H:%M') AS hour, count() AS cnt
             FROM clif_logs.triage_scores
             WHERE timestamp >= now() - INTERVAL 24 HOUR
             GROUP BY toStartOfHour(timestamp)
             ORDER BY toStartOfHour(timestamp) ASC
             SETTINGS max_threads = 1`
          ),
          queryClickHouse<{ hour: string; cnt: string }>(
            `SELECT formatDateTime(toStartOfHour(started_at), '%H:%M') AS hour, count() AS cnt
             FROM clif_logs.hunter_investigations
             WHERE started_at >= now() - INTERVAL 24 HOUR
             GROUP BY toStartOfHour(started_at)
             ORDER BY toStartOfHour(started_at) ASC`
          ),
          queryClickHouse<{ hour: string; cnt: string }>(
            `SELECT formatDateTime(toStartOfHour(started_at), '%H:%M') AS hour, count() AS cnt
             FROM clif_logs.verifier_results
             WHERE started_at >= now() - INTERVAL 24 HOUR
             GROUP BY toStartOfHour(started_at)
             ORDER BY toStartOfHour(started_at) ASC`
          ),
        ]);
        // Merge the three separate results into combined hourly entries
        const hourMap = new Map<string, { triage: number; hunter: number; verifier: number }>();
        if (triageTrend.status === "fulfilled") {
          for (const r of triageTrend.value.data) hourMap.set(r.hour, { triage: Number(r.cnt), hunter: 0, verifier: 0 });
        }
        if (hunterTrend.status === "fulfilled") {
          for (const r of hunterTrend.value.data) {
            const entry = hourMap.get(r.hour) || { triage: 0, hunter: 0, verifier: 0 };
            entry.hunter = Number(r.cnt);
            hourMap.set(r.hour, entry);
          }
        }
        if (verifierTrend.status === "fulfilled") {
          for (const r of verifierTrend.value.data) {
            const entry = hourMap.get(r.hour) || { triage: 0, hunter: 0, verifier: 0 };
            entry.verifier = Number(r.cnt);
            hourMap.set(r.hour, entry);
          }
        }
        performanceTrends = Array.from(hourMap.entries())
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([hour, counts]) => ({ hour, ...counts }));
      } catch { /* no data */ }

      // Agent confidence — real average confidence scores
      let agentConfidence = { triage: 0, hunter: 0, verifier: 0 };
      try {
        const [triageConf, hunterConf, verifierConf] = await Promise.allSettled([
          queryClickHouse<{ val: string }>(
            `SELECT toString(avg(agreement)) AS val FROM clif_logs.triage_scores
             WHERE agreement > 0 AND timestamp >= now() - INTERVAL 1 DAY
             SETTINGS max_threads = 1`
          ),
          queryClickHouse<{ val: string }>(
            `SELECT toString(avg(confidence)) AS val FROM clif_logs.hunter_investigations
             WHERE confidence > 0 AND started_at >= now() - INTERVAL 7 DAY`
          ),
          queryClickHouse<{ val: string }>(
            `SELECT toString(avg(confidence)) AS val FROM clif_logs.verifier_results
             WHERE confidence > 0 AND started_at >= now() - INTERVAL 7 DAY`
          ),
        ]);
        if (triageConf.status === "fulfilled") agentConfidence.triage = Number(triageConf.value.data[0]?.val) || 0;
        if (hunterConf.status === "fulfilled") agentConfidence.hunter = Number(hunterConf.value.data[0]?.val) || 0;
        if (verifierConf.status === "fulfilled") agentConfidence.verifier = Number(verifierConf.value.data[0]?.val) || 0;
      } catch { /* fallback zeros */ }
      // If agreement is 0 (not populated), use combined_score distribution as a proxy
      if (agentConfidence.triage === 0) {
        try {
          const scoreRes = await queryClickHouse<{ avg_score: string }>(
            `SELECT toString(1.0 - avg(combined_score)) AS avg_score
             FROM (SELECT combined_score FROM clif_logs.triage_scores
                   WHERE timestamp >= now() - INTERVAL 1 DAY
                   ORDER BY timestamp DESC LIMIT 100000)`
          );
          agentConfidence.triage = Number(scoreRes.data[0]?.avg_score) || 0;
        } catch { /* keep 0 */ }
      }

      // XAI Feature Importance from XAI service
      let xaiFeatures: Array<{ feature: string; importance: number }> = [];
      try {
        const xaiRes = await fetch(`${AI_SERVICE_URL}/model/features`, {
          cache: "no-store",
          signal: AbortSignal.timeout(5000),
        });
        if (xaiRes.ok) {
          const xaiData = await xaiRes.json();
          xaiFeatures = (xaiData.features || [])
            .slice(0, 8)
            .map((f: { display_name?: string; feature?: string; importance?: number }) => ({
              feature: f.display_name || f.feature || "unknown",
              importance: Number(f.importance) || 0,
            }));
        }
      } catch { /* no XAI data */ }

      // Model metrics — precision/recall from verifier data
      let modelMetrics = { recall: 0, precision: 0 };
      try {
        const [escalatedRes, tpRes, fpRes, verifiedRes] = await Promise.allSettled([
          queryClickHouse<{ cnt: string }>(
            `SELECT toString(count()) AS cnt FROM clif_logs.triage_scores
             WHERE action = 'escalate' AND timestamp >= now() - INTERVAL 7 DAY
             SETTINGS max_threads = 1`
          ),
          queryClickHouse<{ cnt: string }>(
            `SELECT toString(countIf(verdict = 'true_positive')) AS cnt FROM clif_logs.verifier_results
             WHERE started_at >= now() - INTERVAL 7 DAY`
          ),
          queryClickHouse<{ cnt: string }>(
            `SELECT toString(countIf(verdict = 'false_positive')) AS cnt FROM clif_logs.verifier_results
             WHERE started_at >= now() - INTERVAL 7 DAY`
          ),
          queryClickHouse<{ cnt: string }>(
            `SELECT toString(count()) AS cnt FROM clif_logs.verifier_results
             WHERE started_at >= now() - INTERVAL 7 DAY`
          ),
        ]);
        const escalated = escalatedRes.status === "fulfilled" ? Number(escalatedRes.value.data[0]?.cnt ?? 0) : 0;
        const tpVal = tpRes.status === "fulfilled" ? Number(tpRes.value.data[0]?.cnt ?? 0) : 0;
        const verified = verifiedRes.status === "fulfilled" ? Number(verifiedRes.value.data[0]?.cnt ?? 0) : 0;
        modelMetrics.precision = verified > 0 ? tpVal / verified : 0;
        modelMetrics.recall = escalated > 0 ? tpVal / escalated : 0;
      } catch { /* zeros */ }

      return {
        agents,
        total_agents: agents.length,
        active_agents: agents.filter((a) => a.status === "active").length,
        investigations,
        pipeline,
        performanceTrends,
        agentConfidence,
        xaiFeatures,
        modelMetrics,
      };
    });

    return NextResponse.json(data);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "unknown";
    return NextResponse.json(
      { agents: [], total_agents: 0, investigations: [], error: msg },
      { status: 503 },
    );
  }
}
