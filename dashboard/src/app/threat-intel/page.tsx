"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, AreaChart, Area, ScatterChart, Scatter, ZAxis, Cell,
} from "recharts";
import {
  Globe, Shield, AlertTriangle, Search, RefreshCw, ExternalLink,
  Hash, Server, Mail, FileText, Target, Clock, Filter, Database,
  ChevronDown, ChevronRight, Brain, Crosshair, Search as SearchIcon,
  ShieldCheck, Zap, CheckCircle, Link2, Activity, Eye, ArrowRight,
  AlertCircle, User, Monitor, Wifi,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, timeAgo, cn } from "@/lib/utils";
import type { IOC, ThreatPattern, Investigation } from "@/lib/types";

interface ThreatIntelResponse {
  iocs: IOC[];
  patterns: ThreatPattern[];
  stats?: {
    totalIOCs: number;
    activeThreats: number;
    mitreTechniques: number;
    lastUpdated: string;
  };
  mitreStats?: Array<{ technique: string; tactic: string; count: number; maxSeverity: number }>;
  topIOCs?: Array<{ value: string; type: string; hits: number; maxSeverity: number }>;
  recentAttacks?: Array<{ hour: string; technique: string; count: number }>;
}

const IOC_ICONS: Record<string, typeof Globe> = {
  ip: Server, ipv4: Server, domain: Globe, url: ExternalLink,
  hash: Hash, sha256: Hash, email: Mail, file: FileText,
};

const TYPE_COLORS: Record<string, string> = {
  IPv4: "#6366f1", Domain: "#f97316", Hostname: "#eab308",
  URL: "#06b6d4", Email: "#10b981", Hash: "#8b5cf6", File: "#ec4899",
};

const TACTIC_TO_KILL_CHAIN: Record<string, string> = {
  "reconnaissance": "RECONNAISSANCE",
  "resource-development": "WEAPONIZATION",
  "initial-access": "DELIVERY",
  "execution": "EXPLOITATION",
  "persistence": "INSTALLATION",
  "command-and-control": "C2 INFRASTRUCTURE",
  "privilege-escalation": "EXPLOITATION",
  "defense-evasion": "EXPLOITATION",
  "credential-access": "EXPLOITATION",
  "discovery": "RECONNAISSANCE",
  "lateral-movement": "DELIVERY",
  "collection": "INSTALLATION",
  "exfiltration": "C2 INFRASTRUCTURE",
  "impact": "C2 INFRASTRUCTURE",
};

const KILL_CHAIN_STAGES = ["RECONNAISSANCE", "WEAPONIZATION", "DELIVERY", "EXPLOITATION", "INSTALLATION", "C2 INFRASTRUCTURE"];
const KILL_CHAIN_COLORS: Record<string, string> = {
  RECONNAISSANCE: "bg-orange-500", WEAPONIZATION: "bg-orange-400", DELIVERY: "bg-orange-500",
  EXPLOITATION: "bg-red-500", INSTALLATION: "bg-orange-400", "C2 INFRASTRUCTURE": "bg-red-500",
};

const TACTIC_LABELS: Record<string, string> = {
  "reconnaissance": "Recon",
  "resource-development": "Resource Dev",
  "initial-access": "Initial Access",
  "execution": "Execution",
  "persistence": "Persistence",
  "command-and-control": "C2",
  "privilege-escalation": "Priv Esc",
  "defense-evasion": "Def Evasion",
  "credential-access": "Cred Access",
  "discovery": "Discovery",
  "lateral-movement": "Lateral Move",
  "collection": "Collection",
  "exfiltration": "Exfiltration",
  "impact": "Impact",
  "unknown": "Unknown",
};

export default function ThreatIntelPage() {
  const { data, loading, refresh } = usePolling<ThreatIntelResponse>("/api/threat-intel", 30000);
  const [tab, setTab] = useState("iocs");
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("All Types");
  const [confFilter, setConfFilter] = useState(0);
  const [expandedPattern, setExpandedPattern] = useState<string | null>(null);
  const [selectedBubble, setSelectedBubble] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);

  useEffect(() => {
    fetch("/api/ai/investigations/list")
      .then((r) => r.json())
      .then((d) => setInvestigations(Array.isArray(d.investigations) ? d.investigations : []))
      .catch(() => {});
  }, []);

  const iocs = data?.iocs || [];
  const patterns = data?.patterns || [];
  const stats = data?.stats;

  /* ── Derive chart data from real API response ── */
  const sevMap = useMemo(() => {
    const m: Record<string, number> = {};
    (data?.mitreStats || []).forEach((s) => { m[s.technique] = s.maxSeverity; });
    return m;
  }, [data?.mitreStats]);

  const TIMELINE_DATA = useMemo(() => {
    const attacks = data?.recentAttacks || [];
    const buckets: Record<string, { critical: number; high: number; medium: number }> = {};
    attacks.forEach((a) => {
      const h = a.hour?.slice(11, 16) || a.hour;
      if (!buckets[h]) buckets[h] = { critical: 0, high: 0, medium: 0 };
      const sev = sevMap[a.technique] ?? 2;
      if (sev >= 4) buckets[h].critical += a.count;
      else if (sev === 3) buckets[h].high += a.count;
      else buckets[h].medium += a.count;
    });
    return Object.entries(buckets)
      .map(([hour, v]) => ({ hour, ...v }))
      .sort((a, b) => a.hour.localeCompare(b.hour));
  }, [data?.recentAttacks, sevMap]);

  const TYPE_DIST = useMemo(() => {
    const counts: Record<string, number> = {};
    iocs.forEach((ioc) => { counts[ioc.type] = (counts[ioc.type] || 0) + 1; });
    const total = iocs.length || 1;
    return Object.entries(counts)
      .map(([type, count]) => ({ type, pct: Math.round((count / total) * 100), color: TYPE_COLORS[type] || "#6366f1" }))
      .sort((a, b) => b.pct - a.pct)
      .slice(0, 6);
  }, [iocs]);

  const MITRE_BUBBLE_DATA = useMemo(() => {
    return (data?.mitreStats || []).map((m, i) => ({
      x: i + 1,
      y: m.count,
      z: m.count * 2,
      name: m.technique,
      tacticLabel: TACTIC_LABELS[m.tactic] || TACTIC_LABELS[m.tactic?.toLowerCase()] || m.tactic || "Unknown",
      id: m.tactic || m.technique,
      active: m.maxSeverity >= 3,
    }));
  }, [data?.mitreStats]);

  const KILL_CHAIN = useMemo(() => {
    const counts: Record<string, number> = {};
    (data?.mitreStats || []).forEach((m) => {
      const stage = TACTIC_TO_KILL_CHAIN[m.tactic] || TACTIC_TO_KILL_CHAIN[m.tactic?.toLowerCase()] || "EXPLOITATION";
      counts[stage] = (counts[stage] || 0) + m.count;
    });
    const maxCount = Math.max(1, ...Object.values(counts));
    return KILL_CHAIN_STAGES.map((stage) => ({
      stage,
      count: counts[stage] ? `${counts[stage]}` : null,
      pct: Math.round(((counts[stage] || 0) / maxCount) * 100),
      color: KILL_CHAIN_COLORS[stage] || "bg-orange-500",
    }));
  }, [data?.mitreStats]);

  const RISKY_ENTITIES = useMemo(() => {
    const colors = ["from-red-500 to-orange-500", "from-orange-500 to-amber-500", "from-amber-500 to-yellow-500", "from-yellow-500 to-lime-500"];
    return (data?.topIOCs || []).slice(0, 4).map((ioc, i) => ({
      name: ioc.value,
      type: ioc.type.toLowerCase().includes("host") ? "host" : "host",
      label: ioc.maxSeverity >= 4 ? "Critical" : ioc.maxSeverity >= 3 ? "High" : "",
      score: Math.min(99, Math.round((ioc.maxSeverity / 4) * 100)),
      color: colors[i] || colors[3],
    }));
  }, [data?.topIOCs]);

  const RECENT_ALERTS = useMemo(() => {
    return investigations.slice(0, 4).map((inv) => ({
      title: inv.title || "Investigation",
      desc: inv.description || `Investigation ${inv.id}`,
      mitre: inv.tags?.[0] || "",
      time: inv.created ? timeAgo(inv.created) : "",
      sev: inv.severity >= 4 ? "CRITICAL" : inv.severity >= 3 ? "HIGH" : inv.severity >= 2 ? "MEDIUM" : "LOW",
    }));
  }, [investigations]);

  const filteredIOCs = iocs.filter(
    (ioc) =>
      (typeFilter === "All Types" || ioc.type.toLowerCase() === typeFilter.toLowerCase()) &&
      ioc.confidence >= confFilter &&
      (filter === "" ||
        ioc.value.toLowerCase().includes(filter.toLowerCase()) ||
        ioc.type.toLowerCase().includes(filter.toLowerCase()) ||
        ioc.source?.toLowerCase().includes(filter.toLowerCase()) ||
        ioc.tags?.some((t) => t.toLowerCase().includes(filter.toLowerCase())))
  );

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="-m-6 -mt-4">
      {/* ═══ STATS HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-primary/10 text-primary text-[11px] font-black uppercase tracking-tighter rounded">Live Intelligence</span>
                <span className="text-muted-foreground text-sm font-medium">Real-time threat monitoring</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                Threat <span className="text-primary inline-block">Intelligence</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">IOC management, threat patterns, MITRE ATT&CK mapping, and AI-driven enrichment across global feeds.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-muted/50 border border-border rounded-2xl text-sm font-semibold hover:bg-accent transition-colors">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Total IOCs</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(stats?.totalIOCs || iocs.length)}</h3>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Active Threats</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-red-500">{formatNumber(stats?.activeThreats || patterns.length)}</h3>
                <span className="text-muted-foreground text-xs font-bold uppercase tracking-tighter">Monitoring</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">MITRE Techniques</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(stats?.mitreTechniques || 0)}</h3>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Last Updated</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{stats?.lastUpdated ? timeAgo(stats.lastUpdated) : <><span>2</span> <span className="text-lg">mins</span></>}</h3>
                <span className="text-muted-foreground text-[10px] font-bold uppercase tracking-tighter">Real-time sync</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12 items-stretch">
        {/* LEFT COLUMN */}
        <div className="col-span-12 xl:col-span-8 flex flex-col">

          {/* Attack Timeline */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-red-50 text-red-500 rounded-2xl">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Attack Timeline (24h)</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{formatNumber(TIMELINE_DATA.reduce((s, d) => s + d.critical + d.high + d.medium, 0))} Total hits detected</p>
                </div>
              </div>
              <div className="flex gap-4">
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Critical</span></div>
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-orange-400" /><span className="text-[10px] font-black text-muted-foreground uppercase">High</span></div>
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-cyan-400" /><span className="text-[10px] font-black text-muted-foreground uppercase">Medium</span></div>
              </div>
            </div>
            <div className="h-[420px] bg-white rounded-[2.5rem] border border-border p-8 shadow-sm">
              <ResponsiveContainer>
                <AreaChart data={TIMELINE_DATA}>
                  <defs>
                    <linearGradient id="critG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef4444" stopOpacity={0.4}/><stop offset="100%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                    <linearGradient id="highG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f97316" stopOpacity={0.3}/><stop offset="100%" stopColor="#f97316" stopOpacity={0}/></linearGradient>
                    <linearGradient id="medG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#06b6d4" stopOpacity={0.2}/><stop offset="100%" stopColor="#06b6d4" stopOpacity={0}/></linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis dataKey="hour" tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} interval={3} />
                  <YAxis tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 11 }} />
                  <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critG)" strokeWidth={2} name="Critical" />
                  <Area type="monotone" dataKey="high" stroke="#f97316" fill="url(#highG)" strokeWidth={1.5} name="High" />
                  <Area type="monotone" dataKey="medium" stroke="#06b6d4" fill="url(#medG)" strokeWidth={1} name="Medium" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* MITRE ATT&CK Tactic Bubbles — Main Content */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-indigo-50 text-indigo-600 rounded-2xl">
                  <Target className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">MITRE ATT&CK Tactics</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mt-1">{MITRE_BUBBLE_DATA.filter(t => t.active).length} Active · {MITRE_BUBBLE_DATA.filter(t => !t.active).length} Inactive</p>
                </div>
              </div>
            </div>
            <div className="bg-muted/10 rounded-2xl p-8 border border-border shadow-sm overflow-hidden">
              {/* Packed bubble cluster */}
              {(() => {
                if (MITRE_BUBBLE_DATA.length === 0) return <p className="text-sm text-muted-foreground text-center py-8">No MITRE data available</p>;
                const sorted = [...MITRE_BUBBLE_DATA].sort((a, b) => b.z - a.z);
                const maxZ = Math.max(1, ...sorted.map(t => t.z));
                const MIN_R = 36, MAX_R = 80;
                const radii = sorted.map(t => Math.round(MIN_R + (MAX_R - MIN_R) * Math.sqrt(t.z / maxZ)));
                const positions: { x: number; y: number; r: number; data: typeof MITRE_BUBBLE_DATA[0] }[] = [];
                sorted.forEach((t, i) => {
                  const r = radii[i];
                  if (i === 0) {
                    positions.push({ x: 0, y: 0, r, data: t });
                  } else {
                    let bestX = 0, bestY = 0, bestDist = Infinity;
                    for (const p of positions) {
                      for (let a = 0; a < 360; a += 10) {
                        const rad = (a * Math.PI) / 180;
                        const dist = p.r + r + 3;
                        const cx = p.x + Math.cos(rad) * dist;
                        const cy = p.y + Math.sin(rad) * dist;
                        let valid = true;
                        for (const q of positions) {
                          const dx = cx - q.x, dy = cy - q.y;
                          if (Math.sqrt(dx * dx + dy * dy) < q.r + r + 2) { valid = false; break; }
                        }
                        if (valid) {
                          const d = Math.sqrt(cx * cx + cy * cy);
                          if (d < bestDist) { bestDist = d; bestX = cx; bestY = cy; }
                        }
                      }
                    }
                    positions.push({ x: bestX, y: bestY, r, data: t });
                  }
                });
                const minX = Math.min(...positions.map(p => p.x - p.r));
                const maxX = Math.max(...positions.map(p => p.x + p.r));
                const minY = Math.min(...positions.map(p => p.y - p.r));
                const maxY = Math.max(...positions.map(p => p.y + p.r));
                const w = maxX - minX;
                const h = maxY - minY;
                const cx = (minX + maxX) / 2;
                const cy = (minY + maxY) / 2;

                return (
                  <div className="relative mx-auto" style={{ width: Math.min(Math.max(w + 40, 500), 900), height: Math.min(Math.max(h + 40, 350), 500) }}>
                    {positions.map((p) => {
                      const t = p.data;
                      const size = p.r * 2;
                      const isSelected = selectedBubble === t.id;
                      return (
                        <div
                          key={t.id}
                          onClick={() => setSelectedBubble(isSelected ? null : t.id)}
                          className={cn(
                            "absolute rounded-full flex flex-col items-center justify-center cursor-pointer transition-all duration-300 select-none",
                            t.active
                              ? isSelected
                                ? "bg-primary text-white shadow-lg shadow-primary/30 z-10 scale-110"
                                : "bg-primary/10 text-primary hover:bg-primary/20 hover:scale-105 hover:z-10"
                              : isSelected
                                ? "bg-muted text-foreground shadow-md z-10 scale-110"
                                : "bg-muted/40 text-muted-foreground hover:bg-muted/60 hover:scale-105 hover:z-10 border border-border/50"
                          )}
                          style={{
                            width: size,
                            height: size,
                            left: p.x - cx + (Math.min(Math.max(w + 40, 500), 900)) / 2 - p.r,
                            top: p.y - cy + (Math.min(Math.max(h + 40, 350), 500)) / 2 - p.r,
                          }}
                        >
                          <span className="font-extrabold leading-none" style={{ fontSize: Math.max(10, size / 5) }}>{formatNumber(t.y)}</span>
                          <span className={cn("font-black uppercase leading-tight text-center px-1 mt-0.5", size >= 80 ? "text-[9px]" : "text-[7px]")}>{t.tacticLabel}</span>
                          <span className={cn("font-mono leading-tight text-center px-1 opacity-70", size >= 80 ? "text-[8px]" : "text-[6px]")}>{t.name}</span>
                        </div>
                      );
                    })}
                  </div>
                );
              })()}

              {/* Detail panel for selected bubble */}
              {selectedBubble && (() => {
                const t = MITRE_BUBBLE_DATA.find(b => b.id === selectedBubble);
                if (!t) return null;
                return (
                  <div className="mt-6 pt-6 border-t border-border animate-in fade-in slide-in-from-top-2 duration-200">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-bold text-foreground">{t.name} — {t.tacticLabel}</p>
                        <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-wider">{t.id}</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-extrabold text-primary">{formatNumber(t.y)}</div>
                        <div className="text-[9px] font-black text-muted-foreground uppercase">Detections</div>
                      </div>
                    </div>
                    <div className="mt-3 h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                      <div className={cn("h-full rounded-full transition-all duration-500", t.active ? "bg-primary" : "bg-muted-foreground/40")} style={{ width: `${Math.min(100, t.y)}%` }} />
                    </div>
                    <div className="flex items-center gap-2 mt-3">
                      <span className={cn("px-2.5 py-1 text-[10px] font-black rounded uppercase", t.active ? "bg-emerald-50 text-emerald-600" : "bg-muted text-muted-foreground")}>{t.active ? "Active" : "Inactive"}</span>
                      <span className="text-[10px] text-muted-foreground">{t.z} total events</span>
                    </div>
                  </div>
                );
              })()}
            </div>
          </section>

          {/* Threat Feed Status — Data Sources */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-slate-900 text-white rounded-2xl">
                  <Wifi className="w-5 h-5" />
                </div>
                <h3 className="text-2xl font-extrabold text-foreground">Data Sources</h3>
              </div>
              <button onClick={refresh} className="text-[11px] font-black text-primary uppercase tracking-[0.2em] hover:underline">Refresh</button>
            </div>
            <div className="bg-muted/20 rounded-2xl overflow-hidden border border-border">
              <table className="w-full text-left">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Source</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">IOCs</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Last Updated</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Health</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  <tr className="hover:bg-card transition-colors">
                    <td className="px-6 py-6">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
                          <Database className="w-4 h-4" />
                        </div>
                        <span className="font-bold text-foreground">ClickHouse Pipeline</span>
                      </div>
                    </td>
                    <td className="px-6 py-6 text-sm font-bold text-foreground font-mono">{formatNumber(iocs.length)}</td>
                    <td className="px-6 py-6 text-sm text-muted-foreground">{stats?.lastUpdated ? timeAgo(stats.lastUpdated) : "-"}</td>
                    <td className="px-6 py-6">
                      <span className={cn("px-3 py-1 text-[10px] font-black rounded uppercase", iocs.length > 0 ? "text-emerald-600 bg-emerald-50" : "text-amber-600 bg-amber-50")}>{iocs.length > 0 ? "ACTIVE" : "NO DATA"}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* IOC Matches Table */}
          <section className="px-10 py-10 bg-white border-t border-border">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <Shield className="w-5 h-5" />
                </div>
                <h3 className="text-2xl font-extrabold text-foreground">Recent IOC Matches</h3>
              </div>
              <div className="flex flex-wrap items-center gap-2.5">
                <div className="relative">
                  <Filter className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Search threats..."
                    className="w-52 bg-card border border-border rounded-full pl-9 pr-4 py-2 text-sm focus:ring-1 focus:ring-primary/30 focus:outline-none transition-all"
                  />
                </div>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-2 bg-card border border-border rounded-full text-xs font-medium text-foreground outline-none"
                >
                  <option>All Types</option>
                  <option>ipv4</option>
                  <option>domain</option>
                  <option>sha256</option>
                  <option>url</option>
                  <option>email</option>
                </select>
                <select
                  value={confFilter}
                  onChange={(e) => setConfFilter(Number(e.target.value))}
                  className="px-3 py-2 bg-card border border-border rounded-full text-xs font-medium text-foreground outline-none"
                >
                  <option value={0}>All Confidence</option>
                  <option value={80}>Confidence &gt; 80</option>
                  <option value={90}>Confidence &gt; 90</option>
                </select>
                {filter && <button onClick={() => setFilter("")} className="text-[10px] font-black text-primary uppercase tracking-wider hover:underline">Clear</button>}
              </div>
            </div>
            <div className="bg-card rounded-[2.5rem] overflow-hidden border border-border shadow-sm">
              <table className="w-full text-left">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Type</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Value</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Confidence</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Source</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">MITRE</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {filteredIOCs.map((ioc, i) => {
                    const IconComp = IOC_ICONS[ioc.type.toLowerCase()] || Shield;
                    return (
                      <tr key={i} className="hover:bg-muted/10 transition-colors">
                        <td className="px-5 py-4">
                          <span className="px-2.5 py-1 bg-slate-900 text-white rounded text-[10px] font-black uppercase flex items-center gap-1.5 w-fit">
                            <IconComp className="h-2.5 w-2.5" />{ioc.type}
                          </span>
                        </td>
                        <td className="px-5 py-4 font-mono text-xs text-muted-foreground max-w-[240px] truncate">{ioc.value}</td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-20 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                              <div className={cn("h-full rounded-full", ioc.confidence >= 90 ? "bg-red-500" : ioc.confidence >= 70 ? "bg-primary" : "bg-amber-400")} style={{ width: `${ioc.confidence}%` }} />
                            </div>
                            <span className="text-xs font-black" style={{ color: ioc.confidence >= 90 ? "#ef4444" : ioc.confidence >= 70 ? "#2563eb" : "#f59e0b" }}>{ioc.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-5 py-4 text-xs text-muted-foreground">{ioc.source || "—"}</td>
                        <td className="px-5 py-4">
                          {ioc.mitre ? <span className="px-2.5 py-1 bg-indigo-50 text-indigo-600 text-[10px] font-black rounded uppercase">{ioc.mitre}</span> : "—"}
                        </td>
                        <td className="px-5 py-4 text-xs text-muted-foreground">{ioc.lastSeen ? timeAgo(ioc.lastSeen) : "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filteredIOCs.length === 0 && (
                <div className="py-16 text-center text-sm text-muted-foreground">
                  {filter || typeFilter !== "All Types" || confFilter > 0 ? "No IOCs match your filters" : "No IOCs available"}
                </div>
              )}
            </div>
          </section>

          {/* Threat Patterns + Investigation Matches side by side — fills remaining height */}
          <section className="px-10 py-10 bg-white border-t border-border">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 h-full">
              {/* Threat Patterns */}
              <div className="flex flex-col">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-orange-50 text-orange-500 rounded-2xl">
                    <Target className="w-5 h-5" />
                  </div>
                  <h3 className="text-2xl font-extrabold text-foreground">Threat Patterns</h3>
                </div>
                <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
                  {patterns.length > 0 ? patterns.map((pattern, idx) => (
                    <div key={idx} className="bg-muted/20 rounded-2xl p-5 border border-border hover:border-primary/30 transition-all cursor-pointer group"
                      onClick={() => setExpandedPattern(expandedPattern === pattern.name ? null : pattern.name)}>
                      <div className="flex items-start gap-4">
                        <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl mt-0.5", pattern.severity >= 4 ? "bg-red-50 text-red-500" : "bg-orange-50 text-orange-500")}>
                          <Target className="h-4 w-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded", pattern.severity >= 4 ? "bg-red-50 text-red-600" : "bg-orange-50 text-orange-600")}>
                              {pattern.severity >= 4 ? "CRITICAL" : "HIGH"} · {pattern.mitre}
                            </span>
                          </div>
                          <h4 className="text-sm font-bold text-foreground group-hover:text-primary transition-colors">{pattern.name}</h4>
                          <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2">{pattern.description}</p>
                          <div className="flex items-center gap-4 mt-2">
                            <span className="flex items-center gap-1 text-[10px] font-bold text-muted-foreground">
                              <Shield className="h-2.5 w-2.5" /> {pattern.iocCount} Indicators
                            </span>
                            <span className="flex items-center gap-1 text-[10px] font-bold text-muted-foreground">
                              <Activity className="h-2.5 w-2.5" /> {pattern.matchedEvents} events
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )) : (
                    <div className="bg-muted/20 rounded-2xl p-12 border border-border text-center">
                      <p className="text-sm text-muted-foreground">No threat patterns available</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Investigation Matches */}
              <div className="flex flex-col">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                      <Link2 className="w-5 h-5" />
                    </div>
                    <h3 className="text-2xl font-extrabold text-foreground">Investigation Matches</h3>
                  </div>
                  <Link href="/investigations" className="text-[11px] font-black text-primary uppercase tracking-widest hover:underline">View All</Link>
                </div>
                {investigations.length > 0 ? (
                  <div className="space-y-3">
                    {investigations.slice(0, 4).map((inv) => (
                      <Link key={inv.id} href={`/investigations/${inv.id}`}>
                        <div className="bg-muted/20 rounded-2xl p-5 border border-border hover:border-primary/30 transition-all cursor-pointer group flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded", inv.severity >= 4 ? "bg-red-50 text-red-600" : inv.severity >= 3 ? "bg-orange-50 text-orange-600" : "bg-amber-50 text-amber-600")}>S{inv.severity}</span>
                            <div>
                              <p className="text-sm font-bold text-foreground group-hover:text-primary transition-colors line-clamp-1">{inv.title}</p>
                              <div className="flex items-center gap-2 mt-1">
                                <span className="text-[10px] text-muted-foreground font-bold">{inv.eventCount} events</span>
                                {inv.tags?.slice(0, 2).map((t) => (
                                  <span key={t} className="px-2 py-0.5 bg-indigo-50 text-indigo-600 text-[9px] font-black rounded uppercase">{t}</span>
                                ))}
                              </div>
                            </div>
                          </div>
                          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-primary transition-colors" />
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="bg-muted/20 rounded-2xl p-12 border border-border text-center">
                    <p className="text-sm text-muted-foreground">No active investigations</p>
                  </div>
                )}
              </div>
            </div>
          </section>

        </div>

        {/* RIGHT SIDEBAR */}
        <aside className="col-span-12 xl:col-span-4 bg-white border-l border-border/80 p-8 space-y-10">

          {/* IOC Type Distribution */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="w-10 h-10 bg-card shadow-sm text-primary rounded-xl flex items-center justify-center border border-border">
                <Eye className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">IOC Type Distribution</h3>
            </div>
            <div className="bg-card rounded-2xl p-6 border border-border shadow-sm space-y-5">
              {TYPE_DIST.map((t) => (
                <div key={t.type} className="space-y-2">
                  <div className="flex justify-between text-[10px] font-black text-muted-foreground uppercase tracking-widest">
                    <span>{t.type}</span>
                    <span className="text-foreground">{t.pct}%</span>
                  </div>
                  <div className="h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${t.pct}%`, background: t.color }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Kill Chain Activity */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="p-2.5 bg-orange-50 text-orange-500 rounded-xl">
                <Zap className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Cyber Kill Chain</h3>
            </div>
            <div className="bg-card rounded-2xl p-6 border border-border shadow-sm space-y-4">
              {KILL_CHAIN.map((k) => (
                <div key={k.stage}>
                  <div className="flex justify-between text-[10px] font-bold text-muted-foreground uppercase mb-1.5">
                    <span>{k.stage}</span>
                    <span className="text-foreground">{k.count || `${k.pct}%`}</span>
                  </div>
                  <div className="h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                    <div className={cn("h-full rounded-full", k.color)} style={{ width: `${k.pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* High-Risk Entities */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="w-10 h-10 bg-red-50 text-red-500 rounded-xl flex items-center justify-center">
                <AlertCircle className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">High-Risk Entities</h3>
            </div>
            <div className="space-y-3">
              {RISKY_ENTITIES.map((e) => (
                <div key={e.name} className="bg-card rounded-2xl p-5 border border-border shadow-sm flex items-center justify-between hover:border-primary/30 transition-all">
                  <div className="flex items-center gap-3">
                    <div className={cn("h-9 w-9 rounded-full flex items-center justify-center bg-gradient-to-br text-white text-[10px] font-bold", e.color)}>
                      {e.type === "user" ? <User className="h-3.5 w-3.5" /> : <Monitor className="h-3.5 w-3.5" />}
                    </div>
                    <div>
                      <p className="text-xs font-bold text-foreground">{e.name}</p>
                      {e.label && <p className="text-[10px] text-muted-foreground">{e.label}</p>}
                    </div>
                  </div>
                  <span className={cn("text-lg font-extrabold tabular-nums", e.score >= 90 ? "text-red-500" : e.score >= 70 ? "text-orange-500" : "text-amber-500")}>{e.score}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Critical Alerts */}
          <section>
            <div className="flex items-center justify-between mb-6 px-2">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-card shadow-sm text-red-500 rounded-xl flex items-center justify-center border border-border">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-extrabold text-foreground">Critical Alerts</h3>
              </div>
              <Link href="/investigations" className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline">View All</Link>
            </div>
            <div className="space-y-3">
              {RECENT_ALERTS.map((a) => (
                <div key={a.title} className="bg-card rounded-2xl p-5 border border-border shadow-sm hover:border-primary/30 transition-all cursor-pointer group">
                  <div className="flex justify-between items-start mb-3">
                    <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded", a.sev === "CRITICAL" ? "bg-red-50 text-red-600" : "bg-primary/10 text-primary")}>{a.sev}</span>
                    <span className="text-[10px] font-bold text-muted-foreground">{a.time}</span>
                  </div>
                  <h4 className="font-bold text-foreground text-sm mb-1 group-hover:text-primary transition-colors">{a.title}</h4>
                  <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">{a.desc}</p>
                  <div className="flex items-center gap-2 mt-2">
                    <span className="px-2.5 py-1 bg-indigo-50 text-indigo-600 text-[10px] font-black rounded uppercase">{a.mitre}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

        </aside>
      </div>


    </div>
  );
}
