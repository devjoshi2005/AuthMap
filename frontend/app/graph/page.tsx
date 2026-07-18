"use client";

import { useAuth } from "@clerk/nextjs";
import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import cytoscape from "cytoscape";
// @ts-ignore
import fcose from "cytoscape-fcose";

if (typeof window !== "undefined" && !cytoscape.use.name.includes("fcose")) {
  cytoscape.use(fcose);
}
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { Network } from "lucide-react";

/* ── Types ─────────────────────────────────────────────── */
interface GraphNode {
  id: string;
  label: string;
  type: string;
  provider?: string;
  risk_score?: number;
  is_admin?: boolean;
  is_overprivileged?: boolean;
  has_mfa?: boolean;
  is_dormant?: boolean;
  account_id?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
  relationship?: string;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface AttackPath {
  path?: string[];
  path_nodes?: {
    nodes: string[];
    types?: string[];
  };
  risk_score: number;
  description?: string;
}

/* ── Entity type → color map ───────────────────────────── */
const TYPE_COLORS: Record<string, string> = {
  User: "#9ec1b6",
  Role: "#ead8b2",
  Group: "rgba(255, 255, 255, 0.26)",
  Policy: "#cb8e77",
  ServiceAccount: "#7bc8a4",
  PermissionSet: "#a89ecf",
  Resource: "#6b8fa3",
  AccessKey: "#8b8b8b",
  MFADevice: "#66cc99",
  Organization: "#f0e68c",
  Account: "#dda0dd",
  Event: "#ff7f50",
};

const cyStylesheet: cytoscape.StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      "label": "data(label)",
      "text-valign": "bottom" as const,
      "text-halign": "center" as const,
      "font-size": "10px",
      "color": "#f5efe6",
      "text-outline-color": "#0d1015",
      "text-outline-width": 2,
      "width": "mapData(risk_score,0,100,30,70)",
      "height": "mapData(risk_score,0,100,30,70)",
      "border-width": 2,
      "border-color": "rgba(255, 255, 255, 0.13)",
      "background-color": "#666",
    },
  },
  { selector: 'node[type="User"]', style: { "background-color": "#9ec1b6" } },
  { selector: 'node[type="Role"]', style: { "background-color": "#ead8b2" } },
  { selector: 'node[type="Group"]', style: { "background-color": "rgba(255, 255, 255, 0.26)" } },
  { selector: 'node[type="Policy"]', style: { "background-color": "#cb8e77" } },
  { selector: 'node[type="ServiceAccount"]', style: { "background-color": "#7bc8a4" } },
  { selector: 'node[type="PermissionSet"]', style: { "background-color": "#a89ecf" } },
  { selector: 'node[type="Resource"]', style: { "background-color": "#6b8fa3" } },
  { selector: 'node[type="AccessKey"]', style: { "background-color": "#8b8b8b" } },
  { selector: 'node[type="MFADevice"]', style: { "background-color": "#66cc99" } },
  { selector: 'node[type="Organization"]', style: { "background-color": "#f0e68c" } },
  { selector: 'node[type="Account"]', style: { "background-color": "#dda0dd" } },
  { selector: 'node[type="Event"]', style: { "background-color": "#ff7f50" } },
  {
    selector: "node[?is_admin]",
    style: { "border-color": "#ff4444", "border-width": 3, "border-opacity": 0.8 },
  },
  {
    selector: "edge",
    style: {
      width: 1.5,
      "line-color": "rgba(255, 255, 255, 0.09)",
      "target-arrow-color": "rgba(255, 255, 255, 0.18)",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.8,
      label: "data(label)",
      
      "font-size": "7px",
      color: "rgba(255, 255, 255, 0.26)",
      "text-rotation": "autorotate",
    },
  },
  {
    selector: ".attack-path",
    style: {
      "line-color": "#ff4444",
      "target-arrow-color": "#ff4444",
      width: 3,
      "z-index": 10,
    },
  },
  {
    selector: ".attack-path-node",
    style: {
      "border-color": "#ff4444",
      "border-width": 4,
      "border-opacity": 1,
    },
  },
  {
    selector: "node.dimmed",
    style: {
      "opacity": 0.2,
    },
  },
  {
    selector: "edge.dimmed",
    style: {
      "opacity": 0.1,
    },
  },
];

/* ── Component ─────────────────────────────────────────── */
export default function GraphPage() {
  const { getToken, isLoaded } = useAuth();

  const cyRef = useRef<HTMLDivElement>(null);
  const cyInstanceRef = useRef<cytoscape.Core | null>(null);

  const [loading, setLoading] = useState(true);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [showAttackPaths, setShowAttackPaths] = useState(false);
  const [entityTypes, setEntityTypes] = useState<string[]>([]);
  const [stats, setStats] = useState({ nodes: 0, edges: 0, admins: 0 });
  const [noScan, setNoScan] = useState(false);

  /* ── Data fetching ─────────────────────────────────── */
  useEffect(() => {
    if (!isLoaded) return;
    async function load() {
      try {
        const token = await getToken();
        if (!token) return;
        const headers = { Authorization: `Bearer ${token}` };
        const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

        const scanRes = await fetch(`${backendUrl}/scan/results/latest`, { headers });
        if (!scanRes.ok) {
          setNoScan(true);
          setLoading(false);
          return;
        }
        const scan = await scanRes.json();
        const scanId = scan.id ?? scan.scan_id;

        const saved = sessionStorage.getItem('boxai_scan_creds');
        let neo4jHeaders: Record<string, string> = {};
        if (saved) {
          try {
            const data = JSON.parse(saved);
            if (data.neo4jUri) neo4jHeaders['x-neo4j-uri'] = data.neo4jUri;
            if (data.neo4jUsername) neo4jHeaders['x-neo4j-user'] = data.neo4jUsername;
            if (data.neo4jPassword) neo4jHeaders['x-neo4j-password'] = data.neo4jPassword;
          } catch (e) {}
        }

        const [graphRes, pathsRes] = await Promise.all([
          fetch(`${backendUrl}/scan/graph/${scanId}`, { 
            headers: { ...headers, ...neo4jHeaders } 
          }),
          fetch(`${backendUrl}/scan/attack-paths/${scanId}`, { headers }),
        ]);

        if (graphRes.ok) {
          const raw = await graphRes.json();
          // Backend returns { elements: { nodes: [{data:{...}}], edges: [{data:{...}}] }, stats: {} }
          const rawNodes = raw.elements?.nodes ?? raw.nodes ?? [];
          const rawEdges = raw.elements?.edges ?? raw.edges ?? [];
          const gd: GraphData = {
            nodes: rawNodes.map((n: { data?: GraphNode } & GraphNode) => n.data ?? n),
            edges: rawEdges.map((e: { data?: GraphEdge } & GraphEdge) => e.data ?? e),
          };
          setGraphData(gd);

          const types = [...new Set(gd.nodes.map((n) => n.type))].sort();
          setEntityTypes(types);
          setStats({
            nodes: gd.nodes.length,
            edges: gd.edges.length,
            admins: gd.nodes.filter((n) => n.is_admin).length,
          });
        } else {
          setNoScan(true);
        }

        if (pathsRes.ok) {
          const ap = await pathsRes.json();
          setAttackPaths(Array.isArray(ap) ? ap : ap.paths ?? []);
        }
      } catch {
        setNoScan(true);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken, isLoaded]);

  useEffect(() => {
    if (!graphData || !cyRef.current) return;

    const labelCounts: Record<string, number> = {};
    graphData.nodes.forEach((n) => {
      const lbl = n.label || n.id;
      labelCounts[lbl] = (labelCounts[lbl] || 0) + 1;
    });

    const elements: cytoscape.ElementDefinition[] = [
      ...graphData.nodes.map((n) => {
        const baseLabel = n.label || n.id;
        const finalLabel = labelCounts[baseLabel] > 1 ? `${baseLabel} (${n.type})` : baseLabel;
        return {
          data: {
            id: n.id,
            label: finalLabel,
            type: n.type,
            risk_score: n.risk_score ?? 20,
            is_admin: n.is_admin ?? false,
            is_overprivileged: n.is_overprivileged ?? false,
            has_mfa: n.has_mfa ?? false,
            is_dormant: n.is_dormant ?? false,
            provider: n.provider ?? "",
            account_id: n.account_id ?? "",
          },
        };
      }),
      ...graphData.edges.map((e, i) => ({
        data: {
          id: `e${i}`,
          source: e.source,
          target: e.target,
          label: e.label ?? e.relationship ?? "",
        },
      })),
    ];

    // Ensure the container has explicit dimensions before Cytoscape init
    // (mapData and other style functions fail if container is 0×0)
    const container = cyRef.current;
    if (!container.offsetHeight) {
      container.style.minHeight = "600px";
    }

    const cy = cytoscape({
      container,
      elements,
      style: cyStylesheet,
      layout: {
        name: "fcose",
        animate: false,
        randomize: true,
        quality: "default",
        nodeRepulsion: 400000,
        idealEdgeLength: 250,
        edgeElasticity: 0.5,
        gravity: 0.25,
        numIter: 1000,
        padding: 50,
      } as any,
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.2, // Essential for smooth zooming on 1000+ node graphs
    });

    cy.on("tap", "node", (evt) => {
      const d = evt.target.data();
      setSelectedNode(d as GraphNode);
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) setSelectedNode(null);
    });

    cyInstanceRef.current = cy;

    return () => {
      if (cy) {
        if (!cy.destroyed()) {
          // Force stop all active animations and layouts before destroying
          cy.stop(true, true);
          cy.elements().stop(true, true);
          cy.removeAllListeners();
          cy.destroy();
        }
      }
      cyInstanceRef.current = null;
    };
    // Only re-init when graphData reference changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphData]);

  /* ── Filter visibility ─────────────────────────────── */
  useEffect(() => {
    const cy = cyInstanceRef.current;
    if (!cy || cy.destroyed()) return;
    
    cy.batch(() => {
      cy.nodes().forEach((node) => {
        const type = node.data("type") as string;
        if (hiddenTypes.has(type)) {
          node.style("display", "none");
        } else {
          node.style("display", "element");
        }
      });
    });
  }, [hiddenTypes]);

  /* ── Attack path toggle ────────────────────────────── */
  useEffect(() => {
    const cy = cyInstanceRef.current;
    if (!cy || cy.destroyed()) return;

    cy.batch(() => {
      cy.elements().removeClass("attack-path attack-path-node dimmed");

      if (showAttackPaths && attackPaths.length > 0) {
        cy.elements().addClass("dimmed");
        attackPaths.forEach((ap) => {
          const path = ap.path_nodes?.nodes || ap.path || [];
          for (let i = 0; i < path.length; i++) {
            const node = cy.getElementById(path[i]);
            if (node.length) {
              node.addClass("attack-path-node");
              node.removeClass("dimmed");
            }
            if (i < path.length - 1) {
              const edges = cy.edges(`[source="${path[i]}"][target="${path[i + 1]}"]`);
              edges.addClass("attack-path");
              edges.removeClass("dimmed");
              const reverseEdges = cy.edges(`[source="${path[i + 1]}"][target="${path[i]}"]`);
              reverseEdges.addClass("attack-path");
              reverseEdges.removeClass("dimmed");
            }
          }
        });
      }
    });
  }, [showAttackPaths, attackPaths]);

  const handleZoomIn = useCallback(() => {
    const cy = cyInstanceRef.current;
    if (cy && !cy.destroyed()) cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }, []);
  const handleZoomOut = useCallback(() => {
    const cy = cyInstanceRef.current;
    if (cy && !cy.destroyed()) cy.zoom({ level: cy.zoom() / 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }, []);

  function toggleType(type: string) {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  function riskColor(score?: number): string {
    if (!score && score !== 0) return "text-slate-400";
    if (score >= 80) return "text-red-400";
    if (score >= 60) return "text-orange-400";
    if (score >= 40) return "text-yellow-400";
    return "text-green-400";
  }

  return (
    <AppShell>
      <div className="space-y-6 pb-10">
        <ScreenHeader
          eyebrow="IAM Graph"
          title="Full relationship graph with controls."
          description="Interactive Cytoscape.js visualization of every IAM entity, trust chain, and privilege escalation path across your connected cloud accounts."
        />

        {loading && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-10 text-center">
            <p className="animate-pulse text-sm text-slate-400">Loading graph data…</p>
          </div>
        )}

        {!loading && !graphData && (
          <section className="rounded-[2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_50px_rgba(0,0,0,0.18)] md:p-8">
            <div className="flex flex-col items-center justify-center gap-6 py-20">
              <div className="flex h-24 w-24 items-center justify-center rounded-full border border-[var(--accent-cyan)]/30 bg-[rgba(158,193,182,0.08)]">
                <Network className="h-10 w-10 text-[var(--accent-cyan)]" />
              </div>
              <div className="text-center">
                <h2 className="text-2xl font-semibold text-white">Graph visualization loading zone</h2>
                <p className="mt-3 max-w-lg text-sm leading-7 text-slate-300">
                  Run a scan from the Scan Wizard to populate the IAM relationship graph. Nodes represent users, roles, policies, and service accounts. Edges show trust chains and permission flows.
                </p>
              </div>
              <div className="flex flex-wrap gap-2 text-[0.68rem] font-semibold uppercase tracking-[0.18em] text-white/80">
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">Neo4j backend</span>
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">Cytoscape.js render</span>
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">Node2vec embeddings</span>
              </div>
              <Link
                href="/scan-wizard"
                className="action-box action-box-cyan px-5 py-2.5 text-sm font-semibold text-white"
              >
                Launch Scan Wizard →
              </Link>
            </div>
          </section>
        )}

        {!loading && graphData && (
          <>
            {/* Stats bar */}
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-4 py-2">
                <span className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.2em] text-slate-400">Nodes</span>
                <span className="text-sm font-semibold text-white">{stats.nodes}</span>
              </div>
              <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-4 py-2">
                <span className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.2em] text-slate-400">Edges</span>
                <span className="text-sm font-semibold text-white">{stats.edges}</span>
              </div>
              <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-4 py-2">
                <span className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.2em] text-slate-400">Admins</span>
                <span className="text-sm font-semibold text-red-400">{stats.admins}</span>
              </div>
              <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-4 py-2">
                <span className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.2em] text-slate-400">Types</span>
                <span className="text-sm font-semibold text-white">{entityTypes.length}</span>
              </div>
            </div>

            {/* Entity type filter toggles */}
            <div className="flex flex-wrap gap-2">
              {entityTypes.map((type) => {
                const isHidden = hiddenTypes.has(type);
                const color = TYPE_COLORS[type] ?? "#888";
                return (
                  <button
                    key={type}
                    type="button"
                    onClick={() => toggleType(type)}
                    className={`flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition ${
                      isHidden
                        ? "border-white/5 bg-white/[0.02] text-slate-600 line-through"
                        : "border-white/15 bg-white/[0.05] text-white"
                    }`}
                  >
                    {type}
                  </button>
                );
              })}

              {attackPaths.length > 0 && (
                <button
                  type="button"
                  onClick={() => setShowAttackPaths((p) => !p)}
                  className={`flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold transition ${
                    showAttackPaths
                      ? "border-red-500/40 bg-red-500/10 text-red-400"
                      : "border-white/15 bg-white/[0.05] text-white"
                  }`}
                >
                  {showAttackPaths ? "Hide Attack Paths" : "Show Attack Paths"}
                </button>
              )}
            </div>

            <div className="relative rounded-[2rem] border border-white/10 bg-[#0a0d12] overflow-hidden">
              <div
                ref={cyRef}
                style={{ width: "100%", height: "calc(100vh - 280px)", minHeight: "600px" }}
              />

              <div className="absolute bottom-6 right-6 flex flex-col gap-3 z-50">
                <button
                  type="button"
                  onClick={handleZoomIn}
                  className="flex h-12 w-12 items-center justify-center rounded-full border border-white/20 bg-[#2a303c] shadow-lg shadow-black/50 text-2xl font-bold text-white transition hover:bg-[#3b4354] hover:border-white/40"
                  aria-label="Zoom In"
                >
                  +
                </button>
                <button
                  type="button"
                  onClick={handleZoomOut}
                  className="flex h-12 w-12 items-center justify-center rounded-full border border-white/20 bg-[#2a303c] shadow-lg shadow-black/50 text-2xl font-bold text-white transition hover:bg-[#3b4354] hover:border-white/40"
                  aria-label="Zoom Out"
                >
                  −
                </button>
              </div>

              {/* Side panel */}
              {selectedNode && (
                <div className="absolute right-0 top-0 z-20 h-full w-80 overflow-y-auto border-l border-white/10 bg-[#12161d] p-5">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.2em] text-slate-400">
                        Entity Detail
                      </p>
                      <h3 className="mt-1 text-lg font-semibold text-white break-all">{selectedNode.label}</h3>
                    </div>
                    <button
                      type="button"
                      onClick={() => setSelectedNode(null)}
                      className="flex h-7 w-7 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-sm text-slate-400 hover:text-white"
                    >
                      ✕
                    </button>
                  </div>

                  <div className="mt-4 space-y-3">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">Type</span>
                      <span className="font-medium text-white">{selectedNode.type}</span>
                    </div>
                    {selectedNode.provider && (
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Provider</span>
                        <span className="font-medium text-white uppercase">{selectedNode.provider}</span>
                      </div>
                    )}
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">Risk Score</span>
                      <span className={`font-semibold ${riskColor(selectedNode.risk_score)}`}>
                        {selectedNode.risk_score ?? "N/A"}
                      </span>
                    </div>
                    {selectedNode.account_id && (
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Account</span>
                        <span className="font-medium text-white text-xs">{selectedNode.account_id}</span>
                      </div>
                    )}
                  </div>

                  {/* Badges */}
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {selectedNode.is_admin && (
                      <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2.5 py-1 text-xs font-semibold text-red-400">
                        Admin
                      </span>
                    )}
                    {selectedNode.is_overprivileged && (
                      <span className="rounded-full border border-orange-500/40 bg-orange-500/10 px-2.5 py-1 text-xs font-semibold text-orange-400">
                        Overprivileged
                      </span>
                    )}
                    {selectedNode.has_mfa === false && (
                      <span className="rounded-full border border-yellow-500/40 bg-yellow-500/10 px-2.5 py-1 text-xs font-semibold text-yellow-400">
                        No MFA
                      </span>
                    )}
                    {selectedNode.is_dormant && (
                      <span className="rounded-full border border-slate-500/40 bg-slate-500/10 px-2.5 py-1 text-xs font-semibold text-slate-400">
                        Dormant
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}
