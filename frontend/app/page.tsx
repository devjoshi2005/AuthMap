"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState, useRef } from "react";

import { AppShell } from "../components/app-shell";
import { AuthLanding } from "../components/auth-landing";

export default function Home() {
  const { userId, isLoaded, getToken } = useAuth();
  const [hasScan, setHasScan] = useState<boolean>(true); // Default true to avoid flash
  const [loadingScan, setLoadingScan] = useState(true);
  const contentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isLoaded || !userId) return;
    async function checkScan() {
      try {
        const token = await getToken();
        if (!token) return;
        const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
        
        // Fire-and-forget Neo4j warmup request to reduce AI cold starts
        fetch(`${backendUrl}/neo4j/warmup`, {
          method: "POST",
          headers: { 
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({})
        }).catch(() => {});
        
        const res = await fetch(`${backendUrl}/scan/results/latest`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          setHasScan(true);
        } else {
          setHasScan(false);
        }
      } catch {
        setHasScan(false);
      } finally {
        setLoadingScan(false);
      }
    }
    checkScan();
  }, [isLoaded, userId, getToken]);

  useEffect(() => {
    if (isLoaded && userId) {
      const timer = setTimeout(() => {
        if (contentRef.current) {
          contentRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 150);
      return () => clearTimeout(timer);
    }
  }, [isLoaded, userId]);

  if (!isLoaded) {
    return null;
  }

  if (!userId) {
    return <AuthLanding isSignedIn={false} />;
  }

  const isPreScan = !loadingScan && !hasScan;

  const scanWizardClasses = isPreScan
    ? "group rounded-[1.6rem] border border-[var(--accent-cyan)] bg-[linear-gradient(180deg,rgba(158,193,182,0.15),rgba(255,255,255,0.05))] p-6 shadow-[0_20px_50px_rgba(158,193,182,0.2)] transition"
    : "group rounded-[1.6rem] border border-[var(--accent-cyan)]/30 bg-[linear-gradient(180deg,rgba(158,193,182,0.08),rgba(255,255,255,0.02))] p-6 transition hover:border-[var(--accent-cyan)]/50 hover:shadow-[0_20px_50px_rgba(158,193,182,0.08)]";

  const otherOptionsClasses = isPreScan
    ? "group rounded-[1.6rem] border border-white/5 bg-white/[0.02] p-6 transition opacity-40 hover:opacity-100 hover:border-white/20"
    : "group rounded-[1.6rem] border border-white/10 bg-white/[0.04] p-6 transition hover:border-white/18 hover:shadow-[0_20px_50px_rgba(0,0,0,0.12)]";

  return (
    <AppShell>
      <div className="space-y-6 pb-10" ref={contentRef}>
        {/* Quick metrics */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.04] p-5">
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-slate-400">Detection Layers</p>
            <p className="mt-2 text-3xl font-semibold text-white">4</p>
            <p className="mt-1 text-xs text-slate-400">S · G · T · C</p>
          </div>
          <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.04] p-5">
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-slate-400">Cloud Providers</p>
            <p className="mt-2 text-3xl font-semibold text-white">2</p>
            <p className="mt-1 text-xs text-slate-400">AWS + GCP</p>
          </div>
          <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.04] p-5">
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-slate-400">Compliance</p>
            <p className="mt-2 text-3xl font-semibold text-white">3</p>
            <p className="mt-1 text-xs text-slate-400">SOC 2 · RBI · DPDP</p>
          </div>
          <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.04] p-5">
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-slate-400">Risk Formula</p>
            <p className="mt-2 text-3xl font-semibold text-white">SGTC</p>
            <p className="mt-1 text-xs text-slate-400">Hybrid quadratic</p>
          </div>
        </div>

        {/* Quick navigation cards */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Link
            href="/scan-wizard"
            className={scanWizardClasses}
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">Start here</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Scan Wizard</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Connect AWS or GCP → enter credentials → set scope → launch analysis.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-[var(--accent-cyan)] transition group-hover:translate-x-1">Launch wizard →</span>
          </Link>

          <Link
            href="/graph"
            className={otherOptionsClasses}
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">Visualize</p>
            <h2 className="mt-2 text-xl font-semibold text-white">IAM Graph</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Full Cytoscape.js network of users, roles, policies, and trust chains.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">Open graph →</span>
          </Link>

          <Link
            href="/findings"
            className={otherOptionsClasses}
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-magenta)]">Detect</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Findings</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Dense table of risk-scored privilege escalation paths with expandable details.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">View findings →</span>
          </Link>

          <Link
            href="/cost-matrix"
            className={otherOptionsClasses}
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-gold)]">Correlate</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Cost Matrix</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Scatter plot of cloud spend vs IAM risk. Four quadrants, one decision matrix.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">Open matrix →</span>
          </Link>

          <Link
            href="/reports"
            className={otherOptionsClasses}
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-magenta)]">Export</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Reports</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">PDF compliance reports mapped to SOC 2, RBI, and DPDP frameworks.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">Download reports →</span>
          </Link>
        </div>
      </div>
    </AppShell>
  );
}
