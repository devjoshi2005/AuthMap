import { auth } from "@clerk/nextjs/server";
import Link from "next/link";

import { AppShell } from "../components/app-shell";
import { AuthLanding } from "../components/auth-landing";

export default async function Home() {
  const { userId } = await auth();

  if (!userId) {
    return <AuthLanding isSignedIn={false} />;
  }

  return (
    <AppShell>
      <div className="space-y-6 pb-10">
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
            className="group rounded-[1.6rem] border border-[var(--accent-cyan)]/30 bg-[linear-gradient(180deg,rgba(158,193,182,0.08),rgba(255,255,255,0.02))] p-6 transition hover:border-[var(--accent-cyan)]/50 hover:shadow-[0_20px_50px_rgba(158,193,182,0.08)]"
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">Start here</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Scan Wizard</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Connect AWS or GCP → enter credentials → set scope → launch analysis.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-[var(--accent-cyan)] transition group-hover:translate-x-1">Launch wizard →</span>
          </Link>

          <Link
            href="/graph"
            className="group rounded-[1.6rem] border border-white/10 bg-white/[0.04] p-6 transition hover:border-white/18 hover:shadow-[0_20px_50px_rgba(0,0,0,0.12)]"
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">Visualize</p>
            <h2 className="mt-2 text-xl font-semibold text-white">IAM Graph</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Full Cytoscape.js network of users, roles, policies, and trust chains.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">Open graph →</span>
          </Link>

          <Link
            href="/findings"
            className="group rounded-[1.6rem] border border-white/10 bg-white/[0.04] p-6 transition hover:border-white/18 hover:shadow-[0_20px_50px_rgba(0,0,0,0.12)]"
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-magenta)]">Detect</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Findings</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Dense table of risk-scored privilege escalation paths with expandable details.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">View findings →</span>
          </Link>

          <Link
            href="/cost-matrix"
            className="group rounded-[1.6rem] border border-white/10 bg-white/[0.04] p-6 transition hover:border-white/18 hover:shadow-[0_20px_50px_rgba(0,0,0,0.12)]"
          >
            <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-gold)]">Correlate</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Cost Matrix</h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">Scatter plot of cloud spend vs IAM risk. Four quadrants, one decision matrix.</p>
            <span className="mt-3 inline-block text-sm font-semibold text-slate-400 transition group-hover:translate-x-1 group-hover:text-white">Open matrix →</span>
          </Link>

          <Link
            href="/reports"
            className="group rounded-[1.6rem] border border-white/10 bg-white/[0.04] p-6 transition hover:border-white/18 hover:shadow-[0_20px_50px_rgba(0,0,0,0.12)]"
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
