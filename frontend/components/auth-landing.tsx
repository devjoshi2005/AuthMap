"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";

import { BrandLogo } from "@/components/brand-logo";
import { GridScan } from "@/components/grid-scan";

type AuthLandingProps = {
  isSignedIn?: boolean;
};

export function AuthLanding({ isSignedIn = false }: AuthLandingProps) {
  const { userId } = useAuth();
  const effectiveIsSignedIn = isSignedIn || Boolean(userId);
  const signInHref = effectiveIsSignedIn ? "/" : "/sign-in";
  const signUpHref = effectiveIsSignedIn ? "/" : "/sign-up";
  const heroHref = effectiveIsSignedIn ? "/" : "/sign-up";

  return (
    <main className="relative flex min-h-screen flex-col overflow-hidden text-white bg-[rgba(13,16,21,1)]">
      {/* Animated background layers */}
      <div className="pointer-events-none absolute inset-0 opacity-100 mix-blend-screen">
        <GridScan
          sensitivity={0.55}
          lineThickness={1}
          linesColor="#94a3b8"
          gridScale={0.1}
          scanColor="#cbd5e1"
          scanOpacity={0.4}
          enablePost={true}
          bloomIntensity={0.6}
          chromaticAberration={0.001}
          noiseIntensity={0.01}
        />
      </div>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_14%,rgba(158,193,182,0.16),transparent_22%),radial-gradient(circle_at_82%_20%,rgba(203,142,119,0.15),transparent_20%),radial-gradient(circle_at_50%_38%,rgba(255,255,255,0.08),transparent_28%),linear-gradient(180deg,rgba(13,16,21,0.72),rgba(13,16,21,0.94))]" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_55%,rgba(255,255,255,0.03),transparent_32%)] mix-blend-screen opacity-80" />

      {/* Main wrapper for absolute vertical centering */}
      <div className="relative z-[1] flex flex-1 flex-col justify-center px-4 py-12 sm:px-8 lg:px-12">
        <div className="mx-auto w-full max-w-7xl">
          <div className="grid gap-12 lg:grid-cols-[1.1fr_0.9fr] lg:items-center xl:gap-20">
            
            {/* ─── LEFT COLUMN: Critical Info & Hero ─── */}
            <div className="flex flex-col items-center space-y-8 text-center lg:items-start lg:text-left">
              <div className="mb-2">
                <BrandLogo size="xl" />
              </div>

              <div className="space-y-4">
                <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">
                  IAM Attack Path Analyzer
                </p>
                <h1 className="auth-title-glow max-w-2xl text-5xl font-semibold leading-[0.92] tracking-[-0.05em] sm:text-6xl lg:text-[4.8rem]">
                  Map the invisible.
                </h1>
                <p className="max-w-xl text-lg leading-8 text-slate-300">
                  See every privilege escalation path across AWS &amp; GCP before attackers do. AuthMap ingests your cloud configurations to build a live relationship graph—exposing critical vulnerabilities and mapping risky permissions to your exact cloud costs.
                </p>
              </div>

              {/* Added critical info layout matching user preference */}
              <div className="grid w-full gap-4 sm:grid-cols-2 lg:max-w-2xl">
                <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-5 text-left transition hover:bg-white/[0.05]">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">Graph Engine</p>
                  <p className="mt-2 text-sm leading-6 text-slate-300">Interactive Neo4j &amp; Cytoscape.js network visualizing every IAM entity and trust chain.</p>
                </div>
                <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-5 text-left transition hover:bg-white/[0.05]">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-magenta)]">Priv-Esc Detection</p>
                  <p className="mt-2 text-sm leading-6 text-slate-300">4-layer analysis (Static, Graph, Temporal, Cost) feeding a hybrid quadratic risk score.</p>
                </div>
                <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-5 text-left transition hover:bg-white/[0.05] sm:col-span-2">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.62rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-gold)]">Cost × Risk Correlation</p>
                  <p className="mt-2 text-sm leading-6 text-slate-300">Scatter plot your cloud spend against IAM risk. Instantly locate resources that are burning budget AND exposing critical attack surface.</p>
                </div>
              </div>
            </div>

            {/* ─── RIGHT COLUMN: Auth Box ─── */}
            <div className="mx-auto flex w-full max-w-md flex-col items-center lg:mx-0 lg:max-w-none lg:items-end">
              <div className="w-full max-w-md rounded-[2.5rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.01))] p-8 shadow-[0_20px_60px_rgba(0,0,0,0.3)] sm:p-10">
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">
                  Access Portal
                </p>
                <h2 className="mt-4 text-3xl font-semibold text-white">
                  {effectiveIsSignedIn ? "Welcome back." : "Start mapping."}
                </h2>
                <p className="mt-3 text-base leading-7 text-slate-300">
                  {effectiveIsSignedIn
                    ? "Your analysis workspace is active. Resume your session."
                    : "Create an account to scan your cloud environment and generate compliance-ready reports."}
                </p>
                <div className="mt-8 flex flex-col gap-4">
                  <Link
                    href={heroHref}
                    prefetch={false}
                    className="action-box action-box-cyan flex w-full items-center justify-center px-6 py-4 text-sm font-semibold uppercase tracking-[0.18em] text-white transition-transform hover:scale-[1.02]"
                  >
                    {effectiveIsSignedIn ? "Open Console" : "Sign Up Free"}
                  </Link>
                  <Link
                    href={signInHref}
                    prefetch={false}
                    className="action-box action-box-ghost flex w-full items-center justify-center px-6 py-4 text-sm font-semibold uppercase tracking-[0.18em] text-white transition-transform hover:scale-[1.02]"
                  >
                    {effectiveIsSignedIn ? "Dashboard" : "Sign In"}
                  </Link>
                </div>

                <div className="mt-10 pt-8 border-t border-white/10">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] uppercase tracking-[0.2em] text-slate-400">Security Scope</p>
                  <ul className="mt-3 space-y-2 text-sm text-slate-300">
                    <li className="flex items-center gap-2">
                      <span className="text-[var(--accent-cyan)]">✓</span> SOC 2 &amp; RBI compliance
                    </li>
                    <li className="flex items-center gap-2">
                      <span className="text-[var(--accent-cyan)]">✓</span> Zero agents required
                    </li>
                    <li className="flex items-center gap-2">
                      <span className="text-[var(--accent-cyan)]">✓</span> In-browser graph rendering
                    </li>
                  </ul>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>

      <footer className="relative z-[1] w-full pb-6 text-center">
        <p className="text-[0.7rem] uppercase tracking-widest text-slate-500">AuthMap — IAM Attack Path Analyzer with Cloud Cost Security</p>
      </footer>
    </main>
  );
}