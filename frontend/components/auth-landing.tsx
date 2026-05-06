"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";

import { BrandLogo } from "@/components/brand-logo";
import { DeferredPrism } from "@/components/deferred-prism";

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
    <main className="relative min-h-screen overflow-hidden text-white">
      <div className="pointer-events-none absolute inset-0 opacity-65">
        <DeferredPrism
          animationType="rotate"
          timeScale={0.24}
          height={3.35}
          baseWidth={4.45}
          scale={3.18}
          hueShift={0.12}
          colorFrequency={1.08}
          noise={0.04}
          glow={0.92}
          bloom={0.88}
          maxDpr={1}
          steps={48}
          targetFps={30}
          suspendWhenOffscreen
        />
      </div>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_14%,rgba(158,193,182,0.16),transparent_22%),radial-gradient(circle_at_82%_20%,rgba(203,142,119,0.15),transparent_20%),radial-gradient(circle_at_50%_38%,rgba(255,255,255,0.08),transparent_28%),linear-gradient(180deg,rgba(13,16,21,0.72),rgba(13,16,21,0.94))]" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_55%,rgba(255,255,255,0.03),transparent_32%)] mix-blend-screen opacity-80" />
      <section className="relative z-[1] mx-auto flex min-h-screen w-full max-w-7xl flex-col px-4 py-5 sm:px-8 sm:py-6 lg:px-12">
        <nav className="mb-10 flex flex-col items-center justify-center gap-4 rounded-[2rem] border border-white/12 bg-[linear-gradient(180deg,rgba(8,10,14,0.96),rgba(13,16,21,0.92))] px-4 py-4 text-center shadow-[0_28px_72px_rgba(0,0,0,0.26)] sm:mb-12 sm:flex-row sm:justify-between sm:px-5 sm:py-3 sm:text-left">
          <BrandLogo compact className="shrink-0 scale-[1.04] origin-center" />
          <div className="flex flex-wrap items-center justify-center gap-3 rounded-[1.2rem] border border-white/8 bg-white/[0.03] p-1.5 sm:justify-end">
            <Link
              href={signInHref}
              prefetch={false}
              className="inline-flex items-stretch overflow-hidden rounded-[0.95rem] uppercase leading-none shadow-[0_10px_24px_rgba(0,0,0,0.22)] transition-transform hover:-translate-y-0.5"
            >
              <span
                className="bg-white px-3 py-2 text-[0.78rem] font-black tracking-[-0.04em] text-[#0a0a0a]"
                style={{ fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif' }}
              >
                SIGN
              </span>
              <span
                className="bg-[#0d1025] px-2.5 py-2 text-[0.78rem] font-black tracking-[-0.04em] text-white"
                style={{ fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif' }}
              >
                IN
              </span>
            </Link>
            <Link
              href={signUpHref}
              prefetch={false}
              className="inline-flex items-stretch overflow-hidden rounded-[0.95rem] uppercase leading-none shadow-[0_10px_24px_rgba(0,0,0,0.22)] transition-transform hover:-translate-y-0.5"
            >
              <span
                className="bg-white px-3 py-2 text-[0.78rem] font-black tracking-[-0.04em] text-[#0a0a0a]"
                style={{ fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif' }}
              >
                SIGN
              </span>
              <span
                className="bg-[#0d1025] px-2.5 py-2 text-[0.78rem] font-black tracking-[-0.04em] text-white"
                style={{ fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif' }}
              >
                UP
              </span>
            </Link>
          </div>
        </nav>

        <div className="flex flex-1 items-center">
          <div className="grid w-full gap-8 xl:grid-cols-[1.08fr_0.92fr] xl:items-end">
            <div className="flex flex-col items-center space-y-7 text-center xl:items-start xl:text-left">
              <div className="max-w-4xl space-y-5 xl:max-w-[52rem]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">
                  AI Agent Security Scanner
                </p>
                <h1 className="auth-title-glow max-w-4xl text-4xl font-semibold leading-[0.92] tracking-[-0.06em] sm:text-5xl lg:text-[5.1rem]">
                  Minimal control for agent risk, review, and release.
                </h1>
                <p className="max-w-3xl text-base leading-8 text-slate-300 sm:text-lg">
                  BoxAI gives teams a calm front door for scan review, remediation, and controlled release. Sign in to enter the secured workspace and move through the full analyst path without visual clutter.
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 xl:justify-start">
                <Link
                  href={heroHref}
                  prefetch={false}
                  className="action-box action-box-cyan min-w-[12rem] px-5 py-3 text-sm font-semibold uppercase tracking-[0.18em] text-white"
                >
                  {effectiveIsSignedIn ? "Return Home" : "Enter Workspace"}
                </Link>          
              </div>

              <div className="flex flex-wrap justify-center gap-2 text-[0.72rem] font-semibold uppercase tracking-[0.18em] text-white/86 xl:justify-start">
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-2">Threat containment</span>
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-2">Operator sign-off</span>
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-2">Controlled release</span>
              </div>
            </div>

            <div className="mx-auto grid w-full max-w-xl gap-4 md:grid-cols-3 xl:mx-0 xl:max-w-none xl:grid-cols-1">
              <article className="rounded-[1.8rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_18px_44px_rgba(0,0,0,0.16)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.66rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">Identity first</p>
                <h2 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-white">Verified access</h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">Every analyst session starts behind account verification before scan details or findings become visible.</p>
              </article>
              <article className="rounded-[1.8rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_18px_44px_rgba(0,0,0,0.16)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.66rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-magenta)]">Readable flow</p>
                <h2 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-white">One operating surface</h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">Inputs, scan details, findings, and reports stay inside one minimal shell instead of breaking into disconnected screens.</p>
              </article>
              <article className="rounded-[1.8rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_18px_44px_rgba(0,0,0,0.16)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.66rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-gold)]">Per-user state</p>
                <h2 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-white">Return where you left off</h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">Demo drafts persist per signed-in account in this browser, so the workspace feels continuous across sessions.</p>
              </article>
            </div>
          </div>
        </div>

        <footer className="mt-10 border-t border-white/10 pt-6">
          <div className="grid gap-6 text-center sm:grid-cols-2 lg:grid-cols-[1.2fr_0.8fr_0.8fr] lg:text-left">
            <div className="mx-auto max-w-2xl lg:mx-0">
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                BoxAI overview
              </p>
              <p className="mt-3 text-sm leading-7 text-slate-300">
                Frontend-only AI agent security scanner demo with protected access, readable scan flow, and controlled report review inside one product shell.
              </p>
            </div>
            <div>
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                Product
              </p>
              <p className="mt-3 text-sm leading-7 text-slate-300">
                Intake modes, scan details, findings, and reports tuned for fast analyst review.
              </p>
            </div>
            <div>
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                Access
              </p>
              <p className="mt-3 text-sm leading-7 text-slate-300">
                Sign in or create an account to enter the contained workspace and retain local demo state per user.
              </p>
            </div>
          </div>
        </footer>
      </section>
    </main>
  );
}