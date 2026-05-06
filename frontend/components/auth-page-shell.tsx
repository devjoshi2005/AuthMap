import Link from "next/link";
import type { ReactNode } from "react";

import { BrandLogo } from "@/components/brand-logo";
import { DeferredPrism } from "@/components/deferred-prism";

type AuthPageShellProps = {
  title: string;
  description: string;
  children: ReactNode;
  alternateHref: string;
  alternateLabel: string;
};

export function AuthPageShell({
  title,
  description,
  children,
  alternateHref,
  alternateLabel,
}: AuthPageShellProps) {
  return (
    <main className="relative min-h-screen overflow-hidden text-white">
      <div className="absolute inset-0 opacity-35">
        <DeferredPrism
          animationType="3drotate"
          timeScale={0.24}
          height={3.2}
          baseWidth={4.5}
          scale={3.05}
          hueShift={0.04}
          colorFrequency={1.15}
          noise={0.04}
          glow={0.85}
          bloom={0.84}
          maxDpr={1}
          steps={48}
          targetFps={30}
          suspendWhenOffscreen
        />
      </div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_14%_14%,rgba(158,193,182,0.12),transparent_22%),radial-gradient(circle_at_84%_18%,rgba(203,142,119,0.12),transparent_20%),linear-gradient(180deg,rgba(13,16,21,0.84),rgba(13,16,21,0.98))]" />
      <section className="relative z-[1] mx-auto flex min-h-screen w-full max-w-7xl flex-col justify-center px-4 py-8 sm:px-8 sm:py-10 lg:px-12">
        <div className="grid gap-8 xl:grid-cols-[1.02fr_0.98fr] xl:items-center">
          <div className="flex flex-col items-center space-y-6 text-center xl:items-start xl:text-left">
            <BrandLogo size="lg" />
            <div className="space-y-4">
              <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-[var(--accent-cyan)]">
                Protected access
              </p>
              <h1 className="max-w-2xl text-4xl font-semibold leading-[0.96] tracking-[-0.05em] text-white sm:text-5xl lg:text-[4.15rem] xl:max-w-[38rem]">
                {title}
              </h1>
              <p className="max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
                {description}
              </p>
            </div>
            <div className="grid w-full gap-3 sm:grid-cols-3">
              <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-4">
                <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] uppercase tracking-[0.24em] text-slate-400">Access</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">Identity first before entering the analyst workspace.</p>
              </div>
              <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-4">
                <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] uppercase tracking-[0.24em] text-slate-400">Review</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">Continue into scans, findings, and reports from one shell.</p>
              </div>
              <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-4">
                <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] uppercase tracking-[0.24em] text-slate-400">Retention</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">Your demo workspace state remains tied to your signed-in account.</p>
              </div>
            </div>
          </div>

          <div className="mx-auto flex w-full max-w-xl flex-col items-center xl:mx-0 xl:items-start">
            <div className="w-full max-w-md">
              {children}
            </div>
            <div className="mt-6 text-center text-sm text-slate-300 xl:text-left">
              <Link
                href={alternateHref}
                prefetch={false}
                className="text-[var(--accent-cyan)] hover:text-white"
              >
                {alternateLabel}
              </Link>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}