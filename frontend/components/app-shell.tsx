import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";

import { TopNav } from "@/components/top-nav";

type AppShellProps = {
  children: ReactNode;
};

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col px-6 py-6 sm:px-10 lg:px-12">
      <header className="mb-12 border-b border-white/10 pb-7">
        <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <Link href="/" className="block max-w-4xl">
            <div className="mt-3">
              <Image
                src="/image.svg"
                alt="ExoAI logo"
                width={360}
                height={104}
                priority
                className="-ml-3 h-auto w-[238px] sm:-ml-5 sm:w-[300px] lg:-ml-7 lg:w-[360px] drop-shadow-[0_16px_38px_rgba(77,238,234,0.08)]"
              />
            </div>
            <p className="mt-2 text-[1.45rem] font-black uppercase tracking-[0.24em] text-white [text-shadow:0_0_10px_rgba(255,255,255,0.62),0_0_26px_rgba(255,255,255,0.18)] sm:text-[1.75rem] lg:text-[2.2rem]">
              AI AGENT SECURITY SCANNER
            </p>
            <p className="mt-3 max-w-3xl text-base leading-7 text-slate-300 sm:text-lg">
              OpenClaw powers the agent. ExoAI adds the <span className="text-[var(--accent-gold)] uppercase">exoskeleton</span> around it,
              so teams can inspect risk, harden behavior, and review findings in
              one controlled workflow.
            </p>
            <div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-xs font-bold uppercase tracking-[0.24em] text-white">
              <span>Signal visibility</span>
              <span>Fast risk triage</span>
              <span>Guided hardening</span>
            </div>
          </Link>
          <TopNav />
        </div>
      </header>
      <div className="flex-1">{children}</div>
    </div>
  );
}