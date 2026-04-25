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
          <Link href="/" className="block max-w-[42rem]">
            <div className="mt-2">
              <Image
                src="/image.svg"
                alt="ExoAI logo"
                width={430}
                height={124}
                priority
                className="-ml-4 h-auto w-[290px] sm:-ml-6 sm:w-[350px] lg:-ml-8 lg:w-[430px] drop-shadow-[0_16px_38px_rgba(77,238,234,0.08)]"
              />
            </div>
            <p className="mt-0 text-[1.55rem] font-black uppercase tracking-[0.18em] text-white [text-shadow:0_0_10px_rgba(255,255,255,0.62),0_0_26px_rgba(255,255,255,0.18)] sm:text-[1.9rem] lg:text-[2.4rem]">
              AI AGENT SECURITY SCANNER
            </p>
            <p className="mt-2 max-w-[39rem] text-base leading-7 text-slate-300 sm:text-lg">
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