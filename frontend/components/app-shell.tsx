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
                alt="BoxAI logo"
                width={567}
                height={258}
                priority
                className="-ml-8 h-auto w-[350px] sm:-ml-10 sm:w-[430px] lg:-ml-12 lg:w-[505px] drop-shadow-[0_16px_38px_rgba(62,233,233,0.07)]"
              />
            </div>
            <p className="mt-[-0.35rem] text-[1.55rem] font-black uppercase tracking-[0.18em] text-white [text-shadow:0_0_10px_rgba(255,255,255,0.62),0_0_26px_rgba(255,255,255,0.18)] sm:text-[1.9rem] lg:text-[2.4rem]">
              AI AGENT SECURITY SCANNER
            </p>
            <p className="mt-2 max-w-[39rem] text-base leading-7 text-slate-300 sm:text-lg">
              OpenClaw powers the agent. BoxAI seals it inside a <span className="text-[var(--accent-gold)] uppercase">containment boundary</span>,
              so teams can isolate risky behavior, inspect exposure, and ship with
              one controlled workflow.
            </p>
            <div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-xs font-bold uppercase tracking-[0.24em] text-white">
              <span>Threat containment</span>
              <span>Fast risk triage</span>
              <span>Controlled release</span>
            </div>
          </Link>
          <TopNav />
        </div>
      </header>
      <div className="flex-1">{children}</div>
    </div>
  );
}