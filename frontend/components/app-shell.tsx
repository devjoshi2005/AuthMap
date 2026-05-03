import { currentUser } from "@clerk/nextjs/server";
import Link from "next/link";
import type { ReactNode } from "react";

import { AccountControls, AccountDangerZone } from "@/components/account-controls";
import { BrandLogo } from "@/components/brand-logo";
import { TopNav } from "@/components/top-nav";

type AppShellProps = {
  children: ReactNode;
};

function getAccountLabel(user: Awaited<ReturnType<typeof currentUser>>) {
  if (!user) {
    return "Operator";
  }

  return (
    user.fullName ||
    user.firstName ||
    user.username ||
    user.primaryEmailAddress?.emailAddress?.split("@")[0] ||
    "Operator"
  );
}

export async function AppShell({ children }: AppShellProps) {
  const user = await currentUser();
  const accountLabel = getAccountLabel(user);

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[92rem] flex-col px-4 py-5 sm:px-6 sm:py-6 lg:px-10">
      <header className="mb-10 rounded-[2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-5 shadow-[0_24px_60px_rgba(0,0,0,0.18)] md:p-7">
        <div className="flex flex-col gap-8 xl:flex-row xl:items-start xl:justify-between">
          <div className="mx-auto flex max-w-[42rem] flex-col items-center text-center xl:mx-0 xl:items-start xl:text-left">
            <Link href="/welcome" className="inline-flex">
              <BrandLogo linked={false} size="lg" />
            </Link>
            <p className="mt-5 font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Command surface
            </p>
            <p className="mt-3 max-w-[38rem] text-[2.2rem] font-semibold leading-[0.94] tracking-[-0.05em] text-white sm:text-[2.8rem] lg:text-[3.35rem]">
              AI agent security scanner for contained execution.
            </p>
            <p className="mt-4 max-w-[38rem] text-base leading-8 text-slate-300 sm:text-lg">
              OpenClaw powers the agent. BoxAI wraps it in a deliberate operating surface so teams can inspect exposure, triage findings, and release with one clean workflow.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-2 text-[0.72rem] font-semibold uppercase tracking-[0.18em] text-white/88 xl:justify-start">
              <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-2">Threat containment</span>
              <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-2">Readable triage</span>
              <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-2">Controlled release</span>
            </div>
          </div>
          <div className="mx-auto flex w-full max-w-[28rem] flex-col items-center space-y-4 xl:mx-0 xl:items-end">
            <div className="w-full rounded-[1.5rem] border border-white/10 bg-[rgba(255,255,255,0.03)] p-3 shadow-[0_14px_34px_rgba(0,0,0,0.14)]">
              <TopNav />
            </div>
            <AccountControls accountLabel={accountLabel} />
          </div>
        </div>
      </header>
      <div className="flex-1">{children}</div>
      <footer className="mt-12 border-t border-white/10 pt-6">
        <div className="grid gap-6 pb-6 text-center sm:grid-cols-2 xl:grid-cols-[1.3fr_0.7fr_0.7fr] xl:text-left">
          <div className="mx-auto max-w-2xl xl:mx-0">
            <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Workspace information
            </p>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              BoxAI keeps the analyst workflow in one interface: capture inputs, inspect the staged pipeline, review findings, and move toward reporting without leaving the contained shell.
            </p>
          </div>
          <div>
            <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Session state
            </p>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              Drafts are retained locally per signed-in account in this browser for the frontend demo experience.
            </p>
          </div>
          <div>
            <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Scope
            </p>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              This environment demonstrates the product shell, auth flow, and operator review path without backend persistence.
            </p>
          </div>
        </div>
        <AccountDangerZone />
      </footer>
    </div>
  );
}