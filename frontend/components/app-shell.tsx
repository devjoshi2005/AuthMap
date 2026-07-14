"use client";

import { useUser, useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { AccountControls, AccountDangerZone } from "@/components/account-controls";
import { BrandLogo } from "@/components/brand-logo";
import { TopNav } from "@/components/top-nav";

type AppShellProps = {
  children: ReactNode;
};

type UserResource = ReturnType<typeof useUser>['user'];

function getAccountLabel(user: UserResource) {
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

export function AppShell({ children }: AppShellProps) {
  const { user } = useUser();
  const { isLoaded, userId } = useAuth();
  const router = useRouter();
  
  useEffect(() => {
    if (isLoaded && !userId) {
      router.replace("/");
    }
  }, [isLoaded, userId, router]);

  if (isLoaded && !userId) {
    return null;
  }

  const accountLabel = getAccountLabel(user);

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[92rem] flex-col px-4 py-5 sm:px-6 sm:py-6 lg:px-10">
      <header className="mb-10 rounded-[2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-5 shadow-[0_24px_60px_rgba(0,0,0,0.18)] md:p-7">
        <div className="flex flex-col gap-8 xl:flex-row xl:items-start xl:justify-between">
          <div className="mx-auto flex max-w-[42rem] flex-col items-center text-center xl:mx-0 xl:items-start xl:text-left">
            <Link href="/welcome" className="inline-flex">
              <BrandLogo linked={false} size="lg" />
            </Link>
            <p className="mt-4 font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Security console
            </p>
            <p className="mt-2 max-w-[36rem] text-[1.8rem] font-semibold leading-[0.96] tracking-[-0.04em] text-white sm:text-[2.2rem] lg:text-[2.6rem]">
              IAM attack path analyzer for AWS & GCP.
            </p>
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
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6">
          <p className="text-sm text-slate-400">
            AuthMap — IAM attack path analyzer · AWS + GCP · SOC 2 · RBI · DPDP
          </p>
          <p className="text-xs text-slate-500">
            Session data persists per signed-in account.
          </p>
        </div>
        <AccountDangerZone />
      </footer>
    </div>
  );
}