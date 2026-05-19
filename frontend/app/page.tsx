import { auth } from "@clerk/nextjs/server";

import { AppShell } from "../components/app-shell";
import { AuthLanding } from "../components/auth-landing";
import { ModeWorkspace } from "../components/mode-workspace";
import { ScreenHeader } from "../components/screen-header";

export default async function Home() {
  const { userId } = await auth();

  if (!userId) {
    return <AuthLanding isSignedIn={false} />;
  }

  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow={
            <>
              <span className="text-[var(--accent-cyan)]">Frontend Overview</span>
            </>
          }
          title="BoxAI turns agent defense into one sealed operating surface."
          description={
            <>
              Start with the input that matches your OpenClaw setup, watch the
              security modules unfold in a readable sequence, and move straight
              into <span className="text-[var(--accent-magenta)]">remediation</span>{" "}
              and <span className="text-[var(--accent-magenta)]">report</span>{" "} views before anything leaves the box.
            </>
          }
          aside={
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="metric-rail metric-cyan pl-4">
                <p className="text-sm text-slate-400">Input types</p>
                <p className="mt-2 text-3xl font-semibold text-white">4</p>
              </div>
              <div className="metric-rail metric-gold pl-4">
                <p className="text-sm text-slate-400">Pipeline steps</p>
                <p className="mt-2 text-3xl font-semibold text-white">7</p>
              </div>
            </div>
          }
        />
        <div className="flex justify-center pt-1">
          <a
            href="#intake-workspace"
            aria-label="Jump to input workspace"
            className="action-box action-box-ghost group inline-flex h-14 w-14 items-center justify-center rounded-[1rem] text-white"
          >
            <span className="arrow-jump text-2xl leading-none transition group-hover:translate-y-1">
              ↓
            </span>
          </a>
        </div>
        <ModeWorkspace />
      </div>
    </AppShell>
  );
}
