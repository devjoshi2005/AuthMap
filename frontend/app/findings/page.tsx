import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { findingsSummary, moduleLabels } from "@/lib/demo-data";

export default function FindingsPage() {
  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Findings"
          title="Frontend findings view for analyst review."
          description="This page keeps the findings layer concise: severity, module coverage, and the short explanation that an operator needs before opening a full report."
        />

        <section className="grid gap-5 lg:grid-cols-3">
          {findingsSummary.map((item) => (
            <article
              key={item.title}
              className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
            >
              <span className="rounded-full border border-white/10 bg-black px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-white">
                {item.severity}
              </span>
              <h2 className="mt-4 text-2xl font-semibold tracking-tight text-white">
                {item.title}
              </h2>
              <p className="mt-3 text-sm leading-7 text-slate-300">{item.summary}</p>
            </article>
          ))}
        </section>

        <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
          <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
            Covered modules
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            {moduleLabels.map((label) => (
              <span
                key={label}
                className="rounded-full border border-white/10 bg-black px-4 py-2 text-sm font-medium text-white"
              >
                {label}
              </span>
            ))}
          </div>
        </section>
      </div>
    </AppShell>
  );
}