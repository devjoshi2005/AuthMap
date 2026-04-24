import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { reportSections } from "@/lib/demo-data";

export default function ReportsPage() {
  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Reports"
          title="Report structure ready for backend data."
          description="This screen is the simplified report destination: executive summary, evidence space, and recommended actions with a clear reading order."
        />

        <section className="grid gap-5 lg:grid-cols-3">
          {reportSections.map((section) => (
            <article
              key={section.title}
              className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
            >
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                {section.title}
              </p>
              <p className="mt-4 text-sm leading-7 text-slate-300">{section.body}</p>
            </article>
          ))}
        </section>

        <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 text-slate-100 shadow-[0_20px_60px_rgba(0,0,0,0.24)]">
          <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-300">
            Status
          </p>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight text-white">
            Frontend complete, data layer pending.
          </h2>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-200">
            The UI now has a dedicated report destination, but all values remain demo-only until the backend scan pipeline is connected.
          </p>
        </section>
      </div>
    </AppShell>
  );
}