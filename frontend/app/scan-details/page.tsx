import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { scanDetailCards, scanModes } from "@/lib/demo-data";

export default function ScanDetailsPage() {
  const defaultMode = scanModes[0];

  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Scan details"
          title="A compact scan session view."
          description="This screen shows the current session shape, guardrails, and the nine-step timeline from module checks through compliance, remediation, and report handoff."
        />

        <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="grid gap-4">
            {scanDetailCards.map((card) => (
              <article
                key={card.label}
                className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-5 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
              >
                <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                  {card.label}
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                  {card.value}
                </h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">{card.note}</p>
              </article>
            ))}
          </div>

          <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
              Timeline
            </p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-white">
              {defaultMode.title} pipeline
            </h2>
            <div className="mt-6 space-y-4">
              {defaultMode.stepOutputs.map((item) => (
                <div
                  key={item.step}
                  className="flex gap-4 rounded-[1.4rem] border border-white/10 bg-black p-4"
                >
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-white text-sm font-semibold text-black">
                    {item.step}
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">{item.title}</h3>
                    <p className="mt-1 text-sm leading-6 text-slate-300">{item.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </section>
      </div>
    </AppShell>
  );
}