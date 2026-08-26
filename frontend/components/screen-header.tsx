import type { ReactNode } from "react";

type ScreenHeaderProps = {
  eyebrow: ReactNode;
  title: ReactNode;
  description: ReactNode;
  aside?: ReactNode;
};

export function ScreenHeader({
  eyebrow,
  title,
  description,
  aside,
}: ScreenHeaderProps) {
  return (
    <section className="grid gap-8 rounded-[2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_50px_rgba(0,0,0,0.18)] md:p-8 lg:grid-cols-[1.18fr_0.82fr] lg:items-end">
      <div className="mx-auto w-full max-w-3xl text-center lg:mx-0 lg:max-w-none lg:text-left">
        <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
          {eyebrow}
        </p>
        <h1 className="mt-4 max-w-3xl text-4xl font-semibold tracking-[-0.04em] text-white sm:text-5xl lg:text-[3.9rem]">
          {title}
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
          {description}
        </p>
      </div>
      {aside ? <div className="hero-spectrum mx-auto w-full max-w-xl lg:mx-0 lg:max-w-none lg:pl-8">{aside}</div> : null}
    </section>
  );
}
