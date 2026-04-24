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
    <section className="grid gap-8 border-b border-white/10 pb-8 md:pb-10 lg:grid-cols-[1.2fr_0.8fr] lg:items-end">
      <div>
        <p className="text-sm font-semibold uppercase tracking-[0.28em] text-slate-400">
          {eyebrow}
        </p>
        <h1 className="mt-3 max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          {title}
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-7 text-slate-300 sm:text-lg">
          {description}
        </p>
      </div>
      {aside ? <div className="hero-spectrum">{aside}</div> : null}
    </section>
  );
}