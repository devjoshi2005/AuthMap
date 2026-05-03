"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { navigationItems } from "@/lib/demo-data";

export function TopNav() {
  const pathname = usePathname();

  return (
    <nav className="no-scrollbar w-full overflow-x-auto overscroll-x-contain [scrollbar-width:none] [-ms-overflow-style:none]">
      <div className="flex min-w-max snap-x snap-mandatory items-center gap-2 px-1 py-1">
      {navigationItems.map((item) => {
        const isActive = pathname === item.href;

        return (
          <Link
            key={item.href}
            href={item.href}
            className={`nav-link snap-start px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] whitespace-nowrap transition-colors ${
              isActive
                ? "is-active"
                : "text-slate-400 hover:border-white/16 hover:bg-white/[0.04] hover:text-slate-100"
            }`}
          >
            {item.label}
          </Link>
        );
      })}
      </div>
    </nav>
  );
}