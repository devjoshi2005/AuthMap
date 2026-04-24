"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { navigationItems } from "@/lib/demo-data";

export function TopNav() {
  const pathname = usePathname();

  return (
    <nav className="overflow-x-auto">
      <div className="flex min-w-max items-center gap-6 border-b border-white/10 pb-1">
      {navigationItems.map((item) => {
        const isActive = pathname === item.href;

        return (
          <Link
            key={item.href}
            href={item.href}
            className={`nav-link px-1 pb-3 pt-1 text-sm font-medium whitespace-nowrap transition-colors ${
              isActive
                ? "is-active text-white"
                : "border-transparent text-slate-400 hover:text-slate-100"
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