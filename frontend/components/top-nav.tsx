"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { navigationItems } from "@/lib/demo-data";

export function TopNav() {
  const pathname = usePathname();
  const scrollRef = useRef<HTMLElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  useEffect(() => {
    const node = scrollRef.current;

    if (!node) {
      return;
    }

    function updateScrollState() {
      const currentNode = scrollRef.current;

      if (!currentNode) {
        return;
      }

      const maxScrollLeft = currentNode.scrollWidth - currentNode.clientWidth;

      setCanScrollLeft(currentNode.scrollLeft > 4);
      setCanScrollRight(maxScrollLeft - currentNode.scrollLeft > 4);
    }

    updateScrollState();

    node.addEventListener("scroll", updateScrollState, { passive: true });
    window.addEventListener("resize", updateScrollState);

    return () => {
      node.removeEventListener("scroll", updateScrollState);
      window.removeEventListener("resize", updateScrollState);
    };
  }, [pathname]);

  function scrollByOffset(offset: number) {
    scrollRef.current?.scrollBy({ left: offset, behavior: "smooth" });
  }

  function handleWheel(event: React.WheelEvent<HTMLElement>) {
    const node = scrollRef.current;

    if (!node) {
      return;
    }

    if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) {
      return;
    }

    event.preventDefault();
    node.scrollBy({ left: event.deltaY, behavior: "auto" });
  }

  return (
    <div className="space-y-2">
      <div className="relative flex items-center gap-2">
        <button
          type="button"
          aria-label="Scroll navigation left"
          onClick={() => scrollByOffset(-220)}
          disabled={!canScrollLeft}
          className={`hidden h-9 w-9 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-sm text-white transition md:inline-flex ${
            canScrollLeft ? "hover:bg-white/[0.08]" : "cursor-default opacity-35"
          }`}
        >
          ←
        </button>

        <nav
          ref={scrollRef}
          onWheel={handleWheel}
          className="no-scrollbar w-full overflow-x-auto overscroll-x-contain scroll-smooth [scrollbar-width:none] [-ms-overflow-style:none] [touch-action:pan-x]"
        >
          <div className="flex min-w-max snap-x snap-mandatory items-center gap-2 px-1 py-1">
            {navigationItems.map((item) => {
              const isActive = pathname === item.href;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`nav-link snap-start whitespace-nowrap px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] transition-colors ${
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

        <button
          type="button"
          aria-label="Scroll navigation right"
          onClick={() => scrollByOffset(220)}
          disabled={!canScrollRight}
          className={`hidden h-9 w-9 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-sm text-white transition md:inline-flex ${
            canScrollRight ? "hover:bg-white/[0.08]" : "cursor-default opacity-35"
          }`}
        >
          →
        </button>
      </div>
      <p className="px-1 text-[0.68rem] uppercase tracking-[0.18em] text-slate-500 md:hidden">
        Swipe left or right for more
      </p>
    </div>
  );
}