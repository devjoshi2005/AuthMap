"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import "./gooey-nav.css";

import { navigationItems } from "@/lib/scan-data";

export function TopNav() {
  const pathname = usePathname();
  const scrollRef = useRef<HTMLElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const filterRef = useRef<HTMLSpanElement>(null);
  const linkRefs = useRef<Record<string, HTMLAnchorElement | null>>({});
  
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return;

    function updateScrollState() {
      const currentNode = scrollRef.current;
      if (!currentNode) return;
      const maxScrollLeft = currentNode.scrollWidth - currentNode.clientWidth;
      setCanScrollLeft(currentNode.scrollLeft > 4);
      setCanScrollRight(maxScrollLeft - currentNode.scrollLeft > 4);
    }
    
    // Restore scroll position
    const savedScroll = sessionStorage.getItem("topnav-scroll");
    if (savedScroll) {
      node.scrollLeft = parseInt(savedScroll, 10);
    }
    
    updateScrollState();
    
    function handleScroll() {
      if (scrollRef.current) {
        sessionStorage.setItem("topnav-scroll", scrollRef.current.scrollLeft.toString());
      }
      updateScrollState();
    }

    node.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("resize", updateScrollState);
    return () => {
      node.removeEventListener("scroll", handleScroll);
      window.removeEventListener("resize", updateScrollState);
    };
  }, [pathname]);

  const noise = (n = 1) => n / 2 - Math.random() * n;
  
  useEffect(() => {
    const activeEl = linkRefs.current[pathname];
    if (!containerRef.current || !filterRef.current || !activeEl) return;
    
    const updateEffectPosition = () => {
      const containerRect = containerRef.current!.getBoundingClientRect();
      const pos = activeEl.getBoundingClientRect();
      const scrollLeft = scrollRef.current?.scrollLeft || 0;
      
      const styles = {
        left: `${pos.x - containerRect.x + scrollLeft}px`,
        top: `${pos.y - containerRect.y}px`,
        width: `${pos.width}px`,
        height: `${pos.height}px`
      };
      Object.assign(filterRef.current!.style, styles);
    };

    updateEffectPosition();

    const d = [90, 10];
    const r = 100;
    const animationTime = 600;
    const timeVariance = 300;
    const bubbleTime = animationTime * 2 + timeVariance;
    
    const element = filterRef.current;
    element.style.setProperty('--time', `${bubbleTime}ms`);

    const particles = element.querySelectorAll('.gooey-particle');
    particles.forEach(p => element.removeChild(p));

    const getXY = (distance: number, pointIndex: number, totalPoints: number) => {
      const angle = ((360 + noise(8)) / totalPoints) * pointIndex * (Math.PI / 180);
      return [distance * Math.cos(angle), distance * Math.sin(angle)];
    };

    for (let i = 0; i < 15; i++) {
      const t = animationTime * 2 + noise(timeVariance * 2);
      let rotate = noise(r / 10);
      const start = getXY(d[0], 15 - i, 15);
      const end = getXY(d[1] + noise(7), 15 - i, 15);
      const scale = 1 + noise(0.2);
      const rotFinal = rotate > 0 ? (rotate + r / 20) * 10 : (rotate - r / 20) * 10;

      element.classList.remove('active');

      setTimeout(() => {
        const particle = document.createElement('span');
        const point = document.createElement('span');
        particle.classList.add('gooey-particle');
        particle.style.setProperty('--start-x', `${start[0]}px`);
        particle.style.setProperty('--start-y', `${start[1]}px`);
        particle.style.setProperty('--end-x', `${end[0]}px`);
        particle.style.setProperty('--end-y', `${end[1]}px`);
        particle.style.setProperty('--time', `${t}ms`);
        particle.style.setProperty('--scale', `${scale}`);
        particle.style.setProperty('--rotate', `${rotFinal}deg`);

        point.classList.add('gooey-point');
        particle.appendChild(point);
        element.appendChild(particle);
        requestAnimationFrame(() => {
          element.classList.add('active');
        });
        setTimeout(() => {
          try {
            element.removeChild(particle);
          } catch {
            // ignore
          }
        }, t);
      }, 30);
    }
  }, [pathname]);

  function scrollByOffset(offset: number) {
    scrollRef.current?.scrollBy({ left: offset, behavior: "smooth" });
  }

  function handleWheel(event: React.WheelEvent<HTMLElement>) {
    const node = scrollRef.current;
    if (!node) return;
    if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return;
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

        <div className="relative w-full overflow-hidden" ref={containerRef}>
          <nav
            ref={scrollRef}
            onWheel={handleWheel}
            className="no-scrollbar w-full overflow-x-auto overscroll-x-contain scroll-smooth [scrollbar-width:none] [-ms-overflow-style:none] [touch-action:pan-x] relative z-10"
          >
            <div className="flex min-w-max snap-x snap-mandatory items-center gap-2 px-1 py-1 relative">
              <span className="gooey-effect filter" ref={filterRef} />
              {navigationItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    scroll={false}
                    ref={(el) => { linkRefs.current[item.href] = el; }}
                    className={`nav-link snap-start whitespace-nowrap px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] transition-colors relative z-20 ${
                      isActive
                        ? "is-active text-black"
                        : "text-slate-400 hover:border-white/16 hover:bg-white/[0.04] hover:text-slate-100"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </nav>
        </div>

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
