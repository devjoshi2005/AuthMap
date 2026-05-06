"use client";

import dynamic from "next/dynamic";
import { useEffect, useState } from "react";

import type { PrismProps } from "@/components/prism";

const Prism = dynamic(() => import("@/components/prism"), {
  ssr: false,
});

type DeferredPrismProps = PrismProps & {
  delayMs?: number;
};

export function DeferredPrism({ delayMs = 250, ...props }: DeferredPrismProps) {
  const [shouldRender, setShouldRender] = useState(false);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    let timeoutId: number | undefined;
    let idleId: number | undefined;

    const showPrism = () => setShouldRender(true);

    if ("requestIdleCallback" in window) {
      idleId = window.requestIdleCallback(showPrism, { timeout: 1200 });
    } else {
      timeoutId = window.setTimeout(showPrism, delayMs);
    }

    return () => {
      if (typeof idleId === "number" && "cancelIdleCallback" in window) {
        window.cancelIdleCallback(idleId);
      }

      if (typeof timeoutId === "number") {
        window.clearTimeout(timeoutId);
      }
    };
  }, [delayMs]);

  if (!shouldRender) {
    return null;
  }

  return <Prism {...props} />;
}