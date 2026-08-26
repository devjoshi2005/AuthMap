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

type BrowserWindow = Window &
  typeof globalThis & {
    requestIdleCallback?: (callback: () => void, options?: { timeout: number }) => number;
    cancelIdleCallback?: (handle: number) => void;
  };

export function DeferredPrism({ delayMs = 250, ...props }: DeferredPrismProps) {
  const [shouldRender, setShouldRender] = useState(false);

  useEffect(() => {
    const browserWindow = window as BrowserWindow;

    if (browserWindow.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    let timeoutId: number | undefined;
    let idleId: number | undefined;

    const showPrism = () => setShouldRender(true);

    if (typeof browserWindow.requestIdleCallback === "function") {
      idleId = browserWindow.requestIdleCallback(showPrism, { timeout: 1200 });
    } else {
      timeoutId = browserWindow.setTimeout(showPrism, delayMs);
    }

    return () => {
      if (typeof idleId === "number" && typeof browserWindow.cancelIdleCallback === "function") {
        browserWindow.cancelIdleCallback(idleId);
      }

      if (typeof timeoutId === "number") {
        browserWindow.clearTimeout(timeoutId);
      }
    };
  }, [delayMs]);

  if (!shouldRender) {
    return null;
  }

  return <Prism {...props} />;
}
