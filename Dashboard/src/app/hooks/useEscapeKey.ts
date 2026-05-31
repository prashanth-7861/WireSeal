import { useEffect, useRef } from "react";

export function useEscapeKey(active: boolean, onEscape: () => void): void {
  // Store latest callback in a ref so callers don't need useCallback.
  // Without this, every inline arrow `() => { ... }` creates a new ref
  // each render, causing useEffect to tear down and re-attach the
  // listener on every single render — unnecessary DOM churn.
  const callbackRef = useRef(onEscape);
  callbackRef.current = onEscape;

  useEffect(() => {
    if (!active) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") callbackRef.current();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [active]);
}
