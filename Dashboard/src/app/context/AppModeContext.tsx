import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

type AppMode = "server" | "client";

interface AppModeContextValue {
  mode: AppMode | null;
  setMode: (mode: AppMode) => void;
  clearMode: () => void;
}

const AppModeContext = createContext<AppModeContextValue | null>(null);

const STORAGE_KEY = "wireseal_mode";

export function AppModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<AppMode | null>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "server" || saved === "client") return saved;
    } catch { /* ignore */ }
    return null;
  });

  const setMode = useCallback((m: AppMode) => {
    setModeState(m);
    try { localStorage.setItem(STORAGE_KEY, m); } catch { /* ignore */ }
  }, []);

  const clearMode = useCallback(() => {
    setModeState(null);
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
  }, []);

  return (
    <AppModeContext.Provider value={{ mode, setMode, clearMode }}>
      {children}
    </AppModeContext.Provider>
  );
}

export function useAppMode(): AppModeContextValue {
  const ctx = useContext(AppModeContext);
  if (!ctx) throw new Error("useAppMode must be used within AppModeProvider");
  return ctx;
}
