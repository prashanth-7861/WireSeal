import { useState } from "react";
import { Server, Terminal, ArrowRight } from "lucide-react";
import { useAppMode } from "../context/AppModeContext";

type AppMode = "server" | "client";

const MODES: { id: AppMode; icon: typeof Server; title: string; description: string; accent: string; hoverBg: string; ring: string }[] = [
  {
    id: "server",
    icon: Server,
    title: "Server Mode",
    description: "Manage WireGuard server, clients, keys, and configs",
    accent: "text-blue-400",
    hoverBg: "hover:border-blue-500/60 hover:bg-blue-500/10",
    ring: "ring-blue-500/40",
  },
  {
    id: "client",
    icon: Terminal,
    title: "Client Mode",
    description: "Connect to a WireGuard server and access SSH terminal",
    accent: "text-emerald-400",
    hoverBg: "hover:border-emerald-500/60 hover:bg-emerald-500/10",
    ring: "ring-emerald-500/40",
  },
];

export function ModeSelector() {
  const { setMode } = useAppMode();
  const [selected, setSelected] = useState<AppMode | null>(null);

  const handleContinue = () => {
    if (selected) setMode(selected);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-950 to-slate-900 flex items-center justify-center">
      <div className="flex flex-col items-center text-center gap-8 max-w-2xl w-full mx-4 animate-fade-in">
        <img
          src="/wireseal-192.png"
          alt="WireSeal"
          width={72}
          height={72}
          className="drop-shadow-[0_4px_24px_rgba(59,130,246,0.35)]"
        />

        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight mb-2">Choose Mode</h1>
          <p className="text-blue-300/60 text-sm">How would you like to use WireSeal?</p>
        </div>

        <div className="grid grid-cols-2 gap-4 w-full max-w-lg">
          {MODES.map(({ id, icon: Icon, title, description, accent, hoverBg, ring }) => (
            <button
              key={id}
              onClick={() => setSelected(id)}
              className={`relative flex flex-col items-center gap-4 p-6 rounded-xl border-2 transition-all cursor-pointer text-left ${
                selected === id
                  ? `border-white/40 bg-white/10 ring-2 ${ring}`
                  : `border-white/10 bg-white/5 ${hoverBg}`
              }`}
            >
              <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${
                selected === id ? "bg-white/20" : "bg-white/10"
              }`}>
                <Icon className={`w-7 h-7 ${accent}`} />
              </div>
              <div className="text-center">
                <h3 className="text-white font-semibold text-lg mb-1">{title}</h3>
                <p className="text-blue-200/50 text-sm leading-relaxed">{description}</p>
              </div>
              {selected === id && (
                <div className="absolute top-3 right-3 w-5 h-5 bg-white/20 rounded-full flex items-center justify-center">
                  <div className="w-2.5 h-2.5 bg-white rounded-full" />
                </div>
              )}
            </button>
          ))}
        </div>

        <button
          onClick={handleContinue}
          disabled={!selected}
          className="flex items-center gap-2 px-8 py-3 bg-blue-600 text-white font-medium rounded-xl hover:bg-blue-500 transition-all shadow-lg shadow-blue-600/30 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-blue-600"
        >
          Continue
          <ArrowRight className="w-5 h-5" />
        </button>

        <p className="text-blue-400/30 text-xs">Mode is locked at vault init. To switch later, Fresh-Start the vault.</p>
      </div>
    </div>
  );
}
