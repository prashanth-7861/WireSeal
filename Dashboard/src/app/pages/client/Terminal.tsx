import { TerminalSquare } from "lucide-react";

export function Terminal() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">SSH Terminal</h1>
        <p className="text-gray-500 mt-1">Secure shell access to your server over the WireGuard tunnel</p>
      </div>

      <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 bg-gray-800 border-b border-gray-700">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/80" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <div className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <span className="text-gray-400 text-xs ml-2 font-mono">ssh — not connected</span>
        </div>
        <div className="flex flex-col items-center justify-center py-24 text-center gap-4">
          <TerminalSquare className="w-12 h-12 text-gray-600" />
          <div>
            <p className="text-gray-400 text-sm">Connect to a server first to start a terminal session</p>
            <p className="text-gray-600 text-xs mt-2">Coming in Phase A-4</p>
          </div>
        </div>
      </div>
    </div>
  );
}
