import { Wifi, Upload, ArrowRight } from "lucide-react";

export function Connect() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Connect</h1>
        <p className="text-gray-500 mt-1">Import a WireGuard config and connect to your server</p>
      </div>

      <div className="bg-white rounded-lg border border-gray-200 p-8">
        <div className="flex flex-col items-center text-center gap-6 max-w-md mx-auto py-8">
          <div className="w-16 h-16 bg-emerald-100 rounded-2xl flex items-center justify-center">
            <Wifi className="w-8 h-8 text-emerald-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900 mb-2">VPN Connection</h2>
            <p className="text-gray-500 text-sm leading-relaxed">
              Import the <code className="bg-gray-100 px-1.5 py-0.5 rounded text-xs">.conf</code> file
              you downloaded from the server, then activate the WireGuard tunnel.
            </p>
          </div>
          <div className="w-full space-y-3">
            <button
              disabled
              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-emerald-600 text-white rounded-lg opacity-50 cursor-not-allowed"
            >
              <Upload className="w-5 h-5" />
              Import Config File
            </button>
            <button
              disabled
              className="w-full flex items-center justify-center gap-2 px-4 py-3 border border-gray-300 rounded-lg opacity-50 cursor-not-allowed"
            >
              <ArrowRight className="w-5 h-5" />
              Connect to Server
            </button>
          </div>
          <p className="text-gray-400 text-xs">Coming in Phase A-2</p>
        </div>
      </div>
    </div>
  );
}
