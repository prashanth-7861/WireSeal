import { Settings } from "lucide-react";

export function ClientSettings() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Client Settings</h1>
        <p className="text-gray-500 mt-1">Manage saved connections and SSH credentials</p>
      </div>

      <div className="bg-white rounded-lg border border-gray-200 p-8">
        <div className="flex flex-col items-center text-center gap-4 py-8">
          <div className="w-14 h-14 bg-gray-100 rounded-xl flex items-center justify-center">
            <Settings className="w-7 h-7 text-gray-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 mb-1">Connection Profiles</h2>
            <p className="text-gray-500 text-sm">
              Save SSH connection details for quick access.
            </p>
          </div>
          <p className="text-gray-400 text-xs">Coming in Phase A-4</p>
        </div>
      </div>
    </div>
  );
}
