import { useState, useEffect } from "react";
import { Bookmark, Plus, Trash2 } from "lucide-react";
import { api, SshSavedHost } from "../../api";

interface Props {
  onSelect: (host: SshSavedHost) => void;
}

export function SavedHostsDropdown({ onSelect }: Props) {
  const [hosts, setHosts] = useState<SshSavedHost[]>([]);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api.clientSettingsGet()
      .then(s => setHosts(s.ssh_saved_hosts || []))
      .catch(() => {});
  }, []);

  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-lg bg-white text-gray-700 hover:bg-gray-50"
      >
        <Bookmark className="w-4 h-4" /> Saved
      </button>
      {open && (
        <div className="absolute top-full mt-1 left-0 w-64 bg-white rounded-xl border shadow-xl z-50 py-1">
          {hosts.length === 0 && (
            <p className="px-3 py-2 text-xs text-gray-400">No saved connections</p>
          )}
          {hosts.map((h, i) => (
            <button key={i} onClick={() => { onSelect(h); setOpen(false); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 text-left"
            >
              <Bookmark className="w-3.5 h-3.5 text-gray-400" />
              <span className="font-medium">{h.label || h.host}</span>
              <span className="text-xs text-gray-400 ml-auto">{h.username}@{h.host}:{h.port}</span>
            </button>
          ))}
          <div className="border-t mt-1 pt-1">
            <button onClick={() => { /* TODO: save current connection */ setOpen(false); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-blue-600 hover:bg-blue-50"
            >
              <Plus className="w-3.5 h-3.5" /> Save current connection
            </button>
          </div>
        </div>
      )}
    </div>
  );
}