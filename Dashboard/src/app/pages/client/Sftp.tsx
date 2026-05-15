import { useState, useCallback, useRef, useEffect } from "react";
import {
  Folder, File, FileText, FileImage, FileArchive, FileCode,
  FileJson, FileSpreadsheet, Video, Music, ArrowUp, Download,
  Upload, Plus, Trash2, AlertTriangle, Home, RefreshCw, Server,
  Plug, PlugZap, Grid3X3, List, Search, X, ChevronRight,
  Edit3, Copy, FilePlus, MoreVertical,
} from "lucide-react";
import { api } from "../../api";
import type { SftpEntry } from "../../api";

const FILE_ICONS: Record<string, typeof File> = {
  txt: FileText, md: FileText, log: FileText,
  json: FileJson, xml: FileCode, yml: FileCode, yaml: FileCode, toml: FileCode,
  py: FileCode, js: FileCode, ts: FileCode, jsx: FileCode, tsx: FileCode,
  rb: FileCode, go: FileCode, rs: FileCode, java: FileCode, kt: FileCode,
  c: FileCode, cpp: FileCode, h: FileCode, hpp: FileCode, cs: FileCode,
  sh: FileCode, bash: FileCode, zsh: FileCode, ps1: FileCode, bat: FileCode,
  html: FileCode, css: FileCode, scss: FileCode,
  jpg: FileImage, jpeg: FileImage, png: FileImage, gif: FileImage,
  svg: FileImage, webp: FileImage, bmp: FileImage, ico: FileImage,
  zip: FileArchive, tar: FileArchive, gz: FileArchive, bz2: FileArchive,
  rar: FileArchive, "7z": FileArchive,
  pdf: FileText, doc: FileSpreadsheet, docx: FileSpreadsheet,
  xls: FileSpreadsheet, xlsx: FileSpreadsheet,
  csv: FileSpreadsheet, tsv: FileSpreadsheet,
  mp3: Music, wav: Music, flac: Music, ogg: Music,
  mp4: Video, avi: Video, mkv: Video, mov: Video,
};

function getFileIcon(name: string) {
  const ext = name.includes(".") ? name.split(".").pop()?.toLowerCase() || "" : "";
  return FILE_ICONS[ext] || File;
}

function formatSize(bytes: number): string {
  if (bytes <= 0) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatTime(ts: number): string {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const now = new Date();
  const opts: Intl.DateTimeFormatOptions = d.toDateString() === now.toDateString()
    ? { hour: "2-digit", minute: "2-digit" }
    : { month: "short", day: "numeric" };
  return d.toLocaleDateString(undefined, opts);
}

function getDirParts(path: string): string[] {
  // Handle both Unix and Windows-style paths via SFTP
  // SFTP always uses '/' separator regardless of server OS
  return path.replace(/^\/|\/$/g, "").split("/").filter(Boolean);
}

const TEXT_EXTS = new Set(["txt","md","json","xml","yml","yaml","toml","ini","cfg","conf","sh","py","js","ts","jsx","tsx","rb","go","rs","java","kt","c","cpp","h","hpp","cs","swift","html","css","scss","sql","r","lua","log","env","csv","tsv","gitignore","dockerfile","makefile"]);

export function Sftp() {
  const [host, setHost] = useState("10.0.0.1");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [currentPath, setCurrentPath] = useState("/");
  const [entries, setEntries] = useState<SftpEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"list" | "grid">("list");
  const [searchQuery, setSearchQuery] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; name: string } | null>(null);
  const [editorFile, setEditorFile] = useState<{ name: string; content: string } | null>(null);
  const [editorContent, setEditorContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameVal, setRenameVal] = useState("");
  const [showNewFile, setShowNewFile] = useState(false);
  const [newFileName, setNewFileName] = useState("");
  const [copyTarget, setCopyTarget] = useState<string | null>(null);
  const [copyDest, setCopyDest] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const connected = sessionId !== null;

  const loadDir = useCallback(async (path: string) => {
    if (!sessionId) return;
    setLoading(true); setError(null); setSelected(new Set());
    try {
      const res = await api.sftpList(sessionId, path);
      setCurrentPath(res.path); setEntries(res.entries);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally { setLoading(false); }
  }, [sessionId]);

  const connect = async () => {
    if (!host || !username) { setError("Host and username required"); return; }
    setLoading(true); setError(null);
    try {
      const res = await api.sftpConnect(host, port, username, password);
      setSessionId(res.session_id);
      await loadDir("/");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Connection failed");
    } finally { setLoading(false); }
  };

  const disconnect = async () => {
    if (sessionId) try { await api.sftpDisconnect(sessionId); } catch {}
    setSessionId(null); setEntries([]); setCurrentPath("/"); setSelected(new Set());
  };

  const navigate = (name: string) => loadDir(currentPath.replace(/\/?$/, "/") + name);
  const goUp = () => { const p = currentPath.replace(/\/+$/, "").split("/").slice(0, -1).join("/") || "/"; loadDir(p); };
  const goTo = (idx: number) => loadDir("/" + getDirParts(currentPath).slice(0, idx + 1).join("/"));

  const fp = (name: string) => currentPath.replace(/\/?$/, "/") + name;
  const filtered = searchQuery ? entries.filter(e => e.name.toLowerCase().includes(searchQuery.toLowerCase())) : entries;

  const toggleSelect = (name: string, e?: React.MouseEvent) => {
    if (e?.shiftKey && selected.size > 0) {
      const names = filtered.map(x => x.name);
      const last = [...selected].pop()!;
      const start = names.indexOf(last);
      const end = names.indexOf(name);
      if (start >= 0 && end >= 0) {
        const range = names.slice(Math.min(start, end), Math.max(start, end) + 1);
        setSelected(new Set([...selected, ...range]));
        return;
      }
    }
    setSelected(prev => { const n = new Set(prev); n.has(name) ? n.delete(name) : n.add(name); return n; });
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") { setSelected(new Set()); setContextMenu(null); }
    if (e.ctrlKey && e.key === "a") { e.preventDefault(); setSelected(new Set(filtered.map(x => x.name))); }
  };

  // Context menu
  useEffect(() => {
    const close = () => setContextMenu(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  const handleCtx = (e: React.MouseEvent, name: string) => {
    e.preventDefault(); e.stopPropagation();
    setContextMenu({ x: e.clientX, y: e.clientY, name });
    if (!selected.has(name)) setSelected(new Set([name]));
  };

  const downloadFile = async (name: string) => {
    try {
      const res = await api.sftpRead(sessionId!, fp(name));
      const bin = atob(res.content_b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const url = URL.createObjectURL(new Blob([bytes]));
      const a = document.createElement("a"); a.href = url; a.download = name; a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Download failed"); }
  };

  const uploadFile = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = async () => {
      const file = input.files?.[0]; if (!file) return;
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          await api.sftpWrite(sessionId!, fp(file.name), (reader.result as string).split(",")[1]);
          loadDir(currentPath);
        } catch (e: unknown) { setError(e instanceof Error ? e.message : "Upload failed"); }
      };
      reader.readAsDataURL(file);
    };
    input.click();
  };

  const newFolder = async () => {
    const name = prompt("Folder name:");
    if (!name?.trim()) return;
    try { await api.sftpMkdir(sessionId!, fp(name.trim())); loadDir(currentPath); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Failed"); }
  };

  const createFile = async () => {
    if (!newFileName.trim()) return;
    try {
      await api.sftpWrite(sessionId!, fp(newFileName.trim()), btoa(""));
      setShowNewFile(false); setNewFileName(""); loadDir(currentPath);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Failed"); }
  };

  const deleteItem = async (name: string) => {
    if (!confirm(`Delete "${name}"?`)) return;
    try { await api.sftpDelete(sessionId!, fp(name)); loadDir(currentPath); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Failed"); }
  };

  const doRename = async () => {
    if (!renaming || !renameVal.trim()) return;
    try {
      await api.sftpRename(sessionId!, fp(renaming), fp(renameVal.trim()));
      setRenaming(null); setRenameVal(""); loadDir(currentPath);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Rename failed"); }
  };

  const doCopy = async () => {
    if (!copyTarget || !copyDest) return;
    try { await api.sftpCopy(sessionId!, fp(copyTarget), copyDest); setCopyTarget(null); setCopyDest(""); loadDir(currentPath); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Copy failed"); }
  };

  const editFile = async (name: string) => {
    try {
      const res = await api.sftpRead(sessionId!, fp(name));
      setEditorFile({ name, content: atob(res.content_b64) });
      setEditorContent(atob(res.content_b64));
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Failed to open"); }
  };

  const saveFile = async () => {
    if (!editorFile) return;
    setSaving(true);
    try { await api.sftpWrite(sessionId!, fp(editorFile.name), btoa(editorContent)); setEditorFile(null); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Save failed"); }
    finally { setSaving(false); }
  };

  const ActionBtn = ({ icon: Icon, label, onClick, disabled, primary }: { icon: typeof File; label: string; onClick: () => void; disabled?: boolean; primary?: boolean }) => (
    <button onClick={onClick} disabled={disabled}
      className={`flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-lg transition-all ${
        primary ? "bg-blue-600 text-white border-blue-600 hover:bg-blue-700" : "bg-white text-gray-700 border-gray-200 hover:bg-gray-50 hover:border-gray-300"
      } disabled:opacity-40 disabled:cursor-not-allowed`}>
      <Icon className="w-4 h-4" /> {label}
    </button>
  );

  if (!connected) {
    return (
      <div className="p-6 max-w-lg mx-auto mt-12">
        <div className="text-center mb-8">
          <Server className="w-12 h-12 text-gray-300 mx-auto mb-3" />
          <h1 className="text-xl font-bold text-gray-900">SFTP File Browser</h1>
          <p className="text-sm text-gray-500 mt-1">Connect to a remote server via SFTP</p>
        </div>
        <div className="bg-white rounded-xl border p-5 space-y-3 shadow-sm">
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-600 mb-1">Host</label>
              <input value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === "Enter" && connect()}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="10.0.0.1" />
            </div>
            <div className="w-20">
              <label className="block text-xs font-medium text-gray-600 mb-1">Port</label>
              <input type="number" value={port} onChange={e => setPort(parseInt(e.target.value) || 22)} onKeyDown={e => e.key === "Enter" && connect()}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
            </div>
          </div>
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-600 mb-1">Username</label>
              <input value={username} onChange={e => setUsername(e.target.value)} onKeyDown={e => e.key === "Enter" && connect()}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="root" />
            </div>
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === "Enter" && connect()}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="••••••••" />
            </div>
          </div>
          <button onClick={connect} disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 font-medium">
            {loading ? "Connecting..." : <><Plug className="w-4 h-4" /> Connect to Server</>}
          </button>
          {error && <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 rounded-lg p-3"><AlertTriangle className="w-4 h-4" />{error}</div>}
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-gray-50" onKeyDown={handleKeyDown} tabIndex={0}>
      {/* Toolbar */}
      <div className="bg-white border-b px-4 py-2 flex items-center gap-2 flex-shrink-0">
        <div className="flex items-center gap-1 mr-2">
          <button onClick={() => loadDir("/")} className="p-1.5 rounded hover:bg-gray-100 text-gray-500" title="Home"><Home className="w-4 h-4" /></button>
          <button onClick={goUp} disabled={currentPath === "/"} className="p-1.5 rounded hover:bg-gray-100 text-gray-500 disabled:opacity-30" title="Up"><ArrowUp className="w-4 h-4" /></button>
          <button onClick={() => loadDir(currentPath)} disabled={loading} className="p-1.5 rounded hover:bg-gray-100 text-gray-500" title="Refresh"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /></button>
        </div>
        <div className="flex items-center gap-1 text-sm flex-1 min-w-0">
          <button onClick={() => loadDir("/")} className="text-gray-500 hover:text-blue-600 font-medium flex-shrink-0">/</button>
          {getDirParts(currentPath).map((part, i) => (
            <span key={i} className="flex items-center gap-1 min-w-0">
              <ChevronRight className="w-3 h-3 text-gray-300 flex-shrink-0" />
              <button onClick={() => goTo(i)} className="truncate hover:text-blue-600 text-gray-700 max-w-[120px]">{part}</button>
            </span>
          ))}
          {!searchQuery && <span className="text-xs text-gray-400 ml-auto tabular-nums">{filtered.length} items</span>}
        </div>
        <div className="relative w-48">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" />
          <input ref={searchRef} value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Filter..."
            className="w-full pl-8 pr-7 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
          {searchQuery && <button onClick={() => setSearchQuery("")} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"><X className="w-3.5 h-3.5" /></button>}
        </div>
        <div className="flex items-center gap-1 border-l pl-2 ml-2">
          <button onClick={() => setViewMode("list")} className={`p-1.5 rounded ${viewMode === "list" ? "bg-gray-100 text-gray-700" : "text-gray-400 hover:text-gray-600"}`} title="List"><List className="w-4 h-4" /></button>
          <button onClick={() => setViewMode("grid")} className={`p-1.5 rounded ${viewMode === "grid" ? "bg-gray-100 text-gray-700" : "text-gray-400 hover:text-gray-600"}`} title="Grid"><Grid3X3 className="w-4 h-4" /></button>
        </div>
        <div className="flex items-center gap-1.5 border-l pl-2 ml-2">
          <ActionBtn icon={Upload} label="Upload" onClick={uploadFile} />
          <ActionBtn icon={FilePlus} label="New File" onClick={() => setShowNewFile(true)} />
          <ActionBtn icon={Plus} label="Folder" onClick={newFolder} />
        </div>
        <button onClick={disconnect} className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-600 ml-1" title="Disconnect">
          <PlugZap className="w-4 h-4" />
        </button>
      </div>

      {/* New file inline */}
      {showNewFile && (
        <div className="bg-white border-b px-4 py-2 flex items-center gap-2">
          <FilePlus className="w-4 h-4 text-gray-400" />
          <input value={newFileName} onChange={e => setNewFileName(e.target.value)} onKeyDown={e => { if (e.key === "Enter") createFile(); if (e.key === "Escape") { setShowNewFile(false); setNewFileName(""); } }}
            className="border rounded px-2.5 py-1.5 text-sm flex-1 max-w-xs focus:ring-2 focus:ring-blue-500" placeholder="filename.txt" autoFocus />
          <button onClick={createFile} disabled={!newFileName.trim()} className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">Create</button>
          <button onClick={() => { setShowNewFile(false); setNewFileName(""); }} className="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50">Cancel</button>
        </div>
      )}

      {/* Error bar */}
      {error && (
        <div className="bg-red-50 border-b border-red-200 px-4 py-2 flex items-center gap-2 text-sm text-red-700">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-600 text-xs font-medium">Dismiss</button>
        </div>
      )}

      {/* Status bar */}
      <div className="bg-white border-b px-4 py-1.5 flex items-center gap-3 text-xs text-gray-500 flex-shrink-0">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" />{username}@{host}:{port}</span>
        <span className="text-gray-300">|</span>
        <span className="font-mono">{currentPath}</span>
        {selected.size > 0 && <><span className="text-gray-300">|</span><span className="font-medium text-blue-600">{selected.size} selected</span></>}
      </div>

      {/* Editor overlay */}
      {editorFile ? (
        <div className="flex-1 flex flex-col bg-white">
          <div className="flex items-center justify-between px-4 py-2 border-b bg-gray-50">
            <span className="text-sm font-medium text-gray-700 flex items-center gap-2"><Edit3 className="w-4 h-4 text-green-600" />{editorFile.name}</span>
            <div className="flex gap-2">
              <button onClick={saveFile} disabled={saving} className="px-3 py-1 text-sm bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50">{saving ? "Saving..." : "Save"}</button>
              <button onClick={() => { setEditorFile(null); }} className="px-3 py-1 text-sm border rounded-lg hover:bg-gray-50">Close</button>
            </div>
          </div>
          <textarea value={editorContent} onChange={e => setEditorContent(e.target.value)} className="flex-1 p-4 font-mono text-sm border-0 resize-none focus:outline-none" spellCheck={false} />
        </div>
      ) : viewMode === "list" ? (
        /* ───── LIST VIEW ───── */
        <div className="flex-1 overflow-auto">
          {loading && filtered.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-400 text-sm">Loading...</div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-400 text-sm">This folder is empty</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50 text-left text-xs text-gray-500 uppercase tracking-wider sticky top-0">
                  <th className="px-4 py-2.5 border-b font-medium w-8"></th>
                  <th className="px-2 py-2.5 border-b font-medium">Name</th>
                  <th className="px-2 py-2.5 border-b font-medium w-24 text-right">Size</th>
                  <th className="px-2 py-2.5 border-b font-medium w-28">Modified</th>
                </tr>
              </thead>
              <tbody>
                {currentPath !== "/" && (
                  <tr className="hover:bg-blue-50 cursor-pointer" onClick={goUp}>
                    <td className="px-4 py-2.5 border-b"><ArrowUp className="w-4 h-4 text-gray-400" /></td>
                    <td className="px-2 py-2.5 border-b font-medium text-gray-600" colSpan={3}>..</td>
                  </tr>
                )}
                {filtered.map(e => {
                  const Icon = e.type === "dir" ? Folder : getFileIcon(e.name);
                  const sel = selected.has(e.name);
                  return (
                    <tr key={e.name}
                      className={`cursor-pointer transition-colors ${sel ? "bg-blue-50" : "hover:bg-gray-50"}`}
                      onClick={() => { if (e.type === "dir") navigate(e.name); else toggleSelect(e.name); }}
                      onContextMenu={ev => handleCtx(ev, e.name)}
                    >
                      <td className="px-4 py-2.5 border-b" onClick={ev => { ev.stopPropagation(); toggleSelect(e.name, ev); }}>
                        <div className={`w-4 h-4 rounded border-2 transition-colors ${sel ? "bg-blue-600 border-blue-600" : "border-gray-300"}`}>
                          {sel && <svg viewBox="0 0 16 16" className="w-full h-full text-white"><path d="M3 8l3 3 7-7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                        </div>
                      </td>
                      <td className="px-2 py-2.5 border-b">
                        <div className="flex items-center gap-3">
                          <Icon className={`w-5 h-5 ${e.type === "dir" ? "text-amber-400" : "text-gray-400"}`} />
                          <span className={`text-sm ${sel ? "font-medium text-blue-700" : "text-gray-800"}`}>{e.name}</span>
                        </div>
                      </td>
                      <td className="px-2 py-2.5 border-b text-right text-sm text-gray-500 tabular-nums">{e.type === "dir" ? "" : formatSize(e.size)}</td>
                      <td className="px-2 py-2.5 border-b text-sm text-gray-400">{formatTime(e.modified)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      ) : (
        /* ───── GRID VIEW ───── */
        <div className="flex-1 overflow-auto p-4">
          {loading && filtered.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-400 text-sm">Loading...</div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-400 text-sm">This folder is empty</div>
          ) : (
            <div className="grid grid-cols-[repeat(auto-fill,minmax(100px,1fr))] gap-3">
              {currentPath !== "/" && (
                <div onClick={goUp} className="flex flex-col items-center justify-center gap-1.5 p-4 rounded-xl border-2 border-dashed border-gray-200 hover:border-blue-300 hover:bg-blue-50/50 cursor-pointer h-28">
                  <ArrowUp className="w-6 h-6 text-gray-400" />
                  <span className="text-xs text-gray-500 font-medium">..</span>
                </div>
              )}
              {filtered.map(e => {
                const Icon = e.type === "dir" ? Folder : getFileIcon(e.name);
                const sel = selected.has(e.name);
                return (
                  <div key={e.name}
                    onClick={() => { if (e.type === "dir") navigate(e.name); else toggleSelect(e.name); }}
                    onContextMenu={ev => handleCtx(ev, e.name)}
                    className={`flex flex-col items-center justify-center gap-1.5 p-4 rounded-xl border-2 cursor-pointer transition-all h-28 ${
                      sel ? "border-blue-500 bg-blue-50 shadow-sm" : "border-gray-100 hover:border-blue-200 hover:shadow-sm bg-white"
                    }`}
                  >
                    <Icon className={`w-8 h-8 ${e.type === "dir" ? "text-amber-400" : "text-gray-400"}`} />
                    <span className="text-xs text-center leading-tight line-clamp-2 text-gray-700 font-medium">{e.name}</span>
                    {e.type === "file" && <span className="text-[10px] text-gray-400">{formatSize(e.size)}</span>}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Context menu */}
      {contextMenu && (
        <div className="fixed z-50 bg-white rounded-xl border shadow-xl py-1 w-44" style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={() => setContextMenu(null)}>
          {[
            { label: "Download", icon: Download, fn: () => downloadFile(contextMenu.name), hidden: false },
            { label: "Edit", icon: Edit3, fn: () => editFile(contextMenu.name), hidden: !TEXT_EXTS.has(contextMenu.name.includes(".") ? contextMenu.name.split(".").pop() || "" : "") },
            { label: "Rename", icon: Edit3, fn: () => { setRenaming(contextMenu.name); setRenameVal(contextMenu.name); }, hidden: false },
            { label: "Copy To...", icon: Copy, fn: () => { setCopyTarget(contextMenu.name); setCopyDest(fp("copy_of_" + contextMenu.name)); }, hidden: false },
            { label: "Delete", icon: Trash2, fn: () => deleteItem(contextMenu.name), hidden: false },
          ].filter(a => !a.hidden).map((a, i) => (
            <button key={i} onClick={() => { a.fn(); setContextMenu(null); }}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 transition-colors">
              <a.icon className="w-4 h-4 text-gray-400" /> {a.label}
            </button>
          ))}
        </div>
      )}

      {/* Rename modal */}
      {renaming && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setRenaming(null)}>
          <div className="bg-white rounded-xl p-5 w-full max-w-sm shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-3">Rename "{renaming}"</h3>
            <form onSubmit={e => { e.preventDefault(); doRename(); }}>
              <input value={renameVal} onChange={e => setRenameVal(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 text-sm mb-3 focus:ring-2 focus:ring-blue-500" autoFocus />
              <div className="flex gap-2 justify-end">
                <button type="button" onClick={() => setRenaming(null)} className="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50">Cancel</button>
                <button type="submit" disabled={!renameVal.trim()} className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700">Rename</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Copy modal */}
      {copyTarget && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setCopyTarget(null)}>
          <div className="bg-white rounded-xl p-5 w-full max-w-sm shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-3">Copy "{copyTarget}"</h3>
            <form onSubmit={e => { e.preventDefault(); doCopy(); }}>
              <label className="text-xs text-gray-500 mb-1 block">Destination path</label>
              <input value={copyDest} onChange={e => setCopyDest(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 text-sm mb-3 font-mono text-xs focus:ring-2 focus:ring-blue-500" autoFocus />
              <div className="flex gap-2 justify-end">
                <button type="button" onClick={() => setCopyTarget(null)} className="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50">Cancel</button>
                <button type="submit" disabled={!copyDest} className="px-3 py-1.5 text-sm bg-purple-600 text-white rounded-lg hover:bg-purple-700">Copy</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
