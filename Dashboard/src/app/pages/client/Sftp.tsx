import { useState, useCallback, useRef, useEffect } from "react";
import {
  Folder, File, FileText, FileImage, FileArchive, FileCode,
  FileJson, FileSpreadsheet, Video, Music, ArrowUp, Download,
  Upload, Plus, Trash2, AlertTriangle, Home, RefreshCw, Server,
  Plug, PlugZap, Grid3X3, List, Search, X, ChevronRight,
  Edit3, Copy, FilePlus, TerminalSquare, Eye, EyeOff,
  Star, Clock, Key, ExternalLink, ImageIcon, Loader,
  Shield, Info as InfoIcon,
} from "lucide-react";
import { useSearchParams } from "react-router";
import { api } from "../../api";
import type { SftpEntry, SshKey, SftpSavedConnection } from "../../api";

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

const FILE_COLORS: Record<string, string> = {
  txt: "text-blue-500", md: "text-blue-500", log: "text-gray-500",
  json: "text-yellow-500", xml: "text-orange-500", yml: "text-red-500", yaml: "text-red-500", toml: "text-red-500",
  py: "text-blue-600", js: "text-yellow-400", ts: "text-blue-500", jsx: "text-cyan-500", tsx: "text-blue-500",
  rb: "text-red-500", go: "text-cyan-500", rs: "text-orange-600", java: "text-red-600", kt: "text-purple-500",
  c: "text-blue-600", cpp: "text-blue-600", h: "text-pink-500", cs: "text-purple-600",
  sh: "text-green-600", bash: "text-green-600", ps1: "text-blue-500",
  html: "text-orange-500", css: "text-blue-500", scss: "text-pink-500",
  jpg: "text-green-500", jpeg: "text-green-500", png: "text-green-500", gif: "text-purple-500",
  svg: "text-yellow-500", webp: "text-green-500",
  zip: "text-amber-600", tar: "text-amber-600", gz: "text-amber-600",
  pdf: "text-red-500",
  mp3: "text-purple-500", wav: "text-purple-500",
  mp4: "text-blue-500", avi: "text-blue-500", mkv: "text-blue-500",
};

function getFileIcon(name: string) {
  const ext = name.includes(".") ? name.split(".").pop()?.toLowerCase() || "" : "";
  return FILE_ICONS[ext] || File;
}

function getFileColor(name: string, isDir: boolean): string {
  if (isDir) return "text-amber-400";
  const ext = name.includes(".") ? name.split(".").pop()?.toLowerCase() || "" : "";
  return FILE_COLORS[ext] || "text-gray-400";
}

const IMG_EXTS = new Set(["jpg","jpeg","png","gif","svg","webp","bmp","ico"]);

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
  return path.replace(/^\/|\/$/g, "").split("/").filter(Boolean);
}

function connLabel(c: SftpSavedConnection): string {
  return c.label || `${c.username}@${c.host}:${c.port}`;
}

const TEXT_EXTS = new Set(["txt","md","json","xml","yml","yaml","toml","ini","cfg","conf","sh","py","js","ts","jsx","tsx","rb","go","rs","java","kt","c","cpp","h","hpp","cs","swift","html","css","scss","sql","r","lua","log","env","csv","tsv","gitignore","dockerfile","makefile"]);

function sanitizeFilename(name: string): string {
  return name.replace(/[/\\:*?"<>|]/g, "_").replace(/\.\./g, "_");
}

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
  const [searchParams] = useSearchParams();
  const [authMode, setAuthMode] = useState<"password" | "key">("password");
  const [selectedKey, setSelectedKey] = useState("");
  const [sshKeys, setSshKeys] = useState<SshKey[]>([]);
  const [showHidden, setShowHidden] = useState(false);
  const [sortBy, setSortBy] = useState<"name" | "size" | "modified" | "type">("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [dragOver, setDragOver] = useState(false);
  const [savedConns, setSavedConns] = useState<SftpSavedConnection[]>([]);
  const [previewFile, setPreviewFile] = useState<string | null>(null);
  const [previewData, setPreviewData] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<string | null>(null);
  const [tofu, setTofu] = useState<{ host: string; port: number; fingerprint: string; key_export: string } | null>(null);
  const [tofuPending, setTofuPending] = useState<{ pw: string; k?: string } | null>(null);
  const [goToPath, setGoToPath] = useState(false);
  const [goToPathVal, setGoToPathVal] = useState("");
  const [chmodTarget, setChmodTarget] = useState<{ name: string; path: string } | null>(null);
  const [chmodVal, setChmodVal] = useState("");
  const [fileStat, setFileStat] = useState<Record<string, unknown> | null>(null);
  const [overwriteConfirm, setOverwriteConfirm] = useState<{ files: File[]; existing: string[] } | null>(null);
  const [focusIdx, setFocusIdx] = useState(-1);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const connected = sessionId !== null;

  useEffect(() => {
    api.sshKeysList().then(res => setSshKeys(res.keys)).catch(() => {});
  }, []);

  useEffect(() => {
    api.clientSettingsGet()
      .then(s => setSavedConns(s.sftp_saved_connections || []))
      .catch(() => {});
  }, [connected]);

  useEffect(() => {
    const h = searchParams.get("host");
    const p = searchParams.get("port");
    const u = searchParams.get("user");
    if (h) setHost(h);
    if (p) setPort(parseInt(p, 10) || 22);
    if (u) setUsername(u);
  }, [searchParams]);

  const loadDir = useCallback(async (path: string, overrideSessionId?: string) => {
    const sid = overrideSessionId ?? sessionId;
    if (!sid) return;
    setLoading(true); setError(null); setSelected(new Set());
    try {
      const res = await api.sftpList(sid, path);
      setCurrentPath(res.path); setEntries(res.entries);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally { setLoading(false); }
  }, [sessionId]);

  const connect = async (connHost?: string, connPort?: number, connUser?: string, connPass?: string, connKey?: string) => {
    const h = connHost || host;
    const p = connPort || port;
    const u = connUser || username;
    const pw = connPass ?? password;
    const k = connKey ?? (authMode === "key" ? selectedKey : undefined);
    if (!h || !u) { setError("Host and username required"); return; }
    if (authMode === "key" && !k) { setError("Select an SSH key"); return; }
    setLoading(true); setError(null); setTofu(null);
    try {
      const res = await api.sftpConnect(h, p, u, pw, k) as Record<string, unknown>;
      if (res.tofu_required) {
        // Host key not yet trusted — show fingerprint to user
        setTofu({
          host: String(res.host),
          port: Number(res.port),
          fingerprint: String(res.fingerprint),
          key_export: String(res.key_export),
        });
        setTofuPending({ pw, k });
        setHost(h); setPort(p); setUsername(u);
        return;
      }
      setSessionId(res.session_id as string);
      setHost(h); setPort(p); setUsername(u);
      await loadDir("/", res.session_id as string);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Connection failed");
    } finally { setLoading(false); }
  };

  const disconnect = async () => {
    if (sessionId) try { await api.sftpDisconnect(sessionId); } catch {}
    setSessionId(null); setEntries([]); setCurrentPath("/"); setSelected(new Set());
    setPreviewFile(null); setPreviewData(null);
  };

  const connectSaved = (c: SftpSavedConnection) => {
    setHost(c.host); setPort(c.port); setUsername(c.username);
    setAuthMode(c.auth_mode as "password" | "key");
    setSelectedKey(c.key_name || "");
    connect(c.host, c.port, c.username, "", c.key_name || undefined);
  };

  const navigate = (name: string) => loadDir(currentPath.replace(/\/?$/, "/") + name);
  const goUp = () => { const p = currentPath.replace(/\/+$/, "").split("/").slice(0, -1).join("/") || "/"; loadDir(p); };
  const goTo = (idx: number) => loadDir("/" + getDirParts(currentPath).slice(0, idx + 1).join("/"));

  const fp = (name: string) => currentPath.replace(/\/?$/, "/") + name;
  const filtered = searchQuery ? entries.filter(e => e.name.toLowerCase().includes(searchQuery.toLowerCase())) : entries;
  const visible = filtered.filter(e => showHidden || !e.name.startsWith("."));
  const sorted = [...visible].sort((a, b) => {
    const dirCmp = (b.type === "dir" ? 1 : 0) - (a.type === "dir" ? 1 : 0);
    if (dirCmp !== 0) return dirCmp;
    const valA = a[sortBy]; const valB = b[sortBy];
    if (valA === valB) return 0;
    if (valA === undefined) return 1; if (valB === undefined) return -1;
    const cmp = valA < valB ? -1 : 1;
    return sortDir === "asc" ? cmp : -cmp;
  });

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
    if (e.key === "Escape") { setSelected(new Set()); setContextMenu(null); setPreviewFile(null); setPreviewData(null); setFocusIdx(-1); }
    if (e.ctrlKey && e.key === "a") { e.preventDefault(); setSelected(new Set(filtered.map(x => x.name))); }
    if (e.key === "Delete" && selected.size > 0) {
      if (confirm(`Delete ${selected.size} selected items?`)) {
        (async () => {
          for (const name of selected) {
            try { await api.sftpDelete(sessionId!, fp(name)); } catch {}
          }
          setSelected(new Set());
          loadDir(currentPath);
        })();
      }
    }
    if (e.key === "Home") { e.preventDefault(); loadDir("/"); }
    // Arrow key navigation
    if (e.key === "ArrowDown" && sorted.length > 0) {
      e.preventDefault();
      const next = Math.min(focusIdx + 1, sorted.length - 1);
      setFocusIdx(next);
      setSelected(new Set([sorted[next].name]));
    }
    if (e.key === "ArrowUp" && sorted.length > 0) {
      e.preventDefault();
      const prev = Math.max(focusIdx - 1, 0);
      setFocusIdx(prev);
      setSelected(new Set([sorted[prev].name]));
    }
    // Enter to open directory or download file
    if (e.key === "Enter" && focusIdx >= 0 && focusIdx < sorted.length) {
      e.preventDefault();
      const entry = sorted[focusIdx];
      if (entry.type === "dir") navigate(entry.name);
      else downloadFile(entry.name);
    }
    // F2 to rename
    if (e.key === "F2" && selected.size === 1) {
      e.preventDefault();
      const name = [...selected][0];
      setRenaming(name); setRenameVal(name);
    }
    // F5 to refresh
    if (e.key === "F5") { e.preventDefault(); loadDir(currentPath); }
    // Backspace to go up
    if (e.key === "Backspace" && currentPath !== "/" && !editorFile && !renaming) {
      e.preventDefault(); goUp();
    }
    // Ctrl+G for go-to-path
    if (e.ctrlKey && e.key === "g") { e.preventDefault(); setGoToPath(true); setGoToPathVal(currentPath); }
  };

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
    input.multiple = true;
    input.onchange = async () => {
      const files = input.files;
      if (!files || files.length === 0) return;
      await uploadWithOverwriteCheck(Array.from(files));
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

  const MAX_EDIT_SIZE = 1024 * 1024; // 1 MB max for text editor
  const editFile = async (name: string) => {
    try {
      // Check size first to avoid loading huge files
      const stat = await api.sftpStat(sessionId!, fp(name));
      if (stat.size && stat.size > MAX_EDIT_SIZE) {
        setError(`File too large to edit (${formatSize(stat.size)}). Max: 1 MB. Download instead.`);
        return;
      }
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

  const doChmod = async () => {
    if (!chmodTarget || !chmodVal.trim()) return;
    const mode = parseInt(chmodVal.trim(), 8);
    if (isNaN(mode) || mode < 0 || mode > 0o7777) { setError("Invalid octal permissions (e.g. 755)"); return; }
    try {
      await api.sftpChmod(sessionId!, chmodTarget.path, mode);
      setChmodTarget(null); setChmodVal(""); loadDir(currentPath);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "chmod failed"); }
  };

  const showProperties = async (name: string) => {
    try {
      const stat = await api.sftpStat(sessionId!, fp(name));
      setFileStat({ name, ...stat });
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Failed to get properties"); }
  };

  const uploadWithOverwriteCheck = async (files: File[]) => {
    // Check which files already exist
    const existing: string[] = [];
    for (const file of files) {
      try {
        const res = await api.sftpExists(sessionId!, fp(sanitizeFilename(file.name)));
        if (res.exists) existing.push(file.name);
      } catch { /* ignore — proceed with upload */ }
    }
    if (existing.length > 0) {
      setOverwriteConfirm({ files, existing });
      return;
    }
    await doUploadFiles(files);
  };

  const doUploadFiles = async (files: File[]) => {
    for (const file of files) {
      setUploadProgress(`Uploading ${file.name}...`);
      const reader = new FileReader();
      await new Promise<void>((resolve) => {
        reader.onload = async () => {
          try {
            await api.sftpWrite(sessionId!, fp(sanitizeFilename(file.name)), (reader.result as string).split(",")[1]);
          } catch (e: unknown) { setError(e instanceof Error ? e.message : `Upload failed: ${file.name}`); }
          resolve();
        };
        reader.readAsDataURL(file);
      });
    }
    setUploadProgress(null);
    loadDir(currentPath);
  };

  const openImagePreview = async (name: string) => {
    try {
      setPreviewFile(name);
      setPreviewData(null);
      const res = await api.sftpRead(sessionId!, fp(name));
      const b64 = res.content_b64;
      const mime = res.mime || "image/png";
      setPreviewData(`data:${mime};base64,${b64}`);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Preview failed"); setPreviewFile(null); }
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
      <div className="max-w-2xl mx-auto mt-8 px-4">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-blue-200">
            <Server className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">SFTP File Browser</h1>
          <p className="text-sm text-gray-500 mt-1">Connect to a remote server via SFTP</p>
        </div>

        {savedConns.length > 0 && (
          <div className="mb-6">
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Star className="w-3 h-3" /> Saved Connections
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {savedConns.map((c, i) => (
                <button key={i} onClick={() => connectSaved(c)}
                  className="flex items-center gap-3 p-3 bg-white rounded-xl border border-gray-200 hover:border-blue-300 hover:shadow-md hover:bg-blue-50/30 transition-all text-left group">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl flex items-center justify-center flex-shrink-0 group-hover:from-blue-100 group-hover:to-blue-200 transition-colors">
                    <Server className="w-5 h-5 text-blue-600" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-gray-800 truncate">{connLabel(c)}</p>
                    <p className="text-xs text-gray-400 truncate">
                      <Key className="w-3 h-3 inline mr-0.5" />
                      {c.auth_mode === "key" ? `SSH Key: ${c.key_name || "default"}` : "Password"}
                    </p>
                  </div>
                  <Plug className="w-4 h-4 text-gray-300 group-hover:text-blue-500 transition-colors flex-shrink-0" />
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100 bg-gray-50/50">
            <h2 className="text-sm font-semibold text-gray-700 flex items-center gap-2">
              <Plug className="w-4 h-4 text-blue-500" /> Quick Connect
            </h2>
          </div>
          <div className="p-5 space-y-3">
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
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  <div className="flex items-center gap-1 bg-gray-100 rounded-lg p-0.5 w-fit">
                    <button type="button" onClick={() => setAuthMode("password")}
                      className={`px-3 py-1 text-xs rounded-md transition-colors ${authMode === "password" ? "bg-white text-gray-900 shadow-sm font-medium" : "text-gray-500 hover:text-gray-700"}`}>Password</button>
                    <button type="button" onClick={() => setAuthMode("key")}
                      className={`px-3 py-1 text-xs rounded-md transition-colors ${authMode === "key" ? "bg-white text-gray-900 shadow-sm font-medium" : "text-gray-500 hover:text-gray-700"}`}>SSH Key</button>
                  </div>
                </label>
                {authMode === "password" ? (
                  <input type="password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === "Enter" && connect()}
                    className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="••••••••" />
                ) : (
                  <select value={selectedKey} onChange={e => setSelectedKey(e.target.value)}
                    className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white">
                    <option value="">Select key...</option>
                    {sshKeys.map(k => <option key={k.name} value={k.name}>{k.name} ({k.type})</option>)}
                  </select>
                )}
              </div>
            </div>
            <div className="flex gap-2">
              <button onClick={() => connect()} disabled={loading}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 font-medium transition-colors">
                {loading ? <><Loader className="w-4 h-4 animate-spin" /> Connecting...</> : <><Plug className="w-4 h-4" /> Connect</>}
              </button>
            </div>
            {error && <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 rounded-lg p-3 border border-red-100"><AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}</div>}
          </div>
        </div>

        {/* TOFU host key verification modal */}
        {tofu && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-2xl p-6 w-full max-w-md mx-4">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-12 h-12 bg-amber-100 rounded-full flex items-center justify-center">
                  <AlertTriangle className="w-6 h-6 text-amber-600" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-gray-900">Unknown Host Key</h2>
                  <p className="text-sm text-gray-500">First connection to {tofu.host}:{tofu.port}</p>
                </div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3 mb-4">
                <p className="text-xs text-gray-500 mb-1">SHA-256 Fingerprint</p>
                <p className="text-sm font-mono text-gray-800 break-all">{tofu.fingerprint}</p>
              </div>
              <p className="text-sm text-gray-600 mb-4">
                Verify this fingerprint matches the server. Accepting will save it for future connections.
              </p>
              <div className="flex gap-3">
                <button onClick={() => { setTofu(null); setTofuPending(null); }}
                  className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 text-sm">
                  Reject
                </button>
                <button onClick={async () => {
                  try {
                    await api.sshAcceptHostKey({ host: tofu.host, port: tofu.port, key_export: tofu.key_export });
                    setTofu(null);
                    // Retry connection now that host key is trusted
                    if (tofuPending) {
                      await connect(host, port, username, tofuPending.pw, tofuPending.k);
                      setTofuPending(null);
                    }
                  } catch (e: unknown) {
                    setError(e instanceof Error ? e.message : "Failed to accept host key");
                    setTofu(null); setTofuPending(null);
                  }
                }} className="flex-1 px-4 py-2.5 bg-amber-600 text-white rounded-lg hover:bg-amber-700 text-sm font-medium">
                  Trust &amp; Connect
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-4rem)] flex flex-col bg-gray-50 relative overflow-hidden rounded-lg" onKeyDown={handleKeyDown} tabIndex={0}
      onDragOver={e => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={async e => {
        e.preventDefault(); setDragOver(false);
        await uploadWithOverwriteCheck(Array.from(e.dataTransfer.files));
      }}>
      {dragOver && (
        <div className="absolute inset-0 z-50 bg-blue-500/10 border-2 border-dashed border-blue-400 rounded-lg flex items-center justify-center pointer-events-none">
          <div className="bg-white rounded-xl px-6 py-4 shadow-xl text-sm font-medium text-blue-700 animate-fade-in">Drop files to upload</div>
        </div>
      )}

      {/* Upload progress bar */}
      {uploadProgress && (
        <div className="absolute top-0 left-0 right-0 z-40 bg-blue-50 border-b border-blue-200 px-4 py-2 flex items-center gap-2 text-sm text-blue-700">
          <Loader className="w-4 h-4 animate-spin" />
          <span>{uploadProgress}</span>
        </div>
      )}

      {/* Toolbar */}
      <div className="bg-white border-b px-4 py-2 flex items-center gap-2 flex-shrink-0">
        <div className="flex items-center gap-1 mr-2">
          <button onClick={() => loadDir("/")} className="p-1.5 rounded hover:bg-gray-100 text-gray-500" title="Home (Home)"><Home className="w-4 h-4" /></button>
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
          {!searchQuery && <span className="text-xs text-gray-400 ml-auto tabular-nums">{sorted.length} items</span>}
        </div>
        <div className="relative w-44">
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
          {selected.size > 0 && (
            <ActionBtn icon={Trash2} label={`Delete (${selected.size})`} onClick={async () => {
              if (!confirm(`Delete ${selected.size} selected items?`)) return;
              for (const name of selected) {
                try { await api.sftpDelete(sessionId!, fp(name)); } catch {}
              }
              setSelected(new Set());
              loadDir(currentPath);
            }} />
          )}
        </div>
        <button onClick={disconnect} className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-600 ml-1" title="Disconnect (Esc)">
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
        {editorFile && <><span className="text-gray-300">|</span><span className="text-green-600 font-medium">Editing: {editorFile.name}</span></>}
        {previewFile && <><span className="text-gray-300">|</span><span className="text-purple-600 font-medium">Preview: {previewFile}</span></>}
        <span className="flex-1" />
        <button onClick={() => setShowHidden(!showHidden)} className={`flex items-center gap-1 px-2 py-0.5 rounded transition-colors ${showHidden ? "bg-gray-200 text-gray-700" : "text-gray-400 hover:text-gray-600"}`} title="Toggle hidden files">
          {showHidden ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
        </button>
        <button onClick={() => { const p = new URLSearchParams({ host, port: String(port), user: username }); window.open(`/client/terminal?${p.toString()}`, "_blank"); }}
          className="flex items-center gap-1 px-2 py-0.5 bg-blue-50 text-blue-700 rounded hover:bg-blue-100 transition-colors">
          <TerminalSquare className="w-3 h-3" /> Terminal Here
        </button>
      </div>

      <div className="flex-1 flex min-h-0">
        {/* Main content area */}
        <div className={`flex-1 flex flex-col min-w-0 ${previewData ? "border-r border-gray-200" : ""}`}>
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
            <div className="flex-1 overflow-auto">
              {loading && sorted.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-400 text-sm">Loading...</div>
              ) : sorted.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-400 text-sm">This folder is empty</div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="bg-gray-50 text-left text-xs text-gray-500 uppercase tracking-wider sticky top-0">
                      <th className="px-4 py-2.5 border-b font-medium w-8"></th>
                      <th className="px-2 py-2.5 border-b font-medium cursor-pointer hover:text-gray-700 select-none" onClick={() => { if (sortBy === "name") setSortDir(d => d === "asc" ? "desc" : "asc"); else { setSortBy("name"); setSortDir("asc"); } }}>
                        Name {sortBy === "name" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                      </th>
                      <th className="px-2 py-2.5 border-b font-medium w-20 hidden lg:table-cell">Permissions</th>
                      <th className="px-2 py-2.5 border-b font-medium w-24 text-right cursor-pointer hover:text-gray-700 select-none" onClick={() => { if (sortBy === "size") setSortDir(d => d === "asc" ? "desc" : "asc"); else { setSortBy("size"); setSortDir("asc"); } }}>
                        Size {sortBy === "size" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                      </th>
                      <th className="px-2 py-2.5 border-b font-medium w-28 cursor-pointer hover:text-gray-700 select-none" onClick={() => { if (sortBy === "modified") setSortDir(d => d === "asc" ? "desc" : "asc"); else { setSortBy("modified"); setSortDir("asc"); } }}>
                        Modified {sortBy === "modified" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                      </th>
                      <th className="px-2 py-2.5 border-b font-medium w-16">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {currentPath !== "/" && (
                      <tr className="hover:bg-blue-50 cursor-pointer" onClick={goUp}>
                        <td className="px-4 py-2.5 border-b"><ArrowUp className="w-4 h-4 text-gray-400" /></td>
                        <td className="px-2 py-2.5 border-b font-medium text-gray-600" colSpan={5}>..</td>
                      </tr>
                    )}
                    {sorted.map(e => {
                      const Icon = e.type === "dir" ? Folder : getFileIcon(e.name);
                      const iconColor = getFileColor(e.name, e.type === "dir");
                      const sel = selected.has(e.name);
                      const isImage = IMG_EXTS.has(e.name.includes(".") ? e.name.split(".").pop()?.toLowerCase() || "" : "");
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
                              <Icon className={`w-5 h-5 ${iconColor}`} />
                              <span className={`text-sm ${sel ? "font-medium text-blue-700" : "text-gray-800"}`}>{e.name}</span>
                            </div>
                          </td>
                          <td className="px-2 py-2.5 border-b text-xs text-gray-400 font-mono hidden lg:table-cell">{e.permissions || ""}</td>
                          <td className="px-2 py-2.5 border-b text-right text-sm text-gray-500 tabular-nums">{e.type === "dir" ? "" : formatSize(e.size)}</td>
                          <td className="px-2 py-2.5 border-b text-sm text-gray-400">{formatTime(e.modified)}</td>
                          <td className="px-2 py-2.5 border-b">
                            <div className="flex items-center gap-1">
                              {isImage && e.type === "file" && (
                                <button onClick={ev => { ev.stopPropagation(); openImagePreview(e.name); }}
                                  className="p-1 rounded hover:bg-purple-100 text-gray-400 hover:text-purple-600 transition-colors" title="Preview">
                                  <ImageIcon className="w-3.5 h-3.5" />
                                </button>
                              )}
                              <button onClick={ev => { ev.stopPropagation(); downloadFile(e.name); }}
                                className="p-1 rounded hover:bg-blue-100 text-gray-400 hover:text-blue-600 transition-colors" title="Download">
                                <Download className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
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
              {loading && sorted.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-400 text-sm">Loading...</div>
              ) : sorted.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-400 text-sm">This folder is empty</div>
              ) : (
                <div className="grid grid-cols-[repeat(auto-fill,minmax(100px,1fr))] gap-3">
                  {currentPath !== "/" && (
                    <div onClick={goUp} className="flex flex-col items-center justify-center gap-1.5 p-4 rounded-xl border-2 border-dashed border-gray-200 hover:border-blue-300 hover:bg-blue-50/50 cursor-pointer h-28">
                      <ArrowUp className="w-6 h-6 text-gray-400" />
                      <span className="text-xs text-gray-500 font-medium">..</span>
                    </div>
                  )}
                  {sorted.map(e => {
                    const Icon = e.type === "dir" ? Folder : getFileIcon(e.name);
                    const iconColor = getFileColor(e.name, e.type === "dir");
                    const sel = selected.has(e.name);
                    return (
                      <div key={e.name}
                        onClick={() => { if (e.type === "dir") navigate(e.name); else toggleSelect(e.name); }}
                        onContextMenu={ev => handleCtx(ev, e.name)}
                        className={`flex flex-col items-center justify-center gap-1.5 p-4 rounded-xl border-2 cursor-pointer transition-all h-28 ${
                          sel ? "border-blue-500 bg-blue-50 shadow-sm" : "border-gray-100 hover:border-blue-200 hover:shadow-sm bg-white"
                        }`}
                      >
                        <Icon className={`w-8 h-8 ${iconColor}`} />
                        <span className="text-xs text-center leading-tight line-clamp-2 text-gray-700 font-medium">{e.name}</span>
                        {e.type === "file" && <span className="text-[10px] text-gray-400">{formatSize(e.size)}</span>}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Image preview panel */}
        {previewData && (
          <div className="w-96 bg-gray-900 flex flex-col flex-shrink-0">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-700">
              <span className="text-xs text-gray-400 font-mono truncate">{previewFile}</span>
              <button onClick={() => { setPreviewFile(null); setPreviewData(null); }}
                className="text-gray-500 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 flex items-center justify-center p-4 overflow-auto">
              <img src={previewData} alt={previewFile || ""}
                className="max-w-full max-h-full object-contain rounded-lg shadow-2xl" />
            </div>
          </div>
        )}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <div className="fixed z-50 bg-white rounded-xl border shadow-xl py-1 w-44" style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={() => setContextMenu(null)}>
          {[
            { label: "Download", icon: Download, fn: () => downloadFile(contextMenu.name), hidden: false },
            ...(IMG_EXTS.has(contextMenu.name.includes(".") ? contextMenu.name.split(".").pop()?.toLowerCase() || "" : "") ? [{ label: "Preview", icon: ImageIcon, fn: () => openImagePreview(contextMenu.name), hidden: false }] : []),
            { label: "Edit", icon: Edit3, fn: () => editFile(contextMenu.name), hidden: !TEXT_EXTS.has(contextMenu.name.includes(".") ? contextMenu.name.split(".").pop() || "" : "") },
            { label: "Rename", icon: Edit3, fn: () => { setRenaming(contextMenu.name); setRenameVal(contextMenu.name); }, hidden: false },
            { label: "Copy To...", icon: Copy, fn: () => { setCopyTarget(contextMenu.name); setCopyDest(fp("copy_of_" + contextMenu.name)); }, hidden: false },
            { label: "Chmod", icon: Shield, fn: () => { setChmodTarget({ name: contextMenu.name, path: fp(contextMenu.name) }); setChmodVal(""); }, hidden: false },
            { label: "Properties", icon: InfoIcon, fn: () => showProperties(contextMenu.name), hidden: false },
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

      {/* Chmod modal */}
      {chmodTarget && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setChmodTarget(null)}>
          <div className="bg-white rounded-xl p-5 w-full max-w-sm shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-1 flex items-center gap-2"><Shield className="w-4 h-4 text-blue-600" />Change Permissions</h3>
            <p className="text-xs text-gray-500 mb-3 truncate">{chmodTarget.name}</p>
            <form onSubmit={e => { e.preventDefault(); doChmod(); }}>
              <label className="text-xs text-gray-500 mb-1 block">Octal mode (e.g. 755, 644)</label>
              <input value={chmodVal} onChange={e => { if (/^[0-7]{0,4}$/.test(e.target.value)) setChmodVal(e.target.value); }}
                className="w-full border rounded-lg px-3 py-2 text-sm mb-2 font-mono text-center text-lg tracking-widest focus:ring-2 focus:ring-blue-500"
                placeholder="755" maxLength={4} autoFocus />
              <div className="grid grid-cols-3 gap-2 mb-3 text-xs text-center">
                {["Owner", "Group", "Other"].map((label, i) => {
                  const digit = chmodVal.length >= i + 1 ? parseInt(chmodVal[chmodVal.length <= 3 ? i : i + 1] || "0") : 0;
                  return (
                    <div key={label} className="bg-gray-50 rounded-lg p-2">
                      <p className="font-medium text-gray-700 mb-1">{label}</p>
                      <div className="flex justify-center gap-2 text-gray-500">
                        <span className={digit & 4 ? "text-green-600 font-bold" : ""}>r</span>
                        <span className={digit & 2 ? "text-yellow-600 font-bold" : ""}>w</span>
                        <span className={digit & 1 ? "text-red-600 font-bold" : ""}>x</span>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="flex gap-2 justify-end">
                <button type="button" onClick={() => setChmodTarget(null)} className="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50">Cancel</button>
                <button type="submit" disabled={chmodVal.length < 3} className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">Apply</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Properties modal */}
      {fileStat && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setFileStat(null)}>
          <div className="bg-white rounded-xl p-5 w-full max-w-sm shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><InfoIcon className="w-4 h-4 text-blue-600" />Properties: {String(fileStat.name)}</h3>
            <div className="space-y-2 text-sm">
              {fileStat.size !== undefined && <div className="flex justify-between"><span className="text-gray-500">Size</span><span className="font-mono">{formatSize(fileStat.size as number)}</span></div>}
              {fileStat.permissions_octal && <div className="flex justify-between"><span className="text-gray-500">Permissions</span><span className="font-mono">{String(fileStat.permissions_octal)}</span></div>}
              {fileStat.uid !== undefined && <div className="flex justify-between"><span className="text-gray-500">Owner (UID)</span><span className="font-mono">{String(fileStat.uid)}</span></div>}
              {fileStat.gid !== undefined && <div className="flex justify-between"><span className="text-gray-500">Group (GID)</span><span className="font-mono">{String(fileStat.gid)}</span></div>}
              {fileStat.is_dir !== undefined && <div className="flex justify-between"><span className="text-gray-500">Type</span><span>{fileStat.is_dir ? "Directory" : fileStat.is_link ? "Symlink" : "File"}</span></div>}
              {fileStat.modified && <div className="flex justify-between"><span className="text-gray-500">Modified</span><span>{new Date((fileStat.modified as number) * 1000).toLocaleString()}</span></div>}
              {fileStat.accessed && <div className="flex justify-between"><span className="text-gray-500">Accessed</span><span>{new Date((fileStat.accessed as number) * 1000).toLocaleString()}</span></div>}
            </div>
            <div className="mt-4 flex justify-end">
              <button onClick={() => setFileStat(null)} className="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Overwrite confirmation */}
      {overwriteConfirm && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-5 w-full max-w-sm shadow-xl">
            <h3 className="text-sm font-semibold mb-2 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-amber-500" />Files Already Exist</h3>
            <p className="text-xs text-gray-500 mb-3">{overwriteConfirm.existing.length} file(s) will be overwritten:</p>
            <div className="bg-gray-50 rounded-lg p-2 mb-3 max-h-32 overflow-auto">
              {overwriteConfirm.existing.map(name => (
                <p key={name} className="text-xs font-mono text-gray-700 py-0.5">{name}</p>
              ))}
            </div>
            <div className="flex gap-2">
              <button onClick={() => setOverwriteConfirm(null)}
                className="flex-1 px-3 py-2 text-sm border rounded-lg hover:bg-gray-50">Cancel</button>
              <button onClick={async () => {
                const files = overwriteConfirm.files;
                setOverwriteConfirm(null);
                await doUploadFiles(files);
              }} className="flex-1 px-3 py-2 text-sm bg-amber-600 text-white rounded-lg hover:bg-amber-700 font-medium">
                Overwrite
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Go-to-path dialog */}
      {goToPath && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setGoToPath(false)}>
          <div className="bg-white rounded-xl p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-3">Go to Path (Ctrl+G)</h3>
            <form onSubmit={e => { e.preventDefault(); if (goToPathVal.trim()) { loadDir(goToPathVal.trim()); setGoToPath(false); } }}>
              <input value={goToPathVal} onChange={e => setGoToPathVal(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" placeholder="/home/user" autoFocus />
              <div className="flex gap-2 justify-end mt-3">
                <button type="button" onClick={() => setGoToPath(false)} className="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50">Cancel</button>
                <button type="submit" disabled={!goToPathVal.trim()} className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700">Go</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
