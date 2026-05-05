import { useState, useEffect, useRef, useCallback } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import { TerminalSquare, Play, Square, AlertTriangle } from "lucide-react";
import { api, ClientTunnelStatus } from "../../api";

/**
 * Base64-decode a string to a Uint8Array (binary-safe, unlike atob() for
 * non-UTF-8 bytes).
 */
function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

interface ConnectForm {
  host: string;
  port: string;
  username: string;
  password: string;
}

export function Terminal() {
  const termContainerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const decoderRef = useRef<TextDecoder>(new TextDecoder("utf-8", { fatal: false }));

  const [tunnel, setTunnel] = useState<ClientTunnelStatus | null>(null);
  const [connectForm, setConnectForm] = useState<ConnectForm>({
    host: "",
    port: "22",
    username: "",
    password: "",
  });
  const [connecting, setConnecting] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const [tofuPrompt, setTofuPrompt] = useState<{
    fingerprint: string;
    key_export: string;
    host: string;
    port: number;
  } | null>(null);
  const [tofuAccepting, setTofuAccepting] = useState(false);

  // Load tunnel status on mount
  useEffect(() => {
    api.clientTunnelStatus()
      .then(setTunnel)
      .catch(() => setTunnel(null));
  }, []);

  // Initialize xterm once
  useEffect(() => {
    if (!termContainerRef.current || termRef.current) return;

    const term = new XTerm({
      fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, Monaco, Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.2,
      cursorBlink: true,
      cursorStyle: "block",
      allowProposedApi: true,
      theme: {
        background: "#0b0f14",
        foreground: "#d4d4d4",
        cursor: "#10b981",
        selectionBackground: "rgba(16, 185, 129, 0.3)",
        black: "#000000",
        red: "#f87171",
        green: "#10b981",
        yellow: "#fbbf24",
        blue: "#60a5fa",
        magenta: "#c084fc",
        cyan: "#22d3ee",
        white: "#e5e7eb",
      },
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(termContainerRef.current);
    fit.fit();

    term.writeln("\x1b[90mWireSeal SSH Terminal\x1b[0m");
    term.writeln("\x1b[90mConnect to a server to start a session.\x1b[0m");
    term.writeln("");

    termRef.current = term;
    fitRef.current = fit;

    const onResize = () => {
      try {
        fit.fit();
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({
            type: "resize",
            cols: term.cols,
            rows: term.rows,
          }));
        }
      } catch { /* ignore */ }
    };
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, []);

  // Forward keystrokes to WS when connected
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    const disp = term.onData((data: string) => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: "input", data }));
      }
    });
    return () => disp.dispose();
  }, [connected]);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      try { wsRef.current.close(); } catch { /* ignore */ }
      wsRef.current = null;
    }
    setConnected(false);
    setConnecting(false);
  }, []);

  const handleAcceptHostKey = useCallback(async () => {
    if (!tofuPrompt) return;
    setTofuAccepting(true);
    try {
      await api.sshAcceptHostKey({
        host: tofuPrompt.host,
        port: tofuPrompt.port,
        key_export: tofuPrompt.key_export,
      });
      setTofuPrompt(null);
      termRef.current?.writeln(`\x1b[32m✓ Host key accepted — reconnecting...\x1b[0m`);
      // Small delay so user sees the confirmation before connect clears it
      setTimeout(() => handleConnect(), 300);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to accept host key";
      setError(msg);
    } finally {
      setTofuAccepting(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tofuPrompt]);

  const handleConnect = async () => {
    setError("");
    const host = connectForm.host.trim();
    const port = parseInt(connectForm.port, 10) || 22;
    const username = connectForm.username.trim();
    const password = connectForm.password;

    if (!host || !username) {
      setError("Host and username are required");
      return;
    }
    if (!tunnel?.connected) {
      setError("Connect a WireGuard profile first (Connect page)");
      return;
    }

    setConnecting(true);

    const term = termRef.current;
    if (term) {
      term.clear();
      term.writeln(`\x1b[90mRequesting SSH token for \x1b[36m${username}@${host}:${port}\x1b[90m...\x1b[0m`);
    }

    let wsUrl = "";
    try {
      const tokenRes = await api.sshToken({
        host,
        port,
        username,
        password,
        profile_name: tunnel.profile || "unknown",
      });
      wsUrl = tokenRes.ws_url;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to get SSH token";
      setError(msg);
      setConnecting(false);
      term?.writeln(`\x1b[31m✗ ${msg}\x1b[0m`);
      return;
    }

    // Open the WebSocket to the bridge
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        term?.writeln("\x1b[90mWebSocket connected, waiting for SSH...\x1b[0m");
        // Send initial resize so the remote PTY matches the visible grid
        if (term) {
          ws.send(JSON.stringify({
            type: "resize",
            cols: term.cols,
            rows: term.rows,
          }));
        }
      };

      ws.onmessage = (evt: MessageEvent) => {
        if (typeof evt.data !== "string") return;
        let msg: { type: string; data?: string; message?: string; session_id?: string; fingerprint?: string; key_export?: string; host?: string; port?: number };
        try {
          msg = JSON.parse(evt.data);
        } catch {
          return;
        }

        switch (msg.type) {
          case "ready":
            setConnecting(false);
            setConnected(true);
            term?.writeln(`\x1b[32m✓ SSH session established\x1b[0m`);
            term?.writeln("");
            term?.focus();
            break;
          case "output":
            if (msg.data && term) {
              const bytes = base64ToBytes(msg.data);
              const text = decoderRef.current.decode(bytes, { stream: true });
              term.write(text);
            }
            break;
          case "tofu":
            term?.writeln(`\x1b[33m⚠ Unknown host key — verify before connecting\x1b[0m`);
            setConnecting(false);
            setTofuPrompt({
              fingerprint: msg.fingerprint ?? "<unknown>",
              key_export: msg.key_export ?? "",
              host: msg.host ?? connectForm.host,
              port: msg.port ?? (parseInt(connectForm.port, 10) || 22),
            });
            disconnect();
            break;
          case "error":
            term?.writeln(`\x1b[31m✗ ${msg.message ?? "Unknown error"}\x1b[0m`);
            setError(msg.message ?? "SSH error");
            setConnecting(false);
            break;
          case "closed":
            term?.writeln(`\x1b[90m-- session ended --\x1b[0m`);
            disconnect();
            break;
          case "pong":
            break;
          default:
            break;
        }
      };

      ws.onerror = () => {
        term?.writeln(`\x1b[31m✗ WebSocket error\x1b[0m`);
        setError("WebSocket connection failed");
        setConnecting(false);
      };

      ws.onclose = () => {
        if (connected) {
          term?.writeln(`\x1b[90m-- disconnected --\x1b[0m`);
        }
        setConnected(false);
        setConnecting(false);
        wsRef.current = null;
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "WebSocket failed";
      setError(msg);
      setConnecting(false);
      term?.writeln(`\x1b[31m✗ ${msg}\x1b[0m`);
    }
  };

  // Re-fit terminal on every render (layout shifts, sidebar changes, etc.)
  useEffect(() => {
    const id = setTimeout(() => {
      try { fitRef.current?.fit(); } catch { /* ignore */ }
    }, 50);
    return () => clearTimeout(id);
  }, [connected, connecting]);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-semibold text-gray-900">SSH Terminal</h1>
        <p className="text-gray-500 mt-1">
          Secure shell access to your server over the WireGuard tunnel
        </p>
      </div>

      {/* Tunnel status warning */}
      {!tunnel?.connected && (
        <div className="mb-4 bg-yellow-50 border border-yellow-200 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-yellow-600 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-yellow-800">
            No WireGuard tunnel active. SSH can only run over the VPN — connect a profile on the{" "}
            <strong>Connect</strong> page first.
          </p>
        </div>
      )}

      {/* TOFU host-key verification prompt */}
      {tofuPrompt && (
        <div className="mb-4 bg-yellow-50 border border-yellow-300 rounded-lg p-4">
          <div className="flex items-start gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-yellow-600 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-sm font-semibold text-yellow-900">Unknown SSH host key</p>
              <p className="text-xs text-yellow-800 mt-0.5">
                The server at <strong>{tofuPrompt.host}:{tofuPrompt.port}</strong> presented a key that has not been verified.
              </p>
            </div>
          </div>
          <div className="bg-yellow-100 rounded px-3 py-2 mb-3 font-mono text-xs text-yellow-900 break-all">
            {tofuPrompt.fingerprint}
          </div>
          <p className="text-xs text-yellow-700 mb-3">
            Only accept if you recognise this fingerprint. Accepting an unknown key risks connecting to a malicious host.
          </p>
          <div className="flex gap-2">
            <button
              onClick={handleAcceptHostKey}
              disabled={tofuAccepting || !tofuPrompt.key_export}
              className="px-4 py-1.5 bg-emerald-600 text-white text-sm rounded-lg hover:bg-emerald-700 disabled:opacity-50 transition-colors font-medium"
            >
              {tofuAccepting ? "Accepting..." : "Accept & Connect"}
            </button>
            <button
              onClick={() => setTofuPrompt(null)}
              className="px-4 py-1.5 bg-white border border-gray-300 text-gray-700 text-sm rounded-lg hover:bg-gray-50 transition-colors"
            >
              Reject
            </button>
          </div>
          {!tofuPrompt.key_export && (
            <p className="text-xs text-red-600 mt-2">Key export unavailable — cannot accept automatically. Add the fingerprint manually.</p>
          )}
        </div>
      )}

      {/* Connection form */}
      {!connected && (
        <div className="bg-white rounded-lg border border-gray-200 p-4 mb-4">
          <div className="grid grid-cols-12 gap-3">
            <div className="col-span-5">
              <label className="block text-xs font-medium text-gray-600 mb-1">Host</label>
              <input
                type="text"
                value={connectForm.host}
                onChange={(e) => setConnectForm({ ...connectForm, host: e.target.value })}
                placeholder="10.0.0.1"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
                disabled={connecting}
              />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-600 mb-1">Port</label>
              <input
                type="number"
                value={connectForm.port}
                onChange={(e) => setConnectForm({ ...connectForm, port: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
                disabled={connecting}
              />
            </div>
            <div className="col-span-5">
              <label className="block text-xs font-medium text-gray-600 mb-1">Username</label>
              <input
                type="text"
                value={connectForm.username}
                onChange={(e) => setConnectForm({ ...connectForm, username: e.target.value })}
                placeholder="root"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
                disabled={connecting}
              />
            </div>
            <div className="col-span-10">
              <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
              <input
                type="password"
                value={connectForm.password}
                onChange={(e) => setConnectForm({ ...connectForm, password: e.target.value })}
                onKeyDown={(e) => { if (e.key === "Enter") handleConnect(); }}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
                disabled={connecting}
              />
            </div>
            <div className="col-span-2 flex items-end">
              <button
                onClick={handleConnect}
                disabled={connecting || !tunnel?.connected}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors text-sm font-medium disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                {connecting ? "..." : "Connect"}
              </button>
            </div>
          </div>
          {error && (
            <p className="text-sm text-red-600 mt-2">{error}</p>
          )}
        </div>
      )}

      {/* Terminal chrome */}
      <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-gray-800 border-b border-gray-700">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-green-500/80" />
            </div>
            <span className="text-gray-400 text-xs ml-2 font-mono">
              {connected
                ? `ssh — ${connectForm.username}@${connectForm.host}`
                : connecting
                ? "ssh — connecting..."
                : "ssh — not connected"}
            </span>
          </div>
          {connected && (
            <button
              onClick={disconnect}
              className="flex items-center gap-1.5 px-2 py-1 bg-red-500/80 hover:bg-red-500 text-white rounded text-xs"
            >
              <Square className="w-3 h-3" />
              Disconnect
            </button>
          )}
        </div>
        <div
          ref={termContainerRef}
          className="p-2"
          style={{ height: "calc(100vh - 360px)", minHeight: "320px" }}
        />
      </div>

      {!connected && !connecting && (
        <div className="mt-2 text-xs text-gray-400 flex items-center gap-1.5">
          <TerminalSquare className="w-3 h-3" />
          Tip: sessions are recorded to <code className="text-gray-500">~/.wireseal/ssh-sessions/</code>
        </div>
      )}
    </div>
  );
}
