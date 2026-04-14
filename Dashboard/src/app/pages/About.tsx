import { useState, useCallback } from "react";
import {
  Shield, Lock, Key, Layers, Github, Terminal, Globe, ExternalLink, User,
  RefreshCw, CheckCircle, AlertTriangle, ArrowUpRight, Heart, BookOpen,
  Tag, Clock, ChevronDown, ChevronUp, Download,
} from "lucide-react";

/* ───────────────────────── Constants ───────────────────────── */

const CURRENT_VERSION = "0.7.7";
const GITHUB_URL = "https://github.com/prashanth-7861/WireSeal";

const FEATURES = [
  {
    icon: Lock,
    title: "Dual-layer AEAD Encryption",
    description:
      "All vault data is encrypted with ChaCha20-Poly1305 (inner) and AES-256-GCM-SIV (outer) using HKDF-SHA512 key separation. Zero plaintext secrets ever touch disk.",
  },
  {
    icon: Key,
    title: "Argon2id Key Derivation",
    description:
      "Your passphrase is stretched with Argon2id (time_cost=6, memory=64 MB, parallelism=4) before any cryptographic operation — resistant to GPU brute-force.",
  },
  {
    icon: Layers,
    title: "Automatic WireGuard Management",
    description:
      "Generates server and client keypairs, pre-shared keys, IP pool allocation, and deploys configs — all from a single CLI command.",
  },
  {
    icon: Shield,
    title: "Sigstore-signed Releases",
    description:
      "Every release binary is signed with Sigstore keyless OIDC signing. No long-lived private key is stored — the signature is tied to the GitHub Actions workflow.",
  },
  {
    icon: Globe,
    title: "Cross-platform",
    description:
      "Runs on Linux (Debian/Ubuntu, Fedora/RHEL/Arch), macOS (Apple Silicon), and Windows. Platform detection adapts commands and config paths automatically.",
  },
  {
    icon: Terminal,
    title: "Headless CLI + Web Dashboard",
    description:
      "Full CLI for scripted/automated environments. Run `wireseal serve` to expose this dashboard and REST API on localhost for a graphical management experience.",
  },
];

interface ChangelogEntry {
  version: string;
  date: string;
  highlights: string[];
}

const CHANGELOG: ChangelogEntry[] = [
  {
    version: "0.7.7",
    date: "2026-04-13",
    highlights: [
      "Server no longer auto-starts on unlock — user explicitly controls the WireGuard tunnel lifecycle from the Dashboard",
      "Dashboard shows a green Start Server button when stopped and a red Stop Server button when running",
    ],
  },
  {
    version: "0.7.6",
    date: "2026-04-13",
    highlights: [
      "SSH Terminal: full xterm.js browser terminal for remote server shells over the WireGuard tunnel",
      "WebSocket SSH bridge powered by AsyncSSH with one-time-token auth — passwords never touch URLs or logs",
      "Session recording to ~/.wireseal/ssh-sessions/ with timestamped input/output for audit trails",
      "Tunnel-gated: SSH token issuance requires an active WireGuard client profile",
      "Client Mode → Connect → Terminal: import a profile, bring the tunnel up, and open a shell without leaving the Dashboard",
    ],
  },
  {
    version: "0.7.5",
    date: "2026-04-13",
    highlights: [
      "Client Mode: server/client mode selection after unlock — switch between managing and connecting",
      "Client layout with emerald-accented sidebar, Connect/Terminal/Settings stubs",
      "Mode persists across sessions via localStorage; switch freely from either sidebar",
    ],
  },
  {
    version: "0.7.4",
    date: "2026-04-13",
    highlights: [
      "Auto-update: Check for Updates now downloads and installs new releases automatically",
      "Backend /api/update/check and /api/update/install endpoints for cross-platform updates",
      "Silent NSIS installer upgrade on Windows; atomic binary replace on Linux/macOS",
    ],
  },
  {
    version: "0.7.3",
    date: "2026-04-13",
    highlights: [
      "Welcome screen shows wax-seal logo instead of generic icon",
      "About page: Check for Updates button, expandable Changelog, Credits & Acknowledgements",
    ],
  },
  {
    version: "0.7.2",
    date: "2026-04-12",
    highlights: [
      "Custom wax-seal app icon across all platforms (Windows EXE, NSIS installer, Dashboard favicon)",
      "Multi-size ICO (16–256px) embedded in Windows builds",
    ],
  },
  {
    version: "0.7.1",
    date: "2026-04-12",
    highlights: [
      "Fixed Windows installer: CLI binary moved to bin\\ subdirectory to avoid NTFS case-insensitive collision with GUI bootloader",
      "PATH updated to $INSTDIR\\bin for CLI; stale entries from pre-fix installs are scrubbed automatically",
    ],
  },
  {
    version: "0.7.0",
    date: "2026-04-10",
    highlights: [
      "Windows GUI switched from PyInstaller onefile to onedir — fixes pywebview native window loading",
      "NSIS installer with Start Menu + Desktop shortcuts, de-elevated launch for WebView2 compatibility",
      "Portable zip and setup.exe published as release assets with Sigstore signatures",
    ],
  },
  {
    version: "0.6.0",
    date: "2026-04-09",
    highlights: [
      "Multi-admin vault with role-based access (owner / admin / viewer)",
      "TOTP two-factor authentication enrollment and verification",
      "Ephemeral client keys with configurable TTL and auto-expiry",
      "Split-DNS configuration support",
      "Local encrypted backup and restore",
    ],
  },
  {
    version: "0.5.0",
    date: "2026-04-07",
    highlights: [
      "Web Dashboard with real-time WireGuard status monitoring",
      "Client management UI (add, remove, QR codes)",
      "Audit log viewer with filtering",
      "Security settings and passphrase management",
    ],
  },
];

interface Credit {
  name: string;
  url: string;
  description: string;
  license: string;
}

const CREDITS: Credit[] = [
  {
    name: "WireGuard",
    url: "https://www.wireguard.com",
    description: "Fast, modern, secure VPN tunnel. The core protocol that WireSeal automates and manages.",
    license: "GPL-2.0",
  },
  {
    name: "Python",
    url: "https://www.python.org",
    description: "The programming language powering the WireSeal backend, CLI, and vault engine.",
    license: "PSF License",
  },
  {
    name: "pywebview",
    url: "https://pywebview.flowrl.com",
    description: "Lightweight cross-platform webview wrapper that gives WireSeal its native desktop window.",
    license: "BSD-3-Clause",
  },
  {
    name: "cryptography",
    url: "https://cryptography.io",
    description: "The Python cryptographic library providing ChaCha20-Poly1305, AES-256-GCM-SIV, HKDF, and X25519.",
    license: "Apache-2.0 / BSD-3-Clause",
  },
  {
    name: "argon2-cffi",
    url: "https://argon2-cffi.readthedocs.io",
    description: "Argon2id password hashing — the memory-hard KDF protecting your vault passphrase.",
    license: "MIT",
  },
  {
    name: "React",
    url: "https://react.dev",
    description: "The UI library powering this Dashboard.",
    license: "MIT",
  },
  {
    name: "Tailwind CSS",
    url: "https://tailwindcss.com",
    description: "Utility-first CSS framework used for all Dashboard styling.",
    license: "MIT",
  },
  {
    name: "Radix UI",
    url: "https://www.radix-ui.com",
    description: "Unstyled, accessible UI primitives for the Dashboard's dialogs, menus, and controls.",
    license: "MIT",
  },
  {
    name: "Vite",
    url: "https://vite.dev",
    description: "Next-generation frontend build tool for the Dashboard.",
    license: "MIT",
  },
  {
    name: "Lucide",
    url: "https://lucide.dev",
    description: "Beautiful, consistent icon set used throughout the Dashboard.",
    license: "ISC",
  },
  {
    name: "Click",
    url: "https://click.palletsprojects.com",
    description: "Python CLI framework for the wireseal command-line interface.",
    license: "BSD-3-Clause",
  },
  {
    name: "PyInstaller",
    url: "https://pyinstaller.org",
    description: "Bundles WireSeal into standalone executables for Windows, macOS, and Linux.",
    license: "GPL-2.0 (bootloader: Apache-2.0)",
  },
  {
    name: "Jinja2",
    url: "https://jinja.palletsprojects.com",
    description: "Template engine for generating WireGuard configuration files.",
    license: "BSD-3-Clause",
  },
  {
    name: "Sigstore",
    url: "https://www.sigstore.dev",
    description: "Keyless code signing for release binaries — every artifact is verifiable without a long-lived key.",
    license: "Apache-2.0",
  },
];

/* ───────────────────────── Auto-Update Hook ───────────────────────── */

type UpdateState =
  | "idle"
  | "checking"
  | "up-to-date"
  | "update-available"
  | "downloading"
  | "installing"
  | "done"
  | "error";

interface UpdateInfo {
  latestVersion: string;
  releaseUrl: string;
  publishedAt: string;
  assetName: string;
}

function useAutoUpdate() {
  const [state, setState] = useState<UpdateState>("idle");
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const check = useCallback(async () => {
    setState("checking");
    setError("");
    setMessage("");
    try {
      const res = await fetch("/api/update/check");
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setInfo({
        latestVersion: data.latest_version,
        releaseUrl: data.release_url,
        publishedAt: data.published_at,
        assetName: data.asset_name,
      });
      if (data.update_available) {
        setState("update-available");
      } else {
        setState("up-to-date");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to check for updates");
      setState("error");
    }
  }, []);

  const install = useCallback(async () => {
    setState("downloading");
    setError("");
    setMessage("");
    try {
      // Brief pause so UI shows "downloading" state
      setState("installing");
      const res = await fetch("/api/update/install", { method: "POST" });
      if (!res.ok) {
        const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        throw new Error(data.error || `Install failed (${res.status})`);
      }
      const data = await res.json();
      setMessage(data.message);
      setState("done");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Update failed");
      setState("error");
    }
  }, []);

  return { state, info, error, message, check, install };
}

/* ───────────────────────── Component ───────────────────────── */

export function About() {
  const update = useAutoUpdate();
  const [changelogExpanded, setChangelogExpanded] = useState(false);
  const visibleChangelog = changelogExpanded ? CHANGELOG : CHANGELOG.slice(0, 3);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">About WireSeal</h1>
        <p className="text-gray-500 mt-1">WireGuard server automation with zero plaintext secrets on disk</p>
      </div>

      {/* Hero card */}
      <div className="bg-gradient-to-br from-blue-600 to-blue-800 rounded-xl p-8 mb-8 text-white">
        <div className="flex items-center gap-4 mb-4">
          <img
            src="/wireseal-192.png"
            alt="WireSeal"
            width={64}
            height={64}
            className="rounded-xl drop-shadow-lg"
          />
          <div>
            <h2 className="text-2xl font-bold">WireSeal</h2>
            <p className="text-blue-200 text-sm">Secure · Automated · Cross-platform</p>
            <p className="text-blue-300/70 text-xs mt-0.5 font-mono">v{CURRENT_VERSION}</p>
          </div>
        </div>
        <p className="text-blue-100 leading-relaxed max-w-xl">
          WireSeal automates WireGuard server setup and client management while keeping every
          cryptographic secret encrypted at all times. Unlike plain-text config approaches,
          WireSeal wraps everything in a dual-layer AEAD vault derived from your passphrase.
        </p>

        <div className="mt-6 flex flex-wrap gap-3">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 bg-white/20 hover:bg-white/30 transition-colors px-4 py-2 rounded-lg text-sm font-medium"
          >
            <Github className="w-4 h-4" />
            GitHub
          </a>
          <span className="inline-flex items-center gap-2 bg-white/10 px-4 py-2 rounded-lg text-sm">
            MIT License
          </span>
          {/* Check for Updates button */}
          <button
            onClick={update.check}
            disabled={update.state === "checking" || update.state === "downloading" || update.state === "installing"}
            className="inline-flex items-center gap-2 bg-white/20 hover:bg-white/30 disabled:opacity-60 transition-colors px-4 py-2 rounded-lg text-sm font-medium cursor-pointer disabled:cursor-wait"
          >
            <RefreshCw className={`w-4 h-4 ${update.state === "checking" ? "animate-spin" : ""}`} />
            {update.state === "checking" ? "Checking..." : "Check for Updates"}
          </button>
        </div>

        {/* Update result banners */}
        {update.state === "up-to-date" && (
          <div className="mt-4 flex items-center gap-2 bg-green-500/20 border border-green-400/30 rounded-lg px-4 py-2.5 text-sm">
            <CheckCircle className="w-4 h-4 text-green-300 flex-shrink-0" />
            <span className="text-green-100">You're on the latest version (v{CURRENT_VERSION}).</span>
          </div>
        )}
        {update.state === "update-available" && update.info && (
          <div className="mt-4 bg-amber-500/20 border border-amber-400/30 rounded-lg px-4 py-3 text-sm">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-300 flex-shrink-0" />
                <span className="text-amber-100">
                  Update available: <strong>v{update.info.latestVersion}</strong>
                  <span className="text-amber-200/60 ml-1">(you have v{CURRENT_VERSION})</span>
                </span>
              </div>
              <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                <button
                  onClick={update.install}
                  className="inline-flex items-center gap-1.5 bg-amber-500 hover:bg-amber-400 text-white px-3 py-1.5 rounded-md text-sm font-medium transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  Install Now
                </button>
                <a
                  href={update.info.releaseUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-amber-200 hover:text-white transition-colors text-xs"
                >
                  Release notes
                  <ArrowUpRight className="w-3 h-3" />
                </a>
              </div>
            </div>
            {update.info.assetName && (
              <p className="text-amber-200/50 text-xs mt-1.5 ml-6">{update.info.assetName}</p>
            )}
          </div>
        )}
        {(update.state === "downloading" || update.state === "installing") && (
          <div className="mt-4 flex items-center gap-2 bg-blue-500/20 border border-blue-400/30 rounded-lg px-4 py-2.5 text-sm">
            <RefreshCw className="w-4 h-4 text-blue-300 flex-shrink-0 animate-spin" />
            <span className="text-blue-100">
              {update.state === "downloading" ? "Downloading update..." : "Installing update..."}
            </span>
          </div>
        )}
        {update.state === "done" && (
          <div className="mt-4 flex items-center gap-2 bg-green-500/20 border border-green-400/30 rounded-lg px-4 py-2.5 text-sm">
            <CheckCircle className="w-4 h-4 text-green-300 flex-shrink-0" />
            <span className="text-green-100">{update.message}</span>
          </div>
        )}
        {update.state === "error" && (
          <div className="mt-4 flex items-center gap-2 bg-red-500/20 border border-red-400/30 rounded-lg px-4 py-2.5 text-sm">
            <AlertTriangle className="w-4 h-4 text-red-300 flex-shrink-0" />
            <span className="text-red-200">{update.error}</span>
          </div>
        )}

        {/* Developer info */}
        <div className="mt-6 pt-6 border-t border-white/20">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/20 rounded-full flex items-center justify-center">
              <User className="w-5 h-5 text-white" />
            </div>
            <div>
              <p className="text-sm text-blue-200">Developed by</p>
              <p className="font-semibold">Prashanth Mudigonda</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-3 mt-3 ml-[52px]">
            <a
              href="https://github.com/prashanth-7861"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-blue-200 hover:text-white transition-colors text-sm"
            >
              <Github className="w-3.5 h-3.5" />
              prashanth-7861
              <ExternalLink className="w-3 h-3" />
            </a>
            <a
              href="https://prashanth-mudigonda.vercel.app/"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-blue-200 hover:text-white transition-colors text-sm"
            >
              <Globe className="w-3.5 h-3.5" />
              Portfolio
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>

      {/* Features grid */}
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Key Features</h2>
      <div className="grid grid-cols-2 gap-4 mb-8">
        {FEATURES.map(({ icon: Icon, title, description }) => (
          <div key={title} className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
            <div className="flex items-start gap-4">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                <Icon className="w-5 h-5 text-blue-700" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900 mb-1">{title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{description}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Changelog */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
        <div className="flex items-center gap-2 mb-5">
          <BookOpen className="w-5 h-5 text-gray-700" />
          <h2 className="text-lg font-semibold text-gray-900">Changelog</h2>
        </div>
        <div className="space-y-5">
          {visibleChangelog.map((entry, idx) => (
            <div key={entry.version} className={idx > 0 ? "pt-5 border-t border-gray-100" : ""}>
              <div className="flex items-center gap-3 mb-2">
                <span className="inline-flex items-center gap-1.5 bg-blue-100 text-blue-700 px-2.5 py-0.5 rounded-full text-sm font-semibold">
                  <Tag className="w-3.5 h-3.5" />
                  v{entry.version}
                </span>
                <span className="inline-flex items-center gap-1 text-gray-400 text-xs">
                  <Clock className="w-3 h-3" />
                  {entry.date}
                </span>
                {idx === 0 && (
                  <span className="bg-green-100 text-green-700 text-xs px-2 py-0.5 rounded-full font-medium">
                    Latest
                  </span>
                )}
              </div>
              <ul className="space-y-1 ml-1">
                {entry.highlights.map((h, i) => (
                  <li key={i} className="text-sm text-gray-600 leading-relaxed flex items-start gap-2">
                    <span className="text-blue-400 mt-1.5 flex-shrink-0">&#x2022;</span>
                    {h}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        {CHANGELOG.length > 3 && (
          <button
            onClick={() => setChangelogExpanded((prev) => !prev)}
            className="mt-4 flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-800 transition-colors font-medium"
          >
            {changelogExpanded ? (
              <>
                <ChevronUp className="w-4 h-4" />
                Show less
              </>
            ) : (
              <>
                <ChevronDown className="w-4 h-4" />
                Show older releases ({CHANGELOG.length - 3} more)
              </>
            )}
          </button>
        )}
      </div>

      {/* Credits & Acknowledgements */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
        <div className="flex items-center gap-2 mb-2">
          <Heart className="w-5 h-5 text-rose-500" />
          <h2 className="text-lg font-semibold text-gray-900">Credits &amp; Acknowledgements</h2>
        </div>
        <p className="text-sm text-gray-500 mb-5">
          WireSeal is built on the shoulders of these incredible open-source projects.
        </p>
        <div className="grid grid-cols-2 gap-3">
          {CREDITS.map(({ name, url, description, license }) => (
            <a
              key={name}
              href={url}
              target="_blank"
              rel="noreferrer"
              className="group flex items-start gap-3 p-3 rounded-lg border border-gray-100 hover:border-blue-200 hover:bg-blue-50/50 transition-colors"
            >
              <div className="w-8 h-8 bg-gray-100 group-hover:bg-blue-100 rounded-md flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors">
                <ExternalLink className="w-3.5 h-3.5 text-gray-400 group-hover:text-blue-600 transition-colors" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-gray-900 text-sm group-hover:text-blue-700 transition-colors">
                    {name}
                  </span>
                  <span className="text-[10px] text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded font-mono">
                    {license}
                  </span>
                </div>
                <p className="text-xs text-gray-500 leading-relaxed mt-0.5">{description}</p>
              </div>
            </a>
          ))}
        </div>
      </div>

      {/* Quick reference */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Reference</h2>
        <div className="space-y-3">
          {[
            { cmd: "wireseal init", desc: "First-time vault and WireGuard setup" },
            { cmd: "wireseal add-client <name>", desc: "Generate a new WireGuard client" },
            { cmd: "wireseal list-clients", desc: "Show all registered clients" },
            { cmd: "wireseal remove-client <name>", desc: "Revoke a client's access" },
            { cmd: "wireseal show-qr <name>", desc: "Display client QR code in terminal" },
            { cmd: "wireseal serve", desc: "Start this web dashboard (port 8080)" },
          ].map(({ cmd, desc }) => (
            <div key={cmd} className="flex items-start gap-4">
              <code className="text-sm bg-gray-100 text-gray-800 px-3 py-1 rounded font-mono whitespace-nowrap">
                {cmd}
              </code>
              <span className="text-sm text-gray-500 pt-1">{desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
