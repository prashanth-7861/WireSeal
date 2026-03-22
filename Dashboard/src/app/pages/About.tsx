import { Shield, Lock, Key, Layers, Github, Terminal, Globe } from "lucide-react";

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

export function About() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">About WireSeal</h1>
        <p className="text-gray-500 mt-1">WireGuard server automation with zero plaintext secrets on disk</p>
      </div>

      {/* Hero card */}
      <div className="bg-gradient-to-br from-blue-600 to-blue-800 rounded-xl p-8 mb-8 text-white">
        <div className="flex items-center gap-4 mb-4">
          <div className="w-16 h-16 bg-white/20 rounded-2xl flex items-center justify-center">
            <Shield className="w-9 h-9 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">WireSeal</h2>
            <p className="text-blue-200 text-sm">Secure · Automated · Cross-platform</p>
          </div>
        </div>
        <p className="text-blue-100 leading-relaxed max-w-xl">
          WireSeal automates WireGuard server setup and client management while keeping every
          cryptographic secret encrypted at all times. Unlike plain-text config approaches,
          WireSeal wraps everything in a dual-layer AEAD vault derived from your passphrase.
        </p>

        <div className="mt-6 flex flex-wrap gap-3">
          <a
            href="https://github.com/prashanth-7861/WireSeal"
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
