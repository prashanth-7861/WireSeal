import { NavLink, Outlet } from "react-router";
import {
  Wifi, TerminalSquare, Settings, Info, LogOut, ArrowLeftRight,
  Circle, WifiOff,
} from "lucide-react";

interface ClientLayoutProps {
  onLock: () => void;
  onSwitchMode: () => void;
}

const navItems = [
  { to: "/client", label: "Connect", icon: Wifi, end: true },
  { to: "/client/terminal", label: "Terminal", icon: TerminalSquare },
  { to: "/client/settings", label: "Settings", icon: Settings },
  { to: "/about", label: "About", icon: Info },
];

export function ClientLayout({ onLock, onSwitchMode }: ClientLayoutProps) {
  return (
    <div className="min-h-screen bg-gray-50">
      <aside className="fixed left-0 top-0 h-full w-60 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-5 border-b border-gray-100">
          <h1 className="font-bold text-lg text-gray-900 tracking-tight">WireSeal</h1>
          <p className="text-xs text-emerald-600 mt-0.5 font-medium">Client Mode</p>
        </div>

        <nav className="px-2 py-3 flex-1">
          {navItems.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg mb-0.5 transition-colors text-sm ${
                  isActive
                    ? "bg-emerald-50 text-emerald-700 font-medium"
                    : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Status indicators */}
        <div className="px-4 py-3 border-t border-gray-100 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <WifiOff className="w-3 h-3 text-gray-400" />
              <span className="text-xs text-gray-500">VPN Tunnel</span>
            </div>
            <span className="text-xs font-medium text-gray-400">
              Not connected
            </span>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Circle className="w-2.5 h-2.5 fill-current text-green-500" />
              <span className="text-xs text-gray-500">API Server</span>
            </div>
            <span className="text-xs font-medium text-green-600">Online</span>
          </div>
        </div>

        <div className="p-2 border-t border-gray-100 space-y-0.5">
          {/* Removed "Switch to Server" — server vs client roles are locked
              to the vault at init. clearMode() would just re-sync to
              vault.mode and flip back, leaving the user stuck. To switch
              roles, run Fresh-Start (Settings) which destroys the vault
              and lets the user re-init in the other mode. */}
          <button
            onClick={onLock}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg w-full text-gray-500 hover:bg-gray-100 hover:text-gray-700 transition-colors text-sm"
          >
            <LogOut className="w-4 h-4" />
            <span>Lock Vault</span>
          </button>
        </div>
      </aside>

      <main className="ml-60 p-8">
        <Outlet />
      </main>
    </div>
  );
}
