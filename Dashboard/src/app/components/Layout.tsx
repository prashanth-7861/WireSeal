import { NavLink, Outlet } from "react-router";
import { Server, ScrollText, Monitor, Settings, LogOut, Info } from "lucide-react";
import { api } from "../api";

export function Layout() {
  const navItems = [
    { to: "/", label: "Dashboard", icon: Server, end: true },
    { to: "/clients", label: "Clients", icon: Monitor },
    { to: "/audit-log", label: "Audit Log", icon: ScrollText },
    { to: "/settings", label: "Settings", icon: Settings },
    { to: "/about", label: "About", icon: Info },
  ];

  const handleLock = async () => {
    try { await api.lock(); } catch { /* ignore */ }
    window.location.reload();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-60 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-5 border-b border-gray-100">
          <h1 className="font-bold text-lg text-gray-900 tracking-tight">WireSeal</h1>
          <p className="text-xs text-gray-400 mt-0.5">WireGuard Dashboard</p>
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
                    ? "bg-blue-50 text-blue-700 font-medium"
                    : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="p-2 border-t border-gray-100">
          <button
            onClick={handleLock}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg w-full text-gray-500 hover:bg-gray-100 hover:text-gray-700 transition-colors text-sm"
          >
            <LogOut className="w-4 h-4" />
            <span>Lock Vault</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="ml-60 p-8">
        <Outlet />
      </main>
    </div>
  );
}
