import { NavLink } from "react-router";
import {
  Server, ScrollText, Monitor, Settings, LogOut, Info,
  Shield, ShieldAlert, Wifi, WifiOff, Circle, KeyRound,
  Trash2, Timer,
} from "lucide-react";
import { type Status } from "../api";

interface NavItem {
  to: string;
  label: string;
  icon: typeof Server;
  end?: boolean;
}

interface ServerSidebarProps {
  navItems: NavItem[];
  apiOnline: boolean;
  serverStatus: Status | null;
  pinSet: boolean;
  adminActive: boolean;
  adminExpiresIn: number;
  onLock: () => void;
  onAdminDeactivate: () => void;
  onShowPinSetup: () => void;
  onShowAdminAuth: () => void;
  onRemovePin: () => void;
}

export function ServerSidebar({
  navItems, apiOnline, serverStatus, pinSet,
  adminActive, adminExpiresIn,
  onLock, onAdminDeactivate, onShowPinSetup, onShowAdminAuth, onRemovePin,
}: ServerSidebarProps) {
  return (
    <aside className="fixed left-0 top-0 h-full w-60 bg-white border-r border-gray-200 flex flex-col">
      <div className="p-5 border-b border-gray-100">
        <h1 className="font-bold text-lg text-gray-900 tracking-tight">WireSeal</h1>
        <p className="text-xs text-blue-600 mt-0.5 font-medium">Server Mode</p>
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

      <div className="px-4 py-3 border-t border-gray-100 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Circle className={`w-2.5 h-2.5 fill-current ${apiOnline ? "text-green-500" : "text-red-500"}`} />
            <span className="text-xs text-gray-500">API Server</span>
          </div>
          <span className={`text-xs font-medium ${apiOnline ? "text-green-600" : "text-red-500"}`}>
            {apiOnline ? "Online" : "Offline"}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {serverStatus?.running
              ? <Wifi className="w-3 h-3 text-green-500" />
              : <WifiOff className="w-3 h-3 text-gray-400" />}
            <span className="text-xs text-gray-500">WireGuard</span>
          </div>
          <span className={`text-xs font-medium ${serverStatus?.running ? "text-green-600" : "text-gray-400"}`}>
            {serverStatus?.running ? "Running" : "Stopped"}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className={`w-3 h-3 ${pinSet ? "text-green-500" : "text-gray-400"}`} />
            <span className="text-xs text-gray-500">Quick PIN</span>
          </div>
          {pinSet ? (
            <button
              onClick={onRemovePin}
              className="text-xs text-red-500 hover:text-red-600 flex items-center gap-1 transition-colors"
              title="Remove PIN"
            >
              <Trash2 className="w-3 h-3" />
              Remove
            </button>
          ) : (
            <button
              onClick={onShowPinSetup}
              className="text-xs text-blue-500 hover:text-blue-600 transition-colors"
            >
              Set PIN
            </button>
          )}
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className={`w-3 h-3 ${adminActive ? "text-red-500" : "text-gray-400"}`} />
            <span className="text-xs text-gray-500">Admin Mode</span>
          </div>
          {adminActive ? (
            <div className="flex items-center gap-1">
              <span className="text-xs text-red-500 flex items-center gap-0.5">
                <Timer className="w-3 h-3" />
                {Math.ceil(adminExpiresIn / 60)}m
              </span>
              <button
                onClick={onAdminDeactivate}
                className="text-xs text-gray-400 hover:text-gray-600 ml-1 transition-colors"
                title="Deactivate admin mode"
              >
                &times;
              </button>
            </div>
          ) : (
            <button
              onClick={onShowAdminAuth}
              className="text-xs text-red-500 hover:text-red-600 transition-colors"
            >
              Activate
            </button>
          )}
        </div>
      </div>

      <div className="p-2 border-t border-gray-100 space-y-1">
        <button
          onClick={onLock}
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg w-full text-gray-500 hover:bg-gray-100 hover:text-gray-700 transition-colors text-sm"
        >
          <LogOut className="w-4 h-4" />
          <span>Lock Vault</span>
        </button>
      </div>
    </aside>
  );
}
