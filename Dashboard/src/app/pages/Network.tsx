import { useState, useEffect, useRef, useCallback } from "react";
import {
  Radar, RefreshCw, Search, Wifi, Printer, Monitor, FolderOpen,
  Terminal, AlertTriangle, Laptop, Router, HardDrive, Cpu,
} from "lucide-react";
import { api } from "../api";
import type {
  NetworkDevice, NetworkDevicesResponse,
  NetworkService, NetworkServicesResponse, ScanStatus,
} from "../api";

// Module-level cache — survives navigation
let _devicesCache: NetworkDevicesResponse | null = null;
let _servicesCache: NetworkServicesResponse | null = null;

type Tab = "devices" | "services";

export function Network() {
  const [tab, setTab] = useState<Tab>("devices");
  const [devices, setDevices] = useState<NetworkDevice[]>(_devicesCache?.devices ?? []);
  const [lanSubnet, setLanSubnet] = useState(_devicesCache?.lan_subnet ?? "");
  const [scanAvailable, setScanAvailable] = useState(_devicesCache?.scan_available ?? false);
  const [platform, setPlatform] = useState(_devicesCache?.platform ?? "");
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({ total: 0, done: 0, status: "idle" });
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");

  const [services, setServices] = useState<NetworkService[]>(_servicesCache?.services ?? []);
  const [mdnsAvailable, setMdnsAvailable] = useState(_servicesCache?.mdns_available ?? false);
  const [discoveringServices, setDiscoveringServices] = useState(false);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchDevices = useCallback(async () => {
    try {
      const res = await api.getNetworkDevices();
      _devicesCache = res;
      setDevices(res.devices);
      setLanSubnet(res.lan_subnet);
      setScanAvailable(res.scan_available);
      setPlatform(res.platform ?? "");
    } catch { /* vault may be locked */ }
  }, []);

  const fetchServices = useCallback(async () => {
    try {
      const res = await api.getNetworkServices();
      _servicesCache = res;
      setServices(res.services);
      setMdnsAvailable(res.mdns_available);
    } catch { /* vault may be locked */ }
  }, []);

  useEffect(() => {
    fetchDevices();
    fetchServices();
    const iv = setInterval(fetchDevices, 30_000);
    return () => clearInterval(iv);
  }, [fetchDevices, fetchServices]);

  // Scan polling
  useEffect(() => {
    if (!scanning) return;
    const iv = setInterval(async () => {
      try {
        const status: ScanStatus = await api.getNetworkScanStatus();
        setScanProgress(status.progress);
        if (!status.running) {
          setScanning(false);
          if (status.devices.length > 0) {
            setDevices(status.devices);
          } else {
            fetchDevices();
          }
        }
      } catch { /* ignore */ }
    }, 1000);
    pollRef.current = iv;
    return () => clearInterval(iv);
  }, [scanning, fetchDevices]);

  const handleScan = async () => {
    setError("");
    try {
      const res = await api.scanNetwork();
      if (res.ok) {
        setScanning(true);
        setScanProgress({ total: 0, done: 0, status: "starting" });
      } else if (res.reason === "scan_in_progress") {
        setScanning(true);
      } else if (res.reason === "cooldown") {
        setError(`Scan cooldown — retry in ${res.retry_after ?? 30}s`);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Scan failed");
    }
  };

  const handleDiscoverServices = async () => {
    setDiscoveringServices(true);
    try {
      const res = await api.scanNetworkServices();
      _servicesCache = res;
      setServices(res.services);
      setMdnsAvailable(res.mdns_available);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Service discovery failed");
    } finally {
      setDiscoveringServices(false);
    }
  };

  const filteredDevices = devices.filter(d => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return d.ip.includes(q) || d.hostname.toLowerCase().includes(q)
      || d.mac.toLowerCase().includes(q) || d.vendor.toLowerCase().includes(q);
  });

  const filteredServices = services.filter(s => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return s.name.toLowerCase().includes(q) || s.ip.includes(q)
      || s.type.toLowerCase().includes(q) || s.manufacturer.toLowerCase().includes(q);
  });

  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-2">
        <Radar className="w-7 h-7 text-blue-600" />
        <h1 className="text-3xl font-semibold text-gray-900">Network</h1>
      </div>
      <p className="text-gray-500 mb-6">
        Discover devices and services on your home LAN. Requires split-lan or full tunnel mode.
        {lanSubnet && <span className="ml-2 font-mono text-xs bg-gray-100 px-2 py-0.5 rounded">{lanSubnet}</span>}
      </p>

      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-red-800 text-sm">
          {error}
        </div>
      )}

      {/* Tabs + Filter */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex bg-gray-100 rounded-lg p-0.5">
          <button
            onClick={() => setTab("devices")}
            className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
              tab === "devices" ? "bg-white shadow-sm text-gray-900" : "text-gray-500 hover:text-gray-700"
            }`}
          >
            Devices ({devices.length})
          </button>
          <button
            onClick={() => setTab("services")}
            className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
              tab === "services" ? "bg-white shadow-sm text-gray-900" : "text-gray-500 hover:text-gray-700"
            }`}
          >
            Services ({services.length})
          </button>
        </div>
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by IP, hostname, vendor..."
            className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        {tab === "devices" ? (
          <button
            onClick={handleScan}
            disabled={scanning || !scanAvailable}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${scanning ? "animate-spin" : ""}`} />
            {scanning ? "Scanning..." : "Scan Network"}
          </button>
        ) : (
          <button
            onClick={handleDiscoverServices}
            disabled={discoveringServices}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${discoveringServices ? "animate-spin" : ""}`} />
            {discoveringServices ? "Discovering..." : "Discover Services"}
          </button>
        )}
      </div>

      {/* Scan progress */}
      {scanning && scanProgress.total > 0 && (
        <div className="mb-4">
          <div className="flex justify-between text-xs text-gray-500 mb-1">
            <span>Scanning {lanSubnet}</span>
            <span>{scanProgress.done} / {scanProgress.total}</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all"
              style={{ width: `${Math.round((scanProgress.done / scanProgress.total) * 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Devices tab */}
      {tab === "devices" && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-5 py-3 text-sm font-medium text-gray-700">IP Address</th>
                <th className="text-left px-5 py-3 text-sm font-medium text-gray-700">Hostname</th>
                <th className="text-left px-5 py-3 text-sm font-medium text-gray-700">MAC Address</th>
                <th className="text-left px-5 py-3 text-sm font-medium text-gray-700">Vendor</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredDevices.map((d) => (
                <tr key={`${d.ip}-${d.mac}`} className="hover:bg-gray-50">
                  <td className="px-5 py-3 font-mono text-sm text-gray-900">{d.ip}</td>
                  <td className="px-5 py-3 text-sm text-gray-700">
                    {d.hostname || <span className="text-gray-400 italic">—</span>}
                  </td>
                  <td className="px-5 py-3 font-mono text-sm text-gray-500">{d.mac}</td>
                  <td className="px-5 py-3 text-sm text-gray-700">
                    <span className={d.vendor === "Unknown" ? "text-gray-400" : ""}>
                      {d.vendor}
                    </span>
                  </td>
                </tr>
              ))}
              {filteredDevices.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-5 py-12 text-center text-gray-500 text-sm">
                    {devices.length === 0
                      ? "No devices found. Try scanning your network."
                      : "No devices match your filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Services tab */}
      {tab === "services" && (
        <>
          {!mdnsAvailable && (
            <div className="mb-4 bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0" />
              <p className="text-amber-800 text-sm">
                <strong>zeroconf not installed</strong> — only SSDP/UPnP discovery is active.
                Install <code className="mx-1 px-1 bg-amber-100 rounded">pip install wireseal[network]</code> for
                mDNS/Bonjour support (printers, AirPlay, Chromecast, etc.).
              </p>
            </div>
          )}
          <div className="grid gap-3">
            {filteredServices.map((s, i) => (
              <div key={`${s.ip}-${s.port}-${i}`} className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 flex items-start gap-4 hover:border-gray-300 transition-colors">
                <div className="p-2 bg-blue-50 rounded-lg">
                  <ServiceIcon type={s.type} className="w-5 h-5 text-blue-600" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-medium text-gray-900 truncate">{s.name}</h3>
                    <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full flex-shrink-0">{s.type}</span>
                    <span className="text-xs bg-gray-50 text-gray-400 px-1.5 py-0.5 rounded flex-shrink-0">{s.protocol}</span>
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                    <span className="font-mono">{s.ip}:{s.port}</span>
                    {s.host && s.host !== s.ip && <span>{s.host}</span>}
                    {s.manufacturer && <span>{s.manufacturer}</span>}
                    {s.model && <span className="text-gray-400">{s.model}</span>}
                  </div>
                </div>
              </div>
            ))}
            {filteredServices.length === 0 && (
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12 text-center text-gray-500 text-sm">
                {services.length === 0
                  ? "No services found. Try discovering services."
                  : "No services match your filter."}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function ServiceIcon({ type, className }: { type: string; className?: string }) {
  const t = type.toLowerCase();
  if (t.includes("printer") || t.includes("ipp")) return <Printer className={className} />;
  if (t.includes("airplay") || t.includes("chromecast") || t.includes("media")) return <Monitor className={className} />;
  if (t.includes("smb") || t.includes("afp") || t.includes("nfs") || t.includes("file")) return <FolderOpen className={className} />;
  if (t.includes("ssh") || t.includes("sftp")) return <Terminal className={className} />;
  if (t.includes("gateway") || t.includes("router")) return <Router className={className} />;
  if (t.includes("plex") || t.includes("nas")) return <HardDrive className={className} />;
  if (t.includes("homekit") || t.includes("hap")) return <Cpu className={className} />;
  return <Wifi className={className} />;
}
