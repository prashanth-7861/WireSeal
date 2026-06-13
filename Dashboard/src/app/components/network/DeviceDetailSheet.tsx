import { useState } from "react";
import {
  Router, Printer, HardDrive, MonitorPlay, Smartphone,
  Laptop, Cpu, HelpCircle, RefreshCw, Network as NetIcon,
} from "lucide-react";
import { api } from "../../api";
import type { NetworkDevice, NetworkService, OpenPort, DeviceType } from "../../api";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from "../ui/sheet";

const TYPE_META: Record<string, { label: string; Icon: typeof Router }> = {
  router: { label: "Router / Gateway", Icon: Router },
  printer: { label: "Printer", Icon: Printer },
  nas: { label: "NAS / Storage", Icon: HardDrive },
  media: { label: "Media Device", Icon: MonitorPlay },
  phone: { label: "Phone / Mobile", Icon: Smartphone },
  computer: { label: "Computer", Icon: Laptop },
  iot: { label: "IoT Device", Icon: Cpu },
  unknown: { label: "Unknown", Icon: HelpCircle },
};

export function deviceTypeMeta(type?: DeviceType) {
  return TYPE_META[type || "unknown"] ?? TYPE_META.unknown;
}

interface DeviceDetailSheetProps {
  device: NetworkDevice | null;
  services: NetworkService[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeviceUpdate: (ip: string, openPorts: OpenPort[], deviceType: DeviceType) => void;
}

export function DeviceDetailSheet({
  device, services, open, onOpenChange, onDeviceUpdate,
}: DeviceDetailSheetProps) {
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  if (!device) return null;

  const meta = deviceTypeMeta(device.device_type);
  const linkedServices = services.filter(s => s.ip === device.ip);
  const openPorts = device.open_ports ?? [];

  const handleScanPorts = async () => {
    setError("");
    setScanning(true);
    try {
      const res = await api.scanDevicePorts(
        device.ip,
        device.vendor,
        linkedServices.map(s => s.type),
      );
      onDeviceUpdate(res.ip, res.open_ports, res.device_type);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Port scan failed");
    } finally {
      setScanning(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-md overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <meta.Icon className="w-5 h-5 text-blue-600" />
            {device.hostname || device.ip}
          </SheetTitle>
          <SheetDescription>{meta.label}</SheetDescription>
        </SheetHeader>

        <div className="px-4 pb-6 space-y-6">
          {/* Identity */}
          <dl className="grid grid-cols-3 gap-y-3 text-sm">
            <dt className="text-gray-500">IP</dt>
            <dd className="col-span-2 font-mono text-gray-900">{device.ip}</dd>
            <dt className="text-gray-500">Hostname</dt>
            <dd className="col-span-2 text-gray-900">{device.hostname || "—"}</dd>
            <dt className="text-gray-500">MAC</dt>
            <dd className="col-span-2 font-mono text-gray-700">{device.mac || "—"}</dd>
            <dt className="text-gray-500">Vendor</dt>
            <dd className="col-span-2 text-gray-700">{device.vendor || "Unknown"}</dd>
            <dt className="text-gray-500">Source</dt>
            <dd className="col-span-2 text-gray-700">{device.source}</dd>
          </dl>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-red-800 text-sm">
              {error}
            </div>
          )}

          {/* Open ports */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-gray-900">Open Ports</h3>
              <button
                onClick={handleScanPorts}
                disabled={scanning}
                className="px-3 py-1.5 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1.5 text-xs font-medium transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${scanning ? "animate-spin" : ""}`} />
                {scanning ? "Scanning..." : "Scan Ports"}
              </button>
            </div>
            {openPorts.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {openPorts.map(p => (
                  <span
                    key={p.port}
                    className="inline-flex items-center gap-1.5 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-md px-2 py-1 text-xs"
                  >
                    <span className="font-mono font-semibold">{p.port}</span>
                    {p.service && <span className="text-emerald-600">{p.service}</span>}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-400 italic">
                {scanning ? "Probing common ports…" : "No open ports scanned yet."}
              </p>
            )}
          </div>

          {/* Services on this device */}
          <div>
            <h3 className="text-sm font-medium text-gray-900 mb-2 flex items-center gap-1.5">
              <NetIcon className="w-4 h-4 text-gray-400" />
              Services ({linkedServices.length})
            </h3>
            {linkedServices.length > 0 ? (
              <ul className="space-y-2">
                {linkedServices.map((s, i) => (
                  <li
                    key={`${s.port}-${i}`}
                    className="bg-gray-50 border border-gray-200 rounded-md px-3 py-2 text-sm"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-gray-900 truncate">{s.name}</span>
                      <span className="text-xs text-gray-500 font-mono ml-2">:{s.port}</span>
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      {s.type} · {s.protocol}
                      {s.model && <span className="ml-1 text-gray-400">{s.model}</span>}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-gray-400 italic">
                No advertised services. Run “Discover Services” on the Services tab.
              </p>
            )}
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
