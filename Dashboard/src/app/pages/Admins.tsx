import React, { useEffect, useState } from "react";
import { api } from "../api";
import type { AdminInfo } from "../api";
import { AdminRoleBadge } from "../components/AdminRoleBadge";

// Module-level cache — survives navigation, avoids blank loading flash
let _adminsCache: AdminInfo[] | null = null;

export function Admins() {
  const [admins, setAdmins] = useState<AdminInfo[]>(_adminsCache ?? []);
  const [loading, setLoading] = useState(_adminsCache === null);
  const [error, setError] = useState<string | null>(null);

  // Add form state
  const [newId, setNewId] = useState("");
  const [newPass, setNewPass] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "owner" | "readonly">("admin");
  const [addError, setAddError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const load = () => {
    setLoading(true);
    api.listAdmins()
      .then(data => { _adminsCache = data.admins; setAdmins(data.admins); setError(null); })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load admins"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdding(true);
    setAddError(null);
    try {
      await api.addAdmin(newId, newPass, newRole);
      setNewId(""); setNewPass(""); setNewRole("admin");
      load();
    } catch (err: unknown) {
      setAddError(err instanceof Error ? err.message : "Failed to add admin");
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (targetId: string) => {
    if (!window.confirm(`Remove admin "${targetId}"? This cannot be undone.`)) return;
    try {
      await api.removeAdmin(targetId);
      load();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to remove admin");
    }
  };

  // Current admin id — tracked by api module since successful unlock
  const currentAdminId = api.getCurrentAdminId();
  const ownerCount = admins.filter(a => a.role === "owner").length;

  return (
    <div className="p-6 space-y-8">
      <h1 className="text-2xl font-bold text-gray-900">Admins</h1>

      {loading && <p className="text-gray-500">Loading...</p>}
      {error && <p className="text-red-600">{error}</p>}

      {!loading && !error && (
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-gray-50 text-left text-gray-600 uppercase text-xs">
              <th className="px-4 py-2 border-b">Admin ID</th>
              <th className="px-4 py-2 border-b">Role</th>
              <th className="px-4 py-2 border-b">TOTP</th>
              <th className="px-4 py-2 border-b">Last Unlock</th>
              <th className="px-4 py-2 border-b"></th>
            </tr>
          </thead>
          <tbody>
            {admins.map(admin => {
              const isLastOwner = admin.role === "owner" && ownerCount === 1;
              const isSelf = admin.id === currentAdminId;
              const canRemove = !isLastOwner && !isSelf;
              return (
                <tr key={admin.id} className="hover:bg-gray-50">
                  <td className="px-4 py-2 border-b font-mono">{admin.id}</td>
                  <td className="px-4 py-2 border-b"><AdminRoleBadge role={admin.role} /></td>
                  <td className="px-4 py-2 border-b">{admin.totp_enrolled ? "Enrolled" : "\u2014"}</td>
                  <td className="px-4 py-2 border-b text-gray-500">{admin.last_unlock ?? "Never"}</td>
                  <td className="px-4 py-2 border-b">
                    <button
                      onClick={() => handleRemove(admin.id)}
                      disabled={!canRemove}
                      title={isLastOwner ? "Cannot remove last owner" : isSelf ? "Cannot remove yourself" : ""}
                      className="text-red-600 hover:text-red-800 disabled:opacity-30 disabled:cursor-not-allowed text-xs"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <div className="border-t pt-6">
        <h2 className="text-lg font-semibold text-gray-800 mb-4">Add Admin</h2>
        <form onSubmit={handleAdd} className="space-y-3 max-w-sm">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Admin ID</label>
            <input
              value={newId} onChange={e => setNewId(e.target.value)}
              className="w-full border rounded px-3 py-1.5 text-sm"
              placeholder="alice" required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Passphrase</label>
            <input
              type="password" value={newPass} onChange={e => setNewPass(e.target.value)}
              className="w-full border rounded px-3 py-1.5 text-sm"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
            <select
              value={newRole} onChange={e => setNewRole(e.target.value as "admin" | "owner" | "readonly")}
              className="w-full border rounded px-3 py-1.5 text-sm"
            >
              <option value="admin">Admin</option>
              <option value="owner">Owner</option>
              <option value="readonly">Read-only</option>
            </select>
          </div>
          {addError && <p className="text-red-600 text-sm">{addError}</p>}
          <button
            type="submit" disabled={adding}
            className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50"
          >
            {adding ? "Adding..." : "Add Admin"}
          </button>
        </form>
      </div>
    </div>
  );
}
