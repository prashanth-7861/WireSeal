import React from "react";

type Role = "owner" | "admin" | "readonly" | string;

const ROLE_STYLES: Record<string, string> = {
  owner:    "bg-purple-100 text-purple-800 border border-purple-300",
  admin:    "bg-blue-100 text-blue-800 border border-blue-300",
  readonly: "bg-gray-100 text-gray-700 border border-gray-300",
};

const ROLE_LABELS: Record<string, string> = {
  owner:    "Owner",
  admin:    "Admin",
  readonly: "Read-only",
};

export function AdminRoleBadge({ role }: { role: Role }) {
  const styles = ROLE_STYLES[role] ?? ROLE_STYLES["readonly"];
  const label  = ROLE_LABELS[role] ?? role;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${styles}`}>
      {label}
    </span>
  );
}
