interface Props {
  permanent: boolean;
  expiresInSeconds: number | null;
}

export function ClientTtlBadge({ permanent, expiresInSeconds }: Props) {
  if (permanent) return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">
      Permanent
    </span>
  );
  if (expiresInSeconds === null) return null;
  if (expiresInSeconds <= 0) return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700">
      Expired
    </span>
  );
  const h = Math.floor(expiresInSeconds / 3600);
  const m = Math.floor((expiresInSeconds % 3600) / 60);
  const label = h > 0 ? `${h}h ${m}m` : `${m}m`;
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-700">
      {label} left
    </span>
  );
}
