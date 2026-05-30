export interface ScanResult {
  contractAddress: string;
  findingsHash: string;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scannedAt: string;
}

export interface QuotaInfo {
  remaining: number | null;
  limit: number | null;
  resetAt: Date | null;
}

export interface ApiResponse<T> {
  data: T;
  quota: QuotaInfo;
}

export class RateLimitError extends Error {
  retryAfter: number | null;
  constructor(retryAfter: number | null) {
    super("Rate limit exceeded");
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

function parseQuota(headers: Headers): QuotaInfo {
  const remaining = headers.get("X-RateLimit-Remaining");
  const limit = headers.get("X-RateLimit-Limit");
  const reset = headers.get("X-RateLimit-Reset");
  return {
    remaining: remaining !== null ? parseInt(remaining, 10) : null,
    limit: limit !== null ? parseInt(limit, 10) : null,
    resetAt: reset !== null ? new Date(parseInt(reset, 10) * 1000) : null,
  };
}

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "https://api.soroban-guard.example";

export async function submitScan(
  contractAddress: string,
  signal?: AbortSignal
): Promise<ApiResponse<ScanResult>> {
  const res = await fetch(`${BASE_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contractAddress }),
    signal,
  });

  if (res.status === 429) {
    const retryAfter = res.headers.get("Retry-After");
    throw new RateLimitError(retryAfter !== null ? parseInt(retryAfter, 10) : null);
  }

  if (!res.ok) {
    throw new Error(`Scan request failed: ${res.status} ${res.statusText}`);
  }

  const data: ScanResult = await res.json();
  return { data, quota: parseQuota(res.headers) };
}

export async function getScan(
  contractAddress: string,
  signal?: AbortSignal
): Promise<ApiResponse<ScanResult | null>> {
  const res = await fetch(
    `${BASE_URL}/scan/${encodeURIComponent(contractAddress)}`,
    { signal }
  );

  if (res.status === 429) {
    const retryAfter = res.headers.get("Retry-After");
    throw new RateLimitError(retryAfter !== null ? parseInt(retryAfter, 10) : null);
  }

  if (res.status === 404) {
    return { data: null, quota: parseQuota(res.headers) };
  }

  if (!res.ok) {
    throw new Error(`Get scan failed: ${res.status} ${res.statusText}`);
  }

  const data: ScanResult = await res.json();
  return { data, quota: parseQuota(res.headers) };
}
