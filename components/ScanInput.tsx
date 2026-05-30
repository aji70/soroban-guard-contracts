import { useRef, useState } from "react";
import { submitScan, RateLimitError, type ScanResult, type QuotaInfo } from "../lib/api";
import {
  requestPermission,
  notifyScanComplete,
  notifyScanError,
} from "../lib/notifications";

interface ScanState {
  result: ScanResult | null;
  quota: QuotaInfo | null;
  error: string | null;
  scanning: boolean;
}

export default function ScanInput() {
  const [address, setAddress] = useState("");
  const [state, setState] = useState<ScanState>({
    result: null,
    quota: null,
    error: null,
    scanning: false,
  });
  const abortRef = useRef<AbortController | null>(null);

  async function handleScan() {
    if (!address.trim()) return;

    await requestPermission();

    const controller = new AbortController();
    abortRef.current = controller;
    setState({ result: null, quota: null, error: null, scanning: true });

    try {
      const { data, quota } = await submitScan(address.trim(), controller.signal);
      setState({ result: data, quota, error: null, scanning: false });
      notifyScanComplete(
        data.contractAddress,
        data.severityCounts.critical,
        data.severityCounts.high
      );
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        setState((s) => ({ ...s, error: "Scan cancelled.", scanning: false }));
        return;
      }
      const message =
        err instanceof RateLimitError
          ? `Rate limit hit${err.retryAfter ? ` — retry in ${err.retryAfter}s` : ""}`
          : (err as Error).message;
      setState({ result: null, quota: null, error: message, scanning: false });
      notifyScanError(address.trim(), message);
    } finally {
      abortRef.current = null;
    }
  }

  function handleCancel() {
    abortRef.current?.abort();
  }

  const { result, quota, error, scanning } = state;

  return (
    <div>
      <div>
        <input
          type="text"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder="Contract address"
          disabled={scanning}
        />
        {scanning ? (
          <button type="button" onClick={handleCancel}>
            Cancel
          </button>
        ) : (
          <button type="button" onClick={handleScan} disabled={!address.trim()}>
            Scan
          </button>
        )}
      </div>

      {scanning && <p>Scanning…</p>}

      {error && <p role="alert">{error}</p>}

      {quota?.remaining !== null && (
        <p>API quota: {quota!.remaining} / {quota!.limit} remaining</p>
      )}

      {result && (
        <dl>
          <dt>Contract</dt>
          <dd>{result.contractAddress}</dd>
          <dt>Findings hash</dt>
          <dd>{result.findingsHash}</dd>
          <dt>Critical</dt>
          <dd>{result.severityCounts.critical}</dd>
          <dt>High</dt>
          <dd>{result.severityCounts.high}</dd>
          <dt>Medium</dt>
          <dd>{result.severityCounts.medium}</dd>
          <dt>Low</dt>
          <dd>{result.severityCounts.low}</dd>
          <dt>Scanned at</dt>
          <dd>{result.scannedAt}</dd>
        </dl>
      )}
    </div>
  );
}
