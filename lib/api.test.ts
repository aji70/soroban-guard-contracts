/**
 * Unit tests for lib/api.ts
 * Runner: Jest + jest-fetch-mock  (or vitest with global fetch mock)
 *
 * Setup: add `import "jest-fetch-mock"` to jest.setup.ts and
 *        `setupFiles: ["jest-fetch-mock"]` in jest.config.ts.
 */

import { submitScan, getScan, RateLimitError } from "./api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MOCK_RESULT = {
  contractAddress: "CABC123",
  findingsHash: "e3b0c44298fc1c149afb",
  severityCounts: { critical: 1, high: 2, medium: 0, low: 3 },
  scannedAt: "2024-01-01T00:00:00Z",
};

function makeHeaders(extra: Record<string, string> = {}): Headers {
  return new Headers({
    "Content-Type": "application/json",
    ...extra,
  });
}

// ---------------------------------------------------------------------------
// submitScan
// ---------------------------------------------------------------------------

describe("submitScan", () => {
  beforeEach(() => fetchMock.resetMocks());

  it("returns parsed result and quota on 200", async () => {
    fetchMock.mockResponseOnce(JSON.stringify(MOCK_RESULT), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-RateLimit-Remaining": "49",
        "X-RateLimit-Limit": "50",
        "X-RateLimit-Reset": "1700000000",
      },
    });

    const { data, quota } = await submitScan("CABC123");

    expect(data).toEqual(MOCK_RESULT);
    expect(quota.remaining).toBe(49);
    expect(quota.limit).toBe(50);
    expect(quota.resetAt).toEqual(new Date(1700000000 * 1000));
  });

  it("throws RateLimitError with retryAfter on 429", async () => {
    fetchMock.mockResponseOnce("", {
      status: 429,
      headers: { "Retry-After": "30" },
    });

    await expect(submitScan("CABC123")).rejects.toBeInstanceOf(RateLimitError);

    fetchMock.mockResponseOnce("", {
      status: 429,
      headers: { "Retry-After": "30" },
    });
    try {
      await submitScan("CABC123");
    } catch (err) {
      expect((err as RateLimitError).retryAfter).toBe(30);
    }
  });

  it("throws RateLimitError with null retryAfter when header absent", async () => {
    fetchMock.mockResponseOnce("", { status: 429 });

    try {
      await submitScan("CABC123");
    } catch (err) {
      expect(err).toBeInstanceOf(RateLimitError);
      expect((err as RateLimitError).retryAfter).toBeNull();
    }
  });

  it("throws generic Error on non-200/non-429 status", async () => {
    fetchMock.mockResponseOnce("Internal Server Error", { status: 500 });
    await expect(submitScan("CABC123")).rejects.toThrow("500");
  });

  it("propagates AbortError when signal is aborted", async () => {
    fetchMock.mockAbortOnce();

    const controller = new AbortController();
    controller.abort();

    const err = await submitScan("CABC123", controller.signal).catch((e) => e);
    expect(err.name).toBe("AbortError");
  });

  it("rejects with AbortError on timeout (manual abort after delay)", async () => {
    // Simulate a fetch that never resolves until aborted.
    fetchMock.mockResponseOnce(
      () =>
        new Promise((_, reject) => {
          setTimeout(() => reject(Object.assign(new Error("aborted"), { name: "AbortError" })), 10);
        })
    );

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 5);

    const err = await submitScan("CABC123", controller.signal).catch((e) => e);
    expect(err.name).toBe("AbortError");
  });
});

// ---------------------------------------------------------------------------
// getScan
// ---------------------------------------------------------------------------

describe("getScan", () => {
  beforeEach(() => fetchMock.resetMocks());

  it("returns result and quota on 200", async () => {
    fetchMock.mockResponseOnce(JSON.stringify(MOCK_RESULT), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-RateLimit-Remaining": "10",
        "X-RateLimit-Limit": "50",
        "X-RateLimit-Reset": "1700000000",
      },
    });

    const { data, quota } = await getScan("CABC123");
    expect(data).toEqual(MOCK_RESULT);
    expect(quota.remaining).toBe(10);
  });

  it("returns null data on 404", async () => {
    fetchMock.mockResponseOnce("", { status: 404 });
    const { data } = await getScan("UNKNOWN");
    expect(data).toBeNull();
  });

  it("throws RateLimitError on 429", async () => {
    fetchMock.mockResponseOnce("", { status: 429, headers: { "Retry-After": "60" } });
    await expect(getScan("CABC123")).rejects.toBeInstanceOf(RateLimitError);
  });

  it("returns null quota fields when rate-limit headers are absent", async () => {
    fetchMock.mockResponseOnce(JSON.stringify(MOCK_RESULT), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    const { quota } = await getScan("CABC123");
    expect(quota.remaining).toBeNull();
    expect(quota.limit).toBeNull();
    expect(quota.resetAt).toBeNull();
  });
});
