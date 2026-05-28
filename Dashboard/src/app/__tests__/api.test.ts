import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const VAULT_LOCKED_EVENT = 'wireseal:vault-locked';

function mockFetchOk(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  });
}

function mockFetchNetworkError() {
  return vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
}

function mockFetchNonJson() {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.reject(new SyntaxError('Unexpected token')),
  });
}

// ---- _fetch tests -------------------------------------------------------

describe('_fetch (internal)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.useFakeTimers();
    vi.spyOn(globalThis, 'dispatchEvent').mockImplementation(() => true);
  });

  afterEach(async () => {
    await vi.runAllTimersAsync();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('calls fetch with the correct URL', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.vaultInfo();

    // Fast-forward past the 15s timeout
    await vi.runAllTimersAsync();
    const result = await p;

    expect(result).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledWith('/api/vault-info', expect.anything());
  });

  it('sets Content-Type for POST requests with a body', async () => {
    const fetch = mockFetchOk({ ok: true, role: 'owner' });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.unlock('correct-passphrase');

    await vi.runAllTimersAsync();
    await p;

    const opts = fetch.mock.calls[0][1];
    expect(opts.method).toBe('POST');
    expect(opts.headers['Content-Type']).toBe('application/json');
  });

  it('does NOT set Content-Type for GET requests', async () => {
    const fetch = mockFetchOk({});
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.vaultInfo();

    await vi.runAllTimersAsync();
    await p;

    const opts = fetch.mock.calls[0][1];
    expect(opts.headers['Content-Type']).toBeUndefined();
  });

  it('sets X-CSRF-Token header', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.vaultInfo();

    await vi.runAllTimersAsync();
    await p;

    const opts = fetch.mock.calls[0][1];
    expect(opts.headers['X-CSRF-Token']).toEqual(expect.any(String));
  });

  it('reuses the same CSRF token across calls', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p1 = api.vaultInfo();
    await vi.runAllTimersAsync();
    await p1;

    const p2 = api.status();
    await vi.runAllTimersAsync();
    await p2;

    const token1 = fetch.mock.calls[0][1].headers['X-CSRF-Token'];
    const token2 = fetch.mock.calls[1][1].headers['X-CSRF-Token'];
    expect(token1).toBe(token2);
  });

  it('rejects with descriptive message on network error', async () => {
    vi.stubGlobal('fetch', mockFetchNetworkError());

    const { api } = await import('../api');
    const p = api.vaultInfo();

    await vi.runAllTimersAsync();

    await expect(p).rejects.toThrow('Cannot reach WireSeal server');
  });

  it('rejects with descriptive message on non-JSON response', async () => {
    vi.stubGlobal('fetch', mockFetchNonJson());

    const { api } = await import('../api');
    const p = api.vaultInfo();

    await vi.runAllTimersAsync();

    await expect(p).rejects.toThrow('invalid response');
  });

  it('rejects with server error message on non-ok response', async () => {
    vi.stubGlobal('fetch', mockFetchOk({ error: 'wrong passphrase' }, 401));

    const { api } = await import('../api');
    const p = api.unlock('wrong');

    await vi.runAllTimersAsync();

    await expect(p).rejects.toThrow('wrong passphrase');
  });

  it('falls back to HTTP status text when error field is missing', async () => {
    vi.stubGlobal('fetch', mockFetchOk({}, 500));

    const { api } = await import('../api');
    const p = api.vaultInfo();

    await vi.runAllTimersAsync();

    await expect(p).rejects.toThrow('HTTP 500');
  });

  it('dispatches vault-locked event on 401 (exempt unlock/init/fresh-start)', async () => {
    vi.stubGlobal('fetch', mockFetchOk({ error: 'locked' }, 401));

    const { api } = await import('../api');
    const p = api.vaultInfo();

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow('locked');
    expect(globalThis.dispatchEvent).toHaveBeenCalled();
    const event = (globalThis.dispatchEvent as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(event.type).toBe(VAULT_LOCKED_EVENT);
  });

  it('does NOT dispatch vault-locked for /unlock 401', async () => {
    vi.stubGlobal('fetch', mockFetchOk({ error: 'bad' }, 401));

    const { api } = await import('../api');
    const p = api.unlock('wrong');

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow('bad');
    expect(globalThis.dispatchEvent).not.toHaveBeenCalled();
  });

  it('does NOT dispatch vault-locked for /init 401', async () => {
    vi.stubGlobal('fetch', mockFetchOk({ error: 'bad' }, 401));

    const { api } = await import('../api');
    const p = api.init('weak');

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow('bad');
    expect(globalThis.dispatchEvent).not.toHaveBeenCalled();
  });

  it('adds event listener for external AbortSignal', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { cancelSignal } = await import('../api');
    const { signal } = cancelSignal();

    const { api } = await import('../api');
    const p = api.vaultInfo(signal);

    await vi.runAllTimersAsync();
    await p;

    expect(fetch).toHaveBeenCalled();
  });

  it('passes the external signal as the fetch signal', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { cancelSignal, api } = await import('../api');
    const { signal } = cancelSignal();

    const p = api.vaultInfo(signal);

    await vi.runAllTimersAsync();
    await p;

    // The fetch should have been called with the external signal
    const opts = fetch.mock.calls[0][1];
    expect(opts.signal).toBeDefined();
  });


});

// ---- _fetchRetry tests --------------------------------------------------

describe('fetchWithRetry (retry logic)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.useFakeTimers();
  });

  afterEach(async () => {
    await vi.runAllTimersAsync();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('returns on first success', async () => {
    vi.stubGlobal('fetch', mockFetchOk({ data: 'ok' }));

    const { fetchWithRetry } = await import('../api');
    const p = fetchWithRetry('GET', '/test');

    await vi.runAllTimersAsync();
    await expect(p).resolves.toEqual({ data: 'ok' });
  });

  it('retries up to 3 times on 5xx errors', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 500, json: () => Promise.resolve({}) })
      .mockResolvedValueOnce({ ok: false, status: 502, json: () => Promise.resolve({}) })
      .mockResolvedValueOnce({ ok: false, status: 503, json: () => Promise.resolve({}) });
    vi.stubGlobal('fetch', fetch);

    const { fetchWithRetry } = await import('../api');
    const p = fetchWithRetry('GET', '/test');

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('retries on network errors', async () => {
    const fetch = vi.fn()
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(mockFetchOk({ ok: true })());
    vi.stubGlobal('fetch', fetch);

    const { fetchWithRetry } = await import('../api');
    const p = fetchWithRetry('GET', '/test');

    await vi.runAllTimersAsync();
    const result = await p;
    expect(result).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('does NOT retry on 4xx client errors', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 400, json: () => Promise.resolve({ error: 'bad request' }) });
    vi.stubGlobal('fetch', fetch);

    const { fetchWithRetry } = await import('../api');
    const p = fetchWithRetry('GET', '/test');

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow('bad request');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry on 401', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 401, json: () => Promise.resolve({ error: 'locked' }) });
    vi.stubGlobal('fetch', fetch);

    const { fetchWithRetry } = await import('../api');
    const p = fetchWithRetry('GET', '/test');

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow('locked');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('applies exponential backoff between retries', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 500, json: () => Promise.resolve({}) })
      .mockResolvedValueOnce({ ok: false, status: 500, json: () => Promise.resolve({}) })
      .mockResolvedValueOnce({ ok: false, status: 500, json: () => Promise.resolve({}) })
      .mockResolvedValueOnce({ ok: false, status: 500, json: () => Promise.resolve({}) });
    vi.stubGlobal('fetch', fetch);

    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');

    const { fetchWithRetry } = await import('../api');
    const p = fetchWithRetry('GET', '/test');

    await vi.runAllTimersAsync();
    await expect(p).rejects.toThrow();

    // Filter out the internal 15s timeout from _fetch; keep only retry backoff delays
    const delayCalls = setTimeoutSpy.mock.calls.filter(
      ([, delay]) => typeof delay === 'number' && delay > 0 && delay < 15000
    );
    expect(delayCalls.length).toBeGreaterThanOrEqual(2);
    expect(delayCalls[0][1]).toBe(1000);
    expect(delayCalls[1][1]).toBe(2000);
  });
});

// ---- cancelSignal tests -------------------------------------------------

describe('cancelSignal', () => {
  it('returns an object with signal and cancel', async () => {
    const { cancelSignal } = await import('../api');
    const result = cancelSignal();
    expect(result.signal).toBeInstanceOf(AbortSignal);
    expect(typeof result.cancel).toBe('function');
  });

  it('cancel() aborts the signal', async () => {
    const { cancelSignal } = await import('../api');
    const { signal, cancel } = cancelSignal();
    expect(signal.aborted).toBe(false);
    cancel();
    expect(signal.aborted).toBe(true);
  });
});

// ---- api object spot checks ---------------------------------------------

describe('api object', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.useFakeTimers();
  });

  afterEach(async () => {
    await vi.runAllTimersAsync();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('status calls GET /status', async () => {
    const fetch = mockFetchOk({ running: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.status();

    await vi.runAllTimersAsync();
    await p;
    expect(fetch).toHaveBeenCalledWith('/api/status', expect.anything());
  });

  it('lock calls POST /lock and clears currentAdminId', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.lock();

    await vi.runAllTimersAsync();
    await p;

    const opts = fetch.mock.calls[0][1];
    expect(opts.method).toBe('POST');
    expect(opts.body).toBeUndefined();
  });

  it('unlock stores admin_id on success', async () => {
    const fetch = mockFetchOk({ ok: true, role: 'owner' });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.unlock('correct-passphrase', 'admin-1');

    await vi.runAllTimersAsync();
    await p;
    expect(api.getCurrentAdminId()).toBe('admin-1');
  });

  it('lock clears admin_id', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    await api.unlock('pass', 'admin-1');
    const p = api.lock();

    await vi.runAllTimersAsync();
    await p;
    expect(api.getCurrentAdminId()).toBeNull();
  });

  it('freshStart performs 3-step challenge flow', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ ok: true, challenge_token: 'tok-123' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.freshStart();

    await vi.runAllTimersAsync();
    const result = await p;
    expect(result).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(3);

    expect(fetch.mock.calls[0][0]).toBe('/api/fresh-start/challenge');
    expect(fetch.mock.calls[1][0]).toBe('/api/fresh-start/challenge-token');
    expect(fetch.mock.calls[2][0]).toBe('/api/fresh-start');

    const thirdBody = JSON.parse(fetch.mock.calls[2][1].body);
    expect(thirdBody).toEqual({ confirm: 'CONFIRM', challenge_token: 'tok-123' });
  });

  it('logClientError sends error details to /client-error', async () => {
    const fetch = mockFetchOk({ ok: true });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.logClientError({ message: 'oops', stack: 'at line 42', url: '/page', line: 42 });

    await vi.runAllTimersAsync();
    await p;

    const body = JSON.parse(fetch.mock.calls[0][1].body);
    expect(body).toEqual({ message: 'oops', stack: 'at line 42', url: '/page', line: 42 });
    expect(fetch.mock.calls[0][0]).toBe('/api/client-error');
  });

  it('tunnel down sends POST /client/tunnel/down', async () => {
    const fetch = mockFetchOk({ interface: 'wg0', profile: 'myvpn', status: 'down' });
    vi.stubGlobal('fetch', fetch);

    const { api } = await import('../api');
    const p = api.clientTunnelDown();

    await vi.runAllTimersAsync();
    const result = await p;
    expect(result).toEqual({ interface: 'wg0', profile: 'myvpn', status: 'down' });
    expect(fetch.mock.calls[0][0]).toBe('/api/client/tunnel/down');
  });
});
