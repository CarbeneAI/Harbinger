import { describe, expect, test } from 'bun:test';
import { readNetworkPolicy, requestIsAllowed } from './network-policy';

describe('network configuration', () => {
  test('defaults to loopback and the local Vite origin', () => {
    const policy = readNetworkPolicy({});
    expect(policy.hostname).toBe('127.0.0.1');
    expect(policy.allowedOrigin).toBe('http://127.0.0.1:5174');
  });

  test('uses a nondefault client port and an explicit API bind address', () => {
    const policy = readNetworkPolicy({ CLIENT_PORT: '8174', HARBINGER_API_HOST: '::1' });
    expect(policy.allowedOrigin).toBe('http://127.0.0.1:8174');
    expect(policy.hostname).toBe('::1');
  });

  test('normalizes an explicit origin and allows only configured additional hosts', () => {
    const policy = readNetworkPolicy({
      CORS_ALLOWED_ORIGIN: 'https://Dashboard.Example.test/',
      HARBINGER_ALLOWED_HOSTS: 'api.example.test, [fd00::1]',
    });
    expect(policy.allowedOrigin).toBe('https://dashboard.example.test');
    expect(policy.allowedHosts.has('api.example.test')).toBe(true);
    expect(policy.allowedHosts.has('[fd00::1]')).toBe(true);
    expect(policy.allowedHosts.has('dashboard.example.test')).toBe(false);
  });

  test('rejects unsafe or ambiguous configured origins', () => {
    for (const origin of ['*', 'null', 'file:///tmp', 'https://user:pass@host', 'https://host/path', 'https://host?q=1', 'https://host/#fragment', 'https://a https://b']) {
      expect(() => readNetworkPolicy({ CORS_ALLOWED_ORIGIN: origin })).toThrow('CORS_ALLOWED_ORIGIN');
    }
  });

  test('rejects wildcard, URL, port, and malformed allowed-host entries', () => {
    for (const host of ['*', '.example.test', 'https://example.test', 'example.test:80', 'user@localhost', 'bad host', '[::1]:4001']) {
      expect(() => readNetworkPolicy({ HARBINGER_ALLOWED_HOSTS: host })).toThrow('HARBINGER_ALLOWED_HOSTS');
    }
  });

  test('does not automatically authorize a nonloopback bind address', () => {
    const policy = readNetworkPolicy({ HARBINGER_API_HOST: '0.0.0.0' });
    expect(policy.allowedHosts.has('0.0.0.0')).toBe(false);
  });
});

describe('request admission', () => {
  const policy = readNetworkPolicy({});
  const request = (headers: Record<string, string>) => new Request('http://localhost:4001/health', { headers });

  test('requires an explicit allowed Host and ignores forwarded host claims', () => {
    for (const host of ['', 'evil.test', 'user@localhost', 'localhost,evil.test', 'localhost/', 'localhost:999999', '.localhost']) {
      expect(requestIsAllowed(request({ Host: host, 'X-Forwarded-Host': 'localhost' }), policy)).toBe(false);
    }
    expect(requestIsAllowed(request({}), policy)).toBe(false);
  });

  test('accepts exact loopback hosts with legal ports', () => {
    for (const host of ['LOCALHOST:4001', '127.0.0.1:4001', '[::1]:4001']) {
      expect(requestIsAllowed(request({ Host: host }), policy)).toBe(true);
    }
  });

  test('rejects foreign, null, multiple, and malformed browser origins', () => {
    for (const origin of ['https://evil.test', 'null', '', 'http://127.0.0.1:5174/', 'http://127.0.0.1:5174 http://evil.test']) {
      expect(requestIsAllowed(request({ Host: 'localhost', Origin: origin }), policy)).toBe(false);
    }
    expect(requestIsAllowed(request({ Host: 'localhost', Origin: 'http://127.0.0.1:5174' }), policy)).toBe(true);
  });

  test('rejects no-Origin cross-origin browser metadata while retaining same-origin and CLI traffic', () => {
    for (const site of ['same-site', 'cross-site']) {
      expect(requestIsAllowed(request({ Host: 'localhost', 'Sec-Fetch-Site': site }), policy)).toBe(false);
    }
    for (const site of ['same-origin', 'none']) {
      expect(requestIsAllowed(request({ Host: 'localhost', 'Sec-Fetch-Site': site }), policy)).toBe(true);
    }
    expect(requestIsAllowed(request({ Host: 'localhost' }), policy)).toBe(true);
    expect(requestIsAllowed(request({ Host: 'localhost', Origin: 'http://127.0.0.1:5174', 'Sec-Fetch-Site': 'cross-site' }), policy)).toBe(true);
  });
});
