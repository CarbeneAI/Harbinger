import { describe, expect, it } from 'bun:test';
import { isPrivateIndicator } from './prefetch';

describe('isPrivateIndicator — enforced privacy control', () => {
  it('blocks RFC1918 ranges', () => {
    for (const ip of [
      '10.0.0.1', '10.255.255.255',
      '172.16.0.1', '172.31.255.254',
      '192.168.1.1', '192.168.2.110',
    ]) {
      expect(isPrivateIndicator(ip)).toBe(true);
    }
  });

  it('blocks loopback, link-local, CGNAT and reserved', () => {
    for (const ip of [
      '127.0.0.1', '0.0.0.0', '169.254.1.1',
      '100.64.0.1', '100.73.131.1',   // Tailscale CGNAT — the homelab itself
      '224.0.0.1',
    ]) {
      expect(isPrivateIndicator(ip)).toBe(true);
    }
  });

  it('blocks IPv6 loopback, ULA and link-local', () => {
    for (const ip of ['::1', '::', 'fd00::1', 'fc00::1', 'fe80::1']) {
      expect(isPrivateIndicator(ip)).toBe(true);
    }
  });

  it('blocks internal hostnames and TLDs', () => {
    for (const host of [
      'localhost', 'srv-apps',
      'harbinger.home.carbeneai.com',
      'db.corp', 'nas.local', 'printer.lan', 'vault.internal',
    ]) {
      expect(isPrivateIndicator(host)).toBe(true);
    }
  });

  it('does NOT block genuine public IOCs', () => {
    for (const ioc of [
      '8.8.8.8', '1.1.1.1', '185.220.101.5',
      'evil.com', 'malware-c2.ru', 'example.org',
    ]) {
      expect(isPrivateIndicator(ioc)).toBe(false);
    }
  });

  it('judges URLs on host, not path', () => {
    expect(isPrivateIndicator('http://192.168.1.1/admin')).toBe(true);
    expect(isPrivateIndicator('https://nas.local:5001/x')).toBe(true);
    expect(isPrivateIndicator('http://evil.com/192.168.1.1')).toBe(false);
  });

  it('fails closed on empty/garbage input', () => {
    for (const v of ['', '   ']) {
      expect(isPrivateIndicator(v)).toBe(true);
    }
  });
});
