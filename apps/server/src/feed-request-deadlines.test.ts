import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/feed-request-deadlines.ts', import.meta.url));
describe('feed requests settle across real loopback bodies', () => {
  for (const scenario of [
    'body-cisa_kev', 'body-urlhaus', 'body-threatfox', 'headers',
    'http-error-cisa_kev', 'http-error-urlhaus', 'http-error-threatfox',
    'malformed-json', 'reset-body', 'success-native-deadline',
  ]) test(scenario, async () => {
    const root = mkdtempSync(join(tmpdir(), 'harbinger-deadline-test-'));
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario, root], {
      stdout: 'pipe', stderr: 'pipe',
    });
    // A successful native 30-second signal must not keep this process alive.
    const watchdog = setTimeout(() => child.kill(), 8000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
    } finally {
      clearTimeout(watchdog);
      rmSync(root, { recursive: true, force: true });
    }
  }, 10000);
});
