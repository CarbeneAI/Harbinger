import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/feed-single-flight.ts', import.meta.url));
describe('real feed cycles share one settlement boundary', () => {
  for (const scenario of [
    'held-fetch', 'held-json', 'fetch-reentry', 'import-reentry', 'fts-reentry', 'final-log-reentry',
    'scheduler-stale', 'scheduler-fresh', 'scheduler-fetch-reentry', 'scheduler-init-retry',
    'fetch-recovery', 'json-recovery', 'validation-recovery', 'import-recovery',
    'status-recovery', 'fts-recovery', 'stats-recovery', 'initial-read-recovery', 'manual-http',
  ]) test(scenario, async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
    const deadline = setTimeout(() => child.kill(), 8000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
    } finally { clearTimeout(deadline); }
  }, 10000);
});
