import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/feed-fts-recovery.ts', import.meta.url));
describe('real SQLite search rebuild failure and recovery', () => {
  for (const scenario of ['joined-recovery', 'repeated-log-reentry', 'manual-http']) test(scenario, async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
    const watchdog = setTimeout(() => child.kill(), 8000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
    } finally { clearTimeout(watchdog); }
  }, 10000);
});
