import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';
const fixture = fileURLToPath(new URL('../test-fixtures/feed-atomicity.ts', import.meta.url));

// Child processes isolate the real database from the response suite's mocks.
describe('feed import transactions with real SQLite', () => {
  for (const scenario of ['insert-rollback', 'overwrite-rollback', 'domain-rollback', 'threatfox-rollback', 'status-rollback', 'retry', 'empty', 'duplicates']) {
    test(scenario, async () => {
      const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
      const deadline = setTimeout(() => child.kill(), 8000);
      try {
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
        ]);
        expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
      } finally { clearTimeout(deadline); }
    }, 10000);
  }
});
