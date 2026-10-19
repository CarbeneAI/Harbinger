import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';
import { feedCases } from '../test-fixtures/feed-cases';
const fixture = fileURLToPath(new URL('../test-fixtures/feed-validation.ts', import.meta.url));

describe('pollAllFeeds validates before IOC writes', () => {
  for (const entry of feedCases) test(entry.name, async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, entry.name], { stdout: 'pipe', stderr: 'pipe' });
    const deadline = setTimeout(() => child.kill(), 8000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
    } finally { clearTimeout(deadline); }
  }, 10000);
});
