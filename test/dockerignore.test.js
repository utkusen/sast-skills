import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

test('.dockerignore excludes heavy and sensitive paths from the build context', async () => {
  const content = await readFile(resolve(here, '..', '.dockerignore'), 'utf8');
  const entries = content.split('\n').map((l) => l.trim());
  for (const entry of ['node_modules', 'test', '.git', '.github', 'demo.gif']) {
    expect(entries, `missing ${entry}`).toContain(entry);
  }
});
