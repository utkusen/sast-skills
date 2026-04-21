import { test, expect } from 'vitest';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const hook = resolve(here, '..', 'hooks', 'pre-commit');

test('hooks/pre-commit template runs sast-skills doctor and is executable', async () => {
  const content = await readFile(hook, 'utf8');
  expect(content.startsWith('#!')).toBe(true);
  expect(content).toMatch(/sast-skills\s+doctor/);

  const info = await stat(hook);
  const executableByOwner = Boolean(info.mode & 0o100);
  expect(executableByOwner).toBe(true);
});
