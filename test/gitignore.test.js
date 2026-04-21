import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

test('.gitignore excludes the sast/ output directory', async () => {
  const gitignore = await readFile(resolve(here, '..', '.gitignore'), 'utf8');
  const entries = gitignore.split('\n').map((line) => line.trim());
  expect(entries).toContain('sast/');
});

test('.gitignore does not exclude the test/ directory', async () => {
  const gitignore = await readFile(resolve(here, '..', '.gitignore'), 'utf8');
  const entries = gitignore.split('\n').map((line) => line.trim());
  const blocksTests = entries.some((e) => e === '/test' || e === 'test' || e === 'test/' || e === '/test/');
  expect(blocksTests).toBe(false);
});
