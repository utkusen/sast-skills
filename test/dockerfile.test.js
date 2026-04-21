import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const dockerfile = resolve(here, '..', 'Dockerfile');

test('Dockerfile builds a Node 20 image with sast-skills as the entrypoint', async () => {
  const content = await readFile(dockerfile, 'utf8');
  expect(content).toMatch(/^FROM\s+node:20/m);
  expect(content).toMatch(/ENTRYPOINT\s*\[\s*"sast-skills"\s*\]/);
  expect(content).toMatch(/npm\s+(install|ci)/);
});
