import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const workflow = resolve(here, '..', '.github', 'workflows', 'test.yml');

test('.github/workflows/test.yml runs the test suite on push and pull_request with Node 20', async () => {
  const content = await readFile(workflow, 'utf8');
  expect(content).toMatch(/\bpush:/);
  expect(content).toMatch(/\bpull_request:/);
  expect(content).toMatch(/actions\/checkout@/);
  expect(content).toMatch(/actions\/setup-node@/);
  expect(content).toMatch(/node-version:\s*['"]?20/);
  expect(content).toMatch(/npm (ci|install)/);
  expect(content).toMatch(/npm test/);
});

test('.github/workflows/test.yml also runs markdown lint', async () => {
  const content = await readFile(workflow, 'utf8');
  expect(content).toMatch(/npm run lint:md/);
});
