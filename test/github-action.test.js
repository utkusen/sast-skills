import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const action = resolve(here, '..', '.github', 'actions', 'scan', 'action.yml');

test('.github/actions/scan/action.yml is a composite action that exports SARIF and uploads it', async () => {
  const content = await readFile(action, 'utf8');
  expect(content).toMatch(/using:\s*['"]?composite['"]?/);
  expect(content).toMatch(/sast-skills/);
  expect(content).toMatch(/--format\s+sarif/);
  expect(content).toMatch(/github\/codeql-action\/upload-sarif/);
});
