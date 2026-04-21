import { test, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { run } from '../src/cli.js';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');

test('run install --dry-run emits the file plan to the provided stdout', async () => {
  let output = '';
  await run({
    argv: ['install', '--dry-run', '--yes', '--target', '/tmp', '--assistant', 'claude', '--scope', 'project'],
    cwd: '/tmp',
    packageRoot,
    stdin: { isTTY: true },
    stdout: { write: (chunk) => { output += chunk; } },
    stderr: { write: () => {} },
  });
  expect(output).toMatch(/CLAUDE\.md/);
  expect(output).toMatch(/sast-analysis\/SKILL\.md/);
});
