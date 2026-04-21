import { test, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

test('markdownlint passes on all tracked .md files', async () => {
  const result = await new Promise((resolvePromise) => {
    const child = spawn('npm', ['run', '--silent', 'lint:md'], {
      cwd: repoRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
  expect(result.code, `markdownlint output:\n${result.stdout}\n${result.stderr}`).toBe(0);
}, 30_000);
