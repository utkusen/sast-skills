import { test, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const bin = resolve(here, '..', 'bin', 'sast-skills.js');

function run(args) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [bin, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

test('--version prints the version from package.json', async () => {
  const { code, stdout } = await run(['--version']);
  expect(code).toBe(0);
  expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
});

test('unknown command exits with code 1 and writes to stderr', async () => {
  const { code, stderr } = await run(['bogus']);
  expect(code).toBe(1);
  expect(stderr).toMatch(/unknown command/i);
});

test('no arguments prints usage and exits 0', async () => {
  const { code, stdout } = await run([]);
  expect(code).toBe(0);
  expect(stdout).toMatch(/Usage:/);
  expect(stdout).toMatch(/install/);
});

test('usage lists every user-facing command', async () => {
  const { code, stdout } = await run([]);
  expect(code).toBe(0);
  expect(stdout).toMatch(/\binstall\b/);
  expect(stdout).toMatch(/\bupdate\b/);
  expect(stdout).toMatch(/\buninstall\b/);
  expect(stdout).toMatch(/\bdoctor\b/);
  expect(stdout).toMatch(/\bexport\b/);
});

test('--help and -h print the same usage and exit 0', async () => {
  const [noArgs, longFlag, shortFlag] = await Promise.all([run([]), run(['--help']), run(['-h'])]);
  expect(longFlag.code).toBe(0);
  expect(shortFlag.code).toBe(0);
  expect(longFlag.stdout).toBe(noArgs.stdout);
  expect(shortFlag.stdout).toBe(noArgs.stdout);
});
