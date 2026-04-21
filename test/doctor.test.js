import { test, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, unlink, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const bin = resolve(here, '..', 'bin', 'sast-skills.js');

function run(args, opts = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [bin, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-doctor-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('doctor on a clean install reports OK and exits 0', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);

  const { code, stdout } = await run(['doctor', '--target', workdir, '--assistant', 'claude']);
  expect(code).toBe(0);
  expect(stdout).toMatch(/OK/i);
  expect(stdout).toMatch(/CLAUDE\.md/);
});

test('doctor flags missing and modified files and exits non-zero', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);

  await unlink(join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md'));
  await writeFile(join(workdir, '.claude', 'skills', 'sast-sqli', 'SKILL.md'), 'user edit');

  const { code, stdout } = await run(['doctor', '--target', workdir, '--assistant', 'claude']);
  expect(code).not.toBe(0);
  expect(stdout).toMatch(/sast-analysis.*MISSING/);
  expect(stdout).toMatch(/sast-sqli.*MODIFIED/);
});
