import { test, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, stat, writeFile, readFile } from 'node:fs/promises';
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
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-uninstall-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('uninstall removes the entry file and skill tree that install created', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);
  expect((await stat(join(workdir, 'CLAUDE.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md'))).isFile()).toBe(true);

  const { code } = await run(['uninstall', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);
  expect(code).toBe(0);

  await expect(stat(join(workdir, 'CLAUDE.md'))).rejects.toThrow();
  await expect(stat(join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md'))).rejects.toThrow();
});

test('uninstall preserves a user-modified CLAUDE.md unless --force is passed', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);
  const modified = 'user edits on top of the bundled CLAUDE.md\n';
  await writeFile(join(workdir, 'CLAUDE.md'), modified);

  const { code, stderr } = await run(['uninstall', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);
  expect(code).toBe(1);
  expect(stderr).toMatch(/CLAUDE\.md/);
  expect(stderr).toMatch(/modified|--force/i);

  const after = await readFile(join(workdir, 'CLAUDE.md'), 'utf8');
  expect(after).toBe(modified);
});
