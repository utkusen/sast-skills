import { test, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, stat, unlink, writeFile } from 'node:fs/promises';
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
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-update-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('update restores missing skill files and refreshes stale ones', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);

  const missingSkill = join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md');
  const staleSkill = join(workdir, '.claude', 'skills', 'sast-sqli', 'SKILL.md');
  await unlink(missingSkill);
  await writeFile(staleSkill, 'outdated content');

  const { code } = await run(['update', '--yes', '--target', workdir, '--assistant', 'claude', '--scope', 'project']);
  expect(code).toBe(0);

  expect((await stat(missingSkill)).isFile()).toBe(true);
  const refreshed = await (await import('node:fs/promises')).readFile(staleSkill, 'utf8');
  expect(refreshed).not.toBe('outdated content');
});
