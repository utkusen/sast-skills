import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { syncSkills } from '../scripts/sync-skills.js';

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sync-skills-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('syncSkills makes the destination tree byte-identical to the source tree', async () => {
  const from = join(workdir, 'src');
  const to = join(workdir, 'dst');
  await mkdir(join(from, 'sast-foo'), { recursive: true });
  await mkdir(join(from, 'sast-bar'), { recursive: true });
  await writeFile(join(from, 'sast-foo', 'SKILL.md'), 'canonical foo');
  await writeFile(join(from, 'sast-bar', 'SKILL.md'), 'canonical bar');

  await mkdir(join(to, 'sast-foo'), { recursive: true });
  await mkdir(join(to, 'sast-stale'), { recursive: true });
  await writeFile(join(to, 'sast-foo', 'SKILL.md'), 'drifted foo');
  await writeFile(join(to, 'sast-stale', 'SKILL.md'), 'should be removed');

  await syncSkills({ from, to });

  expect(await readFile(join(to, 'sast-foo', 'SKILL.md'), 'utf8')).toBe('canonical foo');
  expect(await readFile(join(to, 'sast-bar', 'SKILL.md'), 'utf8')).toBe('canonical bar');
  await expect(readFile(join(to, 'sast-stale', 'SKILL.md'), 'utf8')).rejects.toThrow();
});

test('scripts/sync-skills.js is executable as a CLI that syncs the paths passed as args', async () => {
  const from = join(workdir, 'src');
  const to = join(workdir, 'dst');
  await mkdir(join(from, 'sast-foo'), { recursive: true });
  await writeFile(join(from, 'sast-foo', 'SKILL.md'), 'canonical');
  await mkdir(to, { recursive: true });
  await writeFile(join(to, 'stray.md'), 'should be removed');

  const here = dirname(fileURLToPath(import.meta.url));
  const script = resolve(here, '..', 'scripts', 'sync-skills.js');

  const exitCode = await new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [script, from, to], { stdio: 'inherit' });
    child.on('close', resolvePromise);
  });
  expect(exitCode).toBe(0);

  expect(await readFile(join(to, 'sast-foo', 'SKILL.md'), 'utf8')).toBe('canonical');
  await expect(readFile(join(to, 'stray.md'), 'utf8')).rejects.toThrow();
});
