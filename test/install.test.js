import { test, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readdir, readFile, stat, writeFile } from 'node:fs/promises';
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
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-test-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('install --dry-run lists files that would be written and touches nothing', async () => {
  const { code, stdout } = await run([
    'install',
    '--dry-run',
    '--yes',
    '--target', workdir,
    '--assistant', 'claude',
    '--scope', 'project',
  ]);
  expect(code).toBe(0);
  expect(stdout).toMatch(/CLAUDE\.md/);
  expect(stdout).toMatch(/sast-analysis\/SKILL\.md/);

  const entries = await readdir(workdir);
  expect(entries).toEqual([]);
});

test('install --yes writes CLAUDE.md and skill files into target', async () => {
  const { code } = await run([
    'install',
    '--yes',
    '--target', workdir,
    '--assistant', 'claude',
    '--scope', 'project',
  ]);
  expect(code).toBe(0);

  const claudeMd = await readFile(join(workdir, 'CLAUDE.md'), 'utf8');
  expect(claudeMd).toMatch(/SAST Security Assessment/);

  const skillFile = join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md');
  const st = await stat(skillFile);
  expect(st.isFile()).toBe(true);
});

test('install --assistant agents writes AGENTS.md and .agents/skills/', async () => {
  const { code } = await run([
    'install',
    '--yes',
    '--target', workdir,
    '--assistant', 'agents',
    '--scope', 'project',
  ]);
  expect(code).toBe(0);

  const agentsMd = await readFile(join(workdir, 'AGENTS.md'), 'utf8');
  expect(agentsMd).toMatch(/SAST Security Assessment/);

  const skillFile = join(workdir, '.agents', 'skills', 'sast-analysis', 'SKILL.md');
  const st = await stat(skillFile);
  expect(st.isFile()).toBe(true);

  const claudeDirs = await readdir(workdir);
  expect(claudeDirs).not.toContain('CLAUDE.md');
  expect(claudeDirs).not.toContain('.claude');
});

test('install --assistant all writes both CLAUDE.md and AGENTS.md trees', async () => {
  const { code } = await run([
    'install',
    '--yes',
    '--target', workdir,
    '--assistant', 'all',
    '--scope', 'project',
  ]);
  expect(code).toBe(0);

  expect((await stat(join(workdir, 'CLAUDE.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, 'AGENTS.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.agents', 'skills', 'sast-analysis', 'SKILL.md'))).isFile()).toBe(true);
});

test('install refuses to overwrite existing CLAUDE.md without --force', async () => {
  const existing = 'user-authored content — do not clobber';
  await writeFile(join(workdir, 'CLAUDE.md'), existing);

  const { code, stderr } = await run([
    'install',
    '--yes',
    '--target', workdir,
    '--assistant', 'claude',
    '--scope', 'project',
  ]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/CLAUDE\.md.*exist/i);

  const after = await readFile(join(workdir, 'CLAUDE.md'), 'utf8');
  expect(after).toBe(existing);
});

test('install --force overwrites an existing CLAUDE.md', async () => {
  await writeFile(join(workdir, 'CLAUDE.md'), 'stale content');

  const { code } = await run([
    'install',
    '--yes',
    '--force',
    '--target', workdir,
    '--assistant', 'claude',
    '--scope', 'project',
  ]);
  expect(code).toBe(0);

  const after = await readFile(join(workdir, 'CLAUDE.md'), 'utf8');
  expect(after).toMatch(/SAST Security Assessment/);
});

test('install --scope global writes skills under $HOME and skips the entry file', async () => {
  const { code } = await run([
    'install',
    '--yes',
    '--assistant', 'claude',
    '--scope', 'global',
  ], { cwd: workdir, env: { HOME: workdir, USERPROFILE: workdir } });
  expect(code).toBe(0);

  const skillFile = join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md');
  expect((await stat(skillFile)).isFile()).toBe(true);

  const entries = await readdir(workdir);
  expect(entries).not.toContain('CLAUDE.md');
});

test('install rejects an invalid --assistant value with a clear error', async () => {
  const { code, stderr } = await run([
    'install',
    '--yes',
    '--target', workdir,
    '--assistant', 'bogus',
    '--scope', 'project',
  ]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/--assistant/);
  expect(stderr).toMatch(/bogus/);
  expect(stderr).toMatch(/claude|agents|all/);
});

test('install rejects an invalid --scope value with a clear error', async () => {
  const { code, stderr } = await run([
    'install',
    '--yes',
    '--target', workdir,
    '--assistant', 'claude',
    '--scope', 'planet',
  ]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/--scope/);
  expect(stderr).toMatch(/planet/);
  expect(stderr).toMatch(/project|global/);
});

test('install without --yes on a non-TTY stdin fails with actionable guidance', async () => {
  const { code, stderr } = await run([
    'install',
    '--target', workdir,
    '--assistant', 'claude',
    '--scope', 'project',
  ]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/--yes/);
  expect(stderr).toMatch(/interactive|TTY/i);
});
