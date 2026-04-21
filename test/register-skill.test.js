import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, readFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { registerSkill } from '../scripts/register-skill.js';

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'register-skill-'));
  await mkdir(join(workdir, 'sast-files'), { recursive: true });

  await writeFile(join(workdir, 'sast-files', 'CLAUDE.md'), [
    '## Step 2: Vulnerability Detection (Parallel)',
    '',
    '- Skip SQLi if `sast/sqli-results.md` already exists.',
    '',
    '| Skill | Results file | Typical intermediate files to clean |',
    '|-------|----------------|--------------------------------------|',
    '| sast-sqli | `sast/sqli-results.md` | `sast/sqli-recon.md` |',
    '',
    '## Step 3: Report Generation',
  ].join('\n'));

  await writeFile(join(workdir, 'sast-files', 'AGENTS.md'), [
    '## Step 2: Vulnerability Detection (Parallel)',
    '',
    '- Skip SQLi if `sast/sqli-results.md` already exists.',
    '',
    '| Skill | Results file | Typical intermediate files to clean |',
    '|-------|----------------|--------------------------------------|',
    '| sast-sqli | `sast/sqli-results.md` | `sast/sqli-recon.md` |',
    '',
    '## Step 3: Report Generation',
  ].join('\n'));

  await writeFile(join(workdir, 'README.md'), [
    '| Skill | Vulnerability Class |',
    '|---|---|',
    '| sast-sqli | SQL Injection |',
    '| sast-report | Consolidated final report ranked by severity |',
  ].join('\n'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

const FIXTURE = {
  repoRoot: () => workdir,
  name: 'sast-csrf',
  resultsBasename: 'csrf',
  label: 'CSRF',
  description: 'Cross-Site Request Forgery',
};

test('registerSkill patches CLAUDE.md with a skip line and a table row for the new skill', async () => {
  await registerSkill({ ...FIXTURE, repoRoot: workdir });
  const claude = await readFile(join(workdir, 'sast-files', 'CLAUDE.md'), 'utf8');
  expect(claude).toMatch(/Skip CSRF if `sast\/csrf-results\.md` already exists\./);
  expect(claude).toMatch(/\| sast-csrf \| `sast\/csrf-results\.md`/);
});

test('registerSkill patches AGENTS.md with a skip line and a table row for the new skill', async () => {
  await registerSkill({ ...FIXTURE, repoRoot: workdir });
  const agents = await readFile(join(workdir, 'sast-files', 'AGENTS.md'), 'utf8');
  expect(agents).toMatch(/Skip CSRF if `sast\/csrf-results\.md` already exists\./);
  expect(agents).toMatch(/\| sast-csrf \| `sast\/csrf-results\.md`/);
});

test('registerSkill adds the skill to README before the sast-report row', async () => {
  await registerSkill({ ...FIXTURE, repoRoot: workdir });
  const readme = await readFile(join(workdir, 'README.md'), 'utf8');
  expect(readme).toMatch(/\| sast-csrf \| Cross-Site Request Forgery \|/);
  const csrfIdx = readme.indexOf('| sast-csrf |');
  const reportIdx = readme.indexOf('| sast-report |');
  expect(csrfIdx).toBeGreaterThan(-1);
  expect(csrfIdx).toBeLessThan(reportIdx);
});

test('scripts/register-skill.js is callable as a CLI via argv positional arguments', async () => {
  const { spawn } = await import('node:child_process');
  const { resolve, dirname } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const here = dirname(fileURLToPath(import.meta.url));
  const script = resolve(here, '..', 'scripts', 'register-skill.js');

  const code = await new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [script, 'sast-xxx', 'xxx', 'XXX', 'XXX Injection'], {
      stdio: 'inherit',
      env: { ...process.env, REGISTER_REPO_ROOT: workdir },
    });
    child.on('close', resolvePromise);
  });
  expect(code).toBe(0);

  const claude = await readFile(join(workdir, 'sast-files', 'CLAUDE.md'), 'utf8');
  expect(claude).toMatch(/\| sast-xxx \| `sast\/xxx-results\.md`/);
});

test('registerSkill uses the name/label/description/resultsBasename args — not hard-coded CSRF', async () => {
  await registerSkill({
    repoRoot: workdir,
    name: 'sast-openredirect',
    resultsBasename: 'openredirect',
    label: 'Open Redirect',
    description: 'Open redirect bugs',
  });

  const claude = await readFile(join(workdir, 'sast-files', 'CLAUDE.md'), 'utf8');
  expect(claude).toMatch(/Skip Open Redirect if `sast\/openredirect-results\.md` already exists\./);
  expect(claude).toMatch(/\| sast-openredirect \| `sast\/openredirect-results\.md`/);
  expect(claude).not.toMatch(/CSRF/);

  const readme = await readFile(join(workdir, 'README.md'), 'utf8');
  expect(readme).toMatch(/\| sast-openredirect \| Open redirect bugs \|/);
});
