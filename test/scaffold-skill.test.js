import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { scaffoldSkill } from '../scripts/scaffold-skill.js';

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'scaffold-skill-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('scaffoldSkill writes a SKILL.md template into every provided root', async () => {
  const claudeRoot = join(workdir, 'claude-skills');
  const agentsRoot = join(workdir, 'agents-skills');

  await scaffoldSkill({ name: 'sast-foo', version: '0.1.0', roots: [claudeRoot, agentsRoot] });

  for (const root of [claudeRoot, agentsRoot]) {
    const content = await readFile(join(root, 'sast-foo', 'SKILL.md'), 'utf8');
    expect(content).toMatch(/^---\n/);
    expect(content).toMatch(/^name: sast-foo$/m);
    expect(content).toMatch(/^version: 0\.1\.0$/m);
    expect(content).toMatch(/^description:/m);
  }
});

test('scripts/scaffold-skill.js as a CLI creates the skill under each root passed via env', async () => {
  const claudeRoot = join(workdir, 'claude-skills');
  const agentsRoot = join(workdir, 'agents-skills');

  const here = dirname(fileURLToPath(import.meta.url));
  const script = resolve(here, '..', 'scripts', 'scaffold-skill.js');

  const exitCode = await new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [script, 'sast-wat'], {
      stdio: 'inherit',
      env: { ...process.env, SCAFFOLD_ROOTS: `${claudeRoot}:${agentsRoot}`, SCAFFOLD_VERSION: '0.1.0' },
    });
    child.on('close', resolvePromise);
  });
  expect(exitCode).toBe(0);

  const claudeContent = await readFile(join(claudeRoot, 'sast-wat', 'SKILL.md'), 'utf8');
  expect(claudeContent).toMatch(/name: sast-wat/);
  const agentsContent = await readFile(join(agentsRoot, 'sast-wat', 'SKILL.md'), 'utf8');
  expect(agentsContent).toMatch(/name: sast-wat/);
});
