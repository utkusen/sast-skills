import { test, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
const skillsRoot = resolve(repoRoot, 'sast-files', '.claude', 'skills');

test('AGENTS.md references every bundled skill', async () => {
  const agents = await readFile(resolve(repoRoot, 'sast-files', 'AGENTS.md'), 'utf8');
  const skills = (await readdir(skillsRoot)).sort();
  const missing = skills.filter((name) => !agents.includes(name));
  expect(missing).toEqual([]);
});

test('README.md references every bundled skill', async () => {
  const readme = await readFile(resolve(repoRoot, 'README.md'), 'utf8');
  const skills = (await readdir(skillsRoot)).sort();
  const missing = skills.filter((name) => !readme.includes(name));
  expect(missing).toEqual([]);
});
