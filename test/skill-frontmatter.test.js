import { test, expect } from 'vitest';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const skillsRoot = resolve(here, '..', 'sast-files', '.claude', 'skills');

test('every bundled SKILL.md declares a semver version in its frontmatter', async () => {
  const skills = await readdir(skillsRoot);
  expect(skills.length).toBeGreaterThan(0);

  const violations = [];
  for (const name of skills) {
    const content = await readFile(join(skillsRoot, name, 'SKILL.md'), 'utf8');
    const match = content.match(/^version:\s*([^\s\n]+)/m);
    if (!match) {
      violations.push(`${name}: no version frontmatter`);
      continue;
    }
    if (!/^\d+\.\d+\.\d+$/.test(match[1])) {
      violations.push(`${name}: version "${match[1]}" is not semver`);
    }
  }
  expect(violations).toEqual([]);
});

test('.claude/skills and .agents/skills stay byte-identical', async () => {
  const claudeRoot = resolve(here, '..', 'sast-files', '.claude', 'skills');
  const agentsRoot = resolve(here, '..', 'sast-files', '.agents', 'skills');

  const claudeNames = (await readdir(claudeRoot)).sort();
  const agentsNames = (await readdir(agentsRoot)).sort();
  expect(agentsNames).toEqual(claudeNames);

  for (const name of claudeNames) {
    const c = await readFile(join(claudeRoot, name, 'SKILL.md'), 'utf8');
    const a = await readFile(join(agentsRoot, name, 'SKILL.md'), 'utf8');
    expect(a).toBe(c);
  }
});
