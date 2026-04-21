import { test, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const skillsRoot = resolve(here, '..', 'sast-files', '.claude', 'skills');

function parseFrontmatter(markdown) {
  const match = markdown.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return null;
  const fields = {};
  for (const line of match[1].split('\n')) {
    const fieldMatch = line.match(/^([a-zA-Z_][\w-]*):\s*(.*)$/);
    if (fieldMatch) fields[fieldMatch[1]] = fieldMatch[2].trim();
  }
  return fields;
}

test('every SKILL.md has name, description, and version, and name matches its directory', async () => {
  const skills = await readdir(skillsRoot);
  const violations = [];
  for (const dir of skills) {
    const content = await readFile(join(skillsRoot, dir, 'SKILL.md'), 'utf8');
    const fm = parseFrontmatter(content);
    if (!fm) { violations.push(`${dir}: no frontmatter block`); continue; }
    for (const field of ['name', 'description', 'version']) {
      if (!fm[field]) violations.push(`${dir}: missing ${field}`);
    }
    if (fm.name && fm.name !== dir) {
      violations.push(`${dir}: name "${fm.name}" does not match directory`);
    }
  }
  expect(violations).toEqual([]);
});
