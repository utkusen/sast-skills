import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const TEMPLATE = (name, version) => `---
name: ${name}
description: TODO — one-line description of what this skill detects and when to use it.
version: ${version}
---

# ${name}

TODO — skill body.
`;

export async function scaffoldSkill({ name, version, roots }) {
  for (const root of roots) {
    const dir = join(root, name);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'SKILL.md'), TEMPLATE(name, version));
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , name] = process.argv;
  const roots = (process.env.SCAFFOLD_ROOTS ?? 'sast-files/.claude/skills:sast-files/.agents/skills').split(':');
  const version = process.env.SCAFFOLD_VERSION ?? '0.1.0';
  await scaffoldSkill({ name, version, roots });
}
