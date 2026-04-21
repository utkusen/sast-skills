import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const skillsRoot = resolve(here, '..', 'sast-files', '.claude', 'skills');

const NEW_SKILLS = [
  'sast-csrf',
  'sast-openredirect',
  'sast-cors',
  'sast-ldap',
  'sast-nosql',
  'sast-prototype',
  'sast-redos',
  'sast-crypto',
  'sast-race',
  'sast-pii',
  'sast-deps',
  'sast-iac',
  'sast-promptinjection',
  'sast-llmoutput',
];

test('every new M5 skill has a full three-phase body with canonical JSON output', async () => {
  const violations = [];
  for (const name of NEW_SKILLS) {
    const content = await readFile(join(skillsRoot, name, 'SKILL.md'), 'utf8');
    const problems = [];

    if (content.length < 2000) problems.push(`body too short (${content.length} bytes — likely still a TODO stub)`);

    if (!/^name:\s*sast-[a-z-]+\s*$/m.test(content)) problems.push('missing name frontmatter');
    if (!/^version:\s*\d+\.\d+\.\d+\s*$/m.test(content)) problems.push('missing semver version frontmatter');
    if (!/^description:/m.test(content)) problems.push('missing description frontmatter');

    if (!/Prerequisites[^\n]*architecture\.md/i.test(content)) problems.push('missing architecture.md prerequisite');

    if (!/Phase\s*1[^\n]*(recon|discover)/i.test(content)) problems.push('missing Phase 1 recon heading');
    if (!/Phase\s*2[^\n]*verify/i.test(content)) problems.push('missing Phase 2 verify heading');
    if (!/Phase\s*3[^\n]*merge/i.test(content)) problems.push('missing Phase 3 merge heading');
    if (!/batch/i.test(content)) problems.push('no mention of batched verify');

    const resultsBasename = name.replace(/^sast-/, '');
    const resultsPattern = new RegExp(`sast/${resultsBasename}-results\\.md`);
    if (!resultsPattern.test(content)) problems.push(`missing reference to sast/${resultsBasename}-results.md`);

    if (!/canonical|findings.*json|results\.json/i.test(content)) problems.push('missing canonical JSON output reference');

    if (!/## What is/i.test(content) && !/##\s+[A-Z]/.test(content)) problems.push('no top-level What-is / overview heading');

    if (problems.length) violations.push(`${name}:\n  - ${problems.join('\n  - ')}`);
  }
  expect(violations, `skills failing the contract:\n${violations.join('\n')}`).toEqual([]);
});
