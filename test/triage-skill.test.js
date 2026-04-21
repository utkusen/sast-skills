import { test, expect } from 'vitest';
import { stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

test('sast-triage skill is present under both .claude/skills and .agents/skills', async () => {
  const claudePath = resolve(repoRoot, 'sast-files', '.claude', 'skills', 'sast-triage', 'SKILL.md');
  const agentsPath = resolve(repoRoot, 'sast-files', '.agents', 'skills', 'sast-triage', 'SKILL.md');
  expect((await stat(claudePath)).isFile()).toBe(true);
  expect((await stat(agentsPath)).isFile()).toBe(true);
});

test('sast-triage SKILL.md defines inputs, outputs, FP criteria, severity rubric, and batched verify', async () => {
  const { readFile } = await import('node:fs/promises');
  const claudePath = resolve(repoRoot, 'sast-files', '.claude', 'skills', 'sast-triage', 'SKILL.md');
  const content = await readFile(claudePath, 'utf8');

  expect(content).toMatch(/final-report\.md/);
  expect(content).toMatch(/\*-results\.json/);
  expect(content).toMatch(/final-report-triaged\.md/);
  expect(content).toMatch(/triaged\.json/);

  expect(content).toMatch(/false positive/i);
  expect(content).toMatch(/unreachable/i);
  expect(content).toMatch(/test|mock/i);
  expect(content).toMatch(/duplicate/i);
  expect(content).toMatch(/mitigat/i);

  expect(content).toMatch(/severity/i);
  expect(content).toMatch(/(upgrade|raise|upgraded|increase)/i);
  expect(content).toMatch(/(downgrade|lower|downgraded|decrease)/i);
  expect(content).toMatch(/evidence/i);

  expect(content).toMatch(/batch/i);
  expect(content).toMatch(/merge/i);

  expect(content).toMatch(/triage_status|triageStatus|triage-status/);
});
