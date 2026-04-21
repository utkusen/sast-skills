import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

test('CLAUDE.md instructs subagents to emit canonical *-results.json findings', async () => {
  const content = await readFile(resolve(repoRoot, 'sast-files', 'CLAUDE.md'), 'utf8');
  expect(content).toMatch(/\*-results\.json/);
  expect(content).toMatch(/canonical/i);
  expect(content).toMatch(/findings/);
  expect(content).toMatch(/severity/);
  expect(content).toMatch(/location/);
});

test('AGENTS.md instructs subagents to emit canonical *-results.json findings', async () => {
  const content = await readFile(resolve(repoRoot, 'sast-files', 'AGENTS.md'), 'utf8');
  expect(content).toMatch(/\*-results\.json/);
  expect(content).toMatch(/canonical/i);
  expect(content).toMatch(/findings/);
  expect(content).toMatch(/severity/);
  expect(content).toMatch(/location/);
});

test('CLAUDE.md defines a Step 4 triage phase that produces final-report-triaged.md', async () => {
  const content = await readFile(resolve(repoRoot, 'sast-files', 'CLAUDE.md'), 'utf8');
  expect(content).toMatch(/## Step 4/);
  expect(content).toMatch(/triage/i);
  expect(content).toMatch(/sast-triage/);
  expect(content).toMatch(/final-report-triaged\.md/);
  expect(content).toMatch(/triaged\.json/);
  expect(content).toMatch(/Skip.*final-report-triaged\.md/i);
});

test('AGENTS.md defines a Step 4 triage phase that produces final-report-triaged.md', async () => {
  const content = await readFile(resolve(repoRoot, 'sast-files', 'AGENTS.md'), 'utf8');
  expect(content).toMatch(/## Step 4/);
  expect(content).toMatch(/triage/i);
  expect(content).toMatch(/sast-triage/);
  expect(content).toMatch(/final-report-triaged\.md/);
  expect(content).toMatch(/triaged\.json/);
  expect(content).toMatch(/Skip.*final-report-triaged\.md/i);
});
