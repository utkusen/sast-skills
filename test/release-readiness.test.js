import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

test('CHANGELOG.md follows Keep-a-Changelog format and has a 0.1.0 entry', async () => {
  const content = await readFile(resolve(repoRoot, 'CHANGELOG.md'), 'utf8');
  expect(content).toMatch(/Keep a Changelog/i);
  expect(content).toMatch(/semantic versioning/i);
  expect(content).toMatch(/##\s*\[0\.1\.0\]/);
  expect(content).toMatch(/### Added/);
});

test('CODE_OF_CONDUCT.md adopts Contributor Covenant with an enforcement contact', async () => {
  const content = await readFile(resolve(repoRoot, 'CODE_OF_CONDUCT.md'), 'utf8');
  expect(content).toMatch(/Contributor Covenant/i);
  expect(content).toMatch(/enforcement/i);
  expect(content).toMatch(/(email|@)/);
});

test('publish.yml triggers on version tags, runs tests, and publishes to npm with provenance', async () => {
  const content = await readFile(resolve(repoRoot, '.github', 'workflows', 'publish.yml'), 'utf8');
  expect(content).toMatch(/on:\s*\n[\s\S]*tags:\s*\n[\s\S]*v\*/);
  expect(content).toMatch(/actions\/setup-node@/);
  expect(content).toMatch(/registry-url:\s*['"]?https:\/\/registry\.npmjs\.org/);
  expect(content).toMatch(/npm test/);
  expect(content).toMatch(/npm publish[\s\S]*--provenance/);
  expect(content).toMatch(/NODE_AUTH_TOKEN.*secrets\.NPM_TOKEN/);
  expect(content).toMatch(/id-token:\s*write/);
});

test('issue templates for bug report, feature request, and skill proposal exist and declare labels', async () => {
  const bug = await readFile(resolve(repoRoot, '.github', 'ISSUE_TEMPLATE', 'bug_report.yml'), 'utf8');
  const feat = await readFile(resolve(repoRoot, '.github', 'ISSUE_TEMPLATE', 'feature_request.yml'), 'utf8');
  const skill = await readFile(resolve(repoRoot, '.github', 'ISSUE_TEMPLATE', 'skill_proposal.yml'), 'utf8');

  expect(bug).toMatch(/name:\s*.*[Bb]ug/);
  expect(bug).toMatch(/labels:\s*\[.*bug.*\]/);
  expect(feat).toMatch(/name:\s*.*[Ff]eature/);
  expect(feat).toMatch(/labels:\s*\[.*enhancement.*\]/);
  expect(skill).toMatch(/name:\s*.*[Ss]kill/);
  expect(skill).toMatch(/labels:\s*\[.*skill.*\]/);
});

test('dependabot.yml updates both npm and github-actions ecosystems', async () => {
  const content = await readFile(resolve(repoRoot, '.github', 'dependabot.yml'), 'utf8');
  expect(content).toMatch(/version:\s*2/);
  expect(content).toMatch(/package-ecosystem:\s*['"]?npm/);
  expect(content).toMatch(/package-ecosystem:\s*['"]?github-actions/);
  expect(content).toMatch(/interval:\s*['"]?(weekly|daily)/);
});

test('README reflects the full 0.1.0 surface: badges, flow diagram, every CLI command, every CI integration', async () => {
  const content = await readFile(resolve(repoRoot, 'README.md'), 'utf8');

  // badges
  expect(content).toMatch(/img\.shields\.io\/npm\/v\/sast-skills/);
  expect(content).toMatch(/github\.com\/mstfknn\/sast-skills\/actions\/workflows\/test\.yml/);
  expect(content).toMatch(/img\.shields\.io\/npm\/l\/sast-skills/);
  expect(content).toMatch(/node-%3E%3D20|node-version-%3E%3D20|node-20/i);

  // flow diagram — mermaid block
  expect(content).toMatch(/```mermaid[\s\S]*Step 1[\s\S]*Step 2[\s\S]*Step 3[\s\S]*Step 4[\s\S]*```/);

  // every CLI command
  for (const cmd of ['install', 'update', 'uninstall', 'doctor', 'export']) {
    expect(content).toMatch(new RegExp(`npx sast-skills ${cmd}\\b`));
  }
  expect(content).toMatch(/--triaged/);
  expect(content).toMatch(/--format\s+sarif/);

  // all four flow steps & triage artifacts
  expect(content).toMatch(/final-report-triaged\.md/);
  expect(content).toMatch(/triaged\.json/);

  // CI integrations
  expect(content).toMatch(/actions\/scan/);
  expect(content).toMatch(/pre-commit/);
  expect(content).toMatch(/docker build/i);
});
