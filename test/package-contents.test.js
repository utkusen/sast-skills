import { test, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

async function packedFiles() {
  const { stdout } = await execFileAsync('npm', ['pack', '--dry-run', '--json'], {
    cwd: repoRoot,
    maxBuffer: 10 * 1024 * 1024,
  });
  const [payload] = JSON.parse(stdout);
  return payload.files.map((f) => f.path);
}

test('npm pack ships CLI, src, and bundled skills but excludes tests and demo.gif', async () => {
  const files = await packedFiles();

  expect(files).toContain('package.json');
  expect(files).toContain('bin/sast-skills.js');
  expect(files).toContain('src/cli.js');
  expect(files).toContain('src/commands/install.js');
  expect(files).toContain('src/commands/uninstall.js');
  expect(files).toContain('src/commands/doctor.js');
  expect(files).toContain('src/prompts/clack.js');
  expect(files).toContain('sast-files/CLAUDE.md');
  expect(files).toContain('sast-files/AGENTS.md');
  expect(files).toContain('sast-files/.claude/skills/sast-analysis/SKILL.md');
  expect(files).toContain('sast-files/.agents/skills/sast-analysis/SKILL.md');

  const testFiles = files.filter((f) => f.startsWith('test/'));
  expect(testFiles).toEqual([]);
  expect(files).not.toContain('demo.gif');
  expect(files).not.toContain('vitest.config.js');
}, 30_000);
