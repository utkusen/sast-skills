import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { install } from '../src/commands/install.js';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-interactive-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

test('install in interactive mode prompts for missing assistant and scope', async () => {
  const asked = [];
  const prompt = async ({ name, choices }) => {
    asked.push({ name, choices });
    if (name === 'assistant') return 'claude';
    if (name === 'scope') return 'project';
    throw new Error(`unexpected prompt for ${name}`);
  };

  const stdout = { write: () => {} };
  await install({
    packageRoot,
    argv: ['--target', workdir],
    cwd: workdir,
    stdout,
    isTTY: true,
    prompt,
  });

  expect(asked.map((a) => a.name)).toEqual(['assistant', 'scope']);
  expect(asked[0].choices).toEqual(expect.arrayContaining(['claude', 'agents', 'all']));
  expect(asked[1].choices).toEqual(expect.arrayContaining(['project', 'global']));

  const claudeMd = join(workdir, 'CLAUDE.md');
  expect((await stat(claudeMd)).isFile()).toBe(true);
});
