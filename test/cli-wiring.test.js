import { test, expect, vi } from 'vitest';

vi.mock('../src/commands/install.js', () => ({
  install: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('../src/prompts/clack.js', () => ({
  clackPrompt: vi.fn(),
}));

const { install } = await import('../src/commands/install.js');
const { clackPrompt } = await import('../src/prompts/clack.js');
const { run } = await import('../src/cli.js');

test('run install wires clackPrompt into the install command', async () => {
  await run({
    argv: ['install', '--yes'],
    cwd: '/tmp',
    packageRoot: '/pkg',
    stdin: { isTTY: true },
    stdout: { write: () => {} },
    stderr: { write: () => {} },
  });

  expect(install).toHaveBeenCalledTimes(1);
  expect(install.mock.calls[0][0]).toMatchObject({ prompt: clackPrompt });
});
