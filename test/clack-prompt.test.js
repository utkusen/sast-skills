import { test, expect, vi } from 'vitest';

vi.mock('@clack/prompts', () => ({
  select: vi.fn(),
  isCancel: vi.fn().mockReturnValue(false),
}));

const clack = await import('@clack/prompts');
const { clackPrompt } = await import('../src/prompts/clack.js');

test('clackPrompt delegates to @clack/prompts.select and returns the selection', async () => {
  clack.select.mockResolvedValueOnce('agents');

  const result = await clackPrompt({ name: 'assistant', choices: ['claude', 'agents', 'all'] });

  expect(result).toBe('agents');
  expect(clack.select).toHaveBeenCalledTimes(1);
  const call = clack.select.mock.calls[0][0];
  expect(call.message).toMatch(/assistant/i);
  expect(call.options.map((o) => o.value)).toEqual(['claude', 'agents', 'all']);
});

test('clackPrompt throws a user-friendly error when the user cancels', async () => {
  const cancelToken = Symbol('cancel');
  clack.select.mockResolvedValueOnce(cancelToken);
  clack.isCancel.mockReturnValueOnce(true);

  await expect(
    clackPrompt({ name: 'assistant', choices: ['claude', 'agents'] }),
  ).rejects.toThrow(/cancel/i);
});
