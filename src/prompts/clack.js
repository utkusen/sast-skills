import { select, isCancel } from '@clack/prompts';

export async function clackPrompt({ name, choices }) {
  const value = await select({
    message: name,
    options: choices.map((value) => ({ value })),
  });
  if (isCancel(value)) {
    throw new Error('Prompt cancelled by user');
  }
  return value;
}
