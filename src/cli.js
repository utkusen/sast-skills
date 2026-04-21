import { install } from './commands/install.js';
import { uninstall } from './commands/uninstall.js';
import { doctor } from './commands/doctor.js';
import { exportCmd } from './commands/export.js';
import { clackPrompt } from './prompts/clack.js';

export async function run({ argv, cwd, packageRoot, stdin, stdout }) {
  const [command, ...rest] = argv;
  if (command === 'uninstall') {
    await uninstall({ argv: rest, cwd, packageRoot });
    return;
  }
  if (command === 'doctor') {
    await doctor({ argv: rest, cwd, packageRoot, stdout });
    return;
  }
  if (command === 'export') {
    await exportCmd({ argv: rest, cwd, stdout });
    return;
  }
  const installArgv = command === 'update' ? [...rest, '--force'] : rest;
  await install({
    argv: installArgv,
    cwd,
    packageRoot,
    stdout,
    isTTY: Boolean(stdin.isTTY),
    prompt: clackPrompt,
  });
}
