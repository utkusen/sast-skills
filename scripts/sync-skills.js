import { rm, cp } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export async function syncSkills({ from, to }) {
  await rm(to, { recursive: true, force: true });
  await cp(from, to, { recursive: true });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , from, to] = process.argv;
  await syncSkills({ from, to });
}
