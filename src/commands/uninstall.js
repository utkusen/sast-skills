import { rm, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const ASSISTANT_LAYOUT = {
  claude: { entryFile: 'CLAUDE.md', skillsDir: '.claude' },
  agents: { entryFile: 'AGENTS.md', skillsDir: '.agents' },
};

async function readIfExists(path) {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}

export async function uninstall({ argv, cwd, packageRoot }) {
  let target = cwd;
  let assistant = 'claude';
  let force = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--assistant') assistant = argv[++i];
    else if (argv[i] === '--force') force = true;
  }

  const { entryFile, skillsDir } = ASSISTANT_LAYOUT[assistant];
  const entryDst = resolve(target, entryFile);

  if (!force) {
    const installedContent = await readIfExists(entryDst);
    const bundledContent = await readIfExists(resolve(packageRoot, 'sast-files', entryFile));
    if (installedContent !== null && bundledContent !== null && installedContent !== bundledContent) {
      throw new Error(`${entryFile} has been modified; pass --force to remove it anyway.`);
    }
  }

  await rm(entryDst, { force: true });
  await rm(resolve(target, skillsDir, 'skills'), { recursive: true, force: true });
}
