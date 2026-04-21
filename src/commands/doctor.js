import { readFile, readdir } from 'node:fs/promises';
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

function classify(installed, bundled) {
  if (installed === null) return 'MISSING';
  if (installed !== bundled) return 'MODIFIED';
  return 'OK';
}

export async function doctor({ argv, cwd, packageRoot, stdout }) {
  let target = cwd;
  let assistant = 'claude';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--assistant') assistant = argv[++i];
  }

  const { entryFile, skillsDir } = ASSISTANT_LAYOUT[assistant];
  const srcRoot = resolve(packageRoot, 'sast-files');
  let ok = true;

  const bundledEntry = await readIfExists(resolve(srcRoot, entryFile));
  const installedEntry = await readIfExists(resolve(target, entryFile));
  const entryStatus = classify(installedEntry, bundledEntry);
  if (entryStatus !== 'OK') ok = false;
  stdout.write(`${entryFile}: ${entryStatus}\n`);

  const skillsSrc = resolve(srcRoot, skillsDir, 'skills');
  const skills = await readdir(skillsSrc);
  for (const name of skills) {
    const bundled = await readIfExists(resolve(skillsSrc, name, 'SKILL.md'));
    const installed = await readIfExists(resolve(target, skillsDir, 'skills', name, 'SKILL.md'));
    const status = classify(installed, bundled);
    if (status !== 'OK') ok = false;
    stdout.write(`${skillsDir}/skills/${name}/SKILL.md: ${status}\n`);
  }

  if (!ok) throw new Error('doctor detected issues');
}
