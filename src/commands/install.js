import { readdir, copyFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const ASSISTANT_LAYOUT = {
  claude: { entryFile: 'CLAUDE.md', skillsDir: '.claude' },
  agents: { entryFile: 'AGENTS.md', skillsDir: '.agents' },
};

const VALID_ASSISTANTS = [...Object.keys(ASSISTANT_LAYOUT), 'all'];
const VALID_SCOPES = ['project', 'global'];

function assistantsFor(choice) {
  if (choice === 'all') return Object.keys(ASSISTANT_LAYOUT);
  return [choice];
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function install({ packageRoot, argv, cwd, stdout, isTTY, prompt }) {
  let target = cwd;
  let dryRun = false;
  let force = false;
  let yes = false;
  let assistant;
  let scope;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--dry-run') dryRun = true;
    else if (argv[i] === '--force') force = true;
    else if (argv[i] === '--yes') yes = true;
    else if (argv[i] === '--assistant') assistant = argv[++i];
    else if (argv[i] === '--scope') scope = argv[++i];
  }

  if (!yes && !isTTY) {
    throw new Error('Non-interactive stdin detected; pass --yes to run without prompts, or run in an interactive TTY.');
  }

  if (!yes && isTTY) {
    if (assistant === undefined) {
      assistant = await prompt({ name: 'assistant', choices: VALID_ASSISTANTS });
    }
    if (scope === undefined) {
      scope = await prompt({ name: 'scope', choices: VALID_SCOPES });
    }
  }

  assistant ??= 'claude';
  scope ??= 'project';

  if (!VALID_ASSISTANTS.includes(assistant)) {
    throw new Error(`Invalid --assistant value: ${assistant}. Expected one of: ${VALID_ASSISTANTS.join(', ')}.`);
  }
  if (!VALID_SCOPES.includes(scope)) {
    throw new Error(`Invalid --scope value: ${scope}. Expected one of: ${VALID_SCOPES.join(', ')}.`);
  }

  const srcRoot = resolve(packageRoot, 'sast-files');

  for (const a of assistantsFor(assistant)) {
    const { entryFile, skillsDir } = ASSISTANT_LAYOUT[a];
    const skillsSrc = resolve(srcRoot, skillsDir, 'skills');
    const skills = await readdir(skillsSrc);

    if (dryRun) {
      stdout.write(`${entryFile}\n`);
      for (const name of skills) {
        stdout.write(`${skillsDir}/skills/${name}/SKILL.md\n`);
      }
      continue;
    }

    if (scope !== 'global') {
      const entryDst = resolve(target, entryFile);
      if (!force && await exists(entryDst)) {
        const err = new Error(`${entryFile} already exists in target; use --force to overwrite`);
        err.code = 'EEXIST';
        throw err;
      }
      await copyFile(resolve(srcRoot, entryFile), entryDst);
    }

    for (const name of skills) {
      const dst = resolve(target, skillsDir, 'skills', name, 'SKILL.md');
      await mkdir(dirname(dst), { recursive: true });
      await copyFile(resolve(skillsSrc, name, 'SKILL.md'), dst);
    }
  }
}
