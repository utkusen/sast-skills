import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

function patchOrchestrator(content, { name, resultsBasename, label }) {
  const skipLine = `- Skip ${label} if \`sast/${resultsBasename}-results.md\` already exists.`;
  const tableRow = `| ${name} | \`sast/${resultsBasename}-results.md\` | \`sast/${resultsBasename}-recon.md\`, \`sast/${resultsBasename}-batch-*.md\` |`;
  const lines = content.split('\n');
  let lastSkip = -1;
  let lastRow = -1;
  lines.forEach((line, i) => {
    if (line.startsWith('- Skip ') && line.includes('-results.md')) lastSkip = i;
    if (line.startsWith('| sast-') && !line.startsWith('| sast-report')) lastRow = i;
  });
  lines.splice(lastRow + 1, 0, tableRow);
  lines.splice(lastSkip + 1, 0, skipLine);
  return lines.join('\n');
}

function patchReadme(content, { name, description }) {
  const row = `| ${name} | ${description} |`;
  const lines = content.split('\n');
  const reportIdx = lines.findIndex((l) => l.startsWith('| sast-report'));
  lines.splice(reportIdx, 0, row);
  return lines.join('\n');
}

export async function registerSkill({ repoRoot, name, resultsBasename, label, description }) {
  const claudePath = join(repoRoot, 'sast-files', 'CLAUDE.md');
  const agentsPath = join(repoRoot, 'sast-files', 'AGENTS.md');
  const readmePath = join(repoRoot, 'README.md');

  const [claude, agents, readme] = await Promise.all([
    readFile(claudePath, 'utf8'),
    readFile(agentsPath, 'utf8'),
    readFile(readmePath, 'utf8'),
  ]);

  await writeFile(claudePath, patchOrchestrator(claude, { name, resultsBasename, label }));
  await writeFile(agentsPath, patchOrchestrator(agents, { name, resultsBasename, label }));
  await writeFile(readmePath, patchReadme(readme, { name, description }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , name, resultsBasename, label, ...descWords] = process.argv;
  const description = descWords.join(' ');
  const repoRoot = process.env.REGISTER_REPO_ROOT ?? process.cwd();
  await registerSkill({ repoRoot, name, resultsBasename, label, description });
}
