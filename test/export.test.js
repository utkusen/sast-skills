import { test, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const bin = resolve(here, '..', 'bin', 'sast-skills.js');

function run(args, opts = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [bin, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-export-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

const findingsFixture = {
  run: { tool: 'sast-skills', version: '0.1.0' },
  findings: [
    {
      id: 'sast-sqli-0001',
      skill: 'sast-sqli',
      severity: 'high',
      title: 'SQL injection in /api/user',
      description: 'User id concatenated into raw query.',
      location: { file: 'src/api/user.js', line: 42, column: 10 },
      remediation: 'Use parameterized queries.',
    },
  ],
};

test('export --format json echoes the findings JSON to stdout', async () => {
  const input = join(workdir, 'findings.json');
  await writeFile(input, JSON.stringify(findingsFixture));

  const { code, stdout } = await run(['export', '--format', 'json', '--input', input]);
  expect(code).toBe(0);

  const parsed = JSON.parse(stdout);
  expect(parsed).toEqual(findingsFixture);
});

test('export --triaged prefers sast/triaged.json over raw *-results.json files', async () => {
  const sastDir = join(workdir, 'sast');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(sastDir, { recursive: true });

  const rawFinding = { id: 'raw', skill: 'sast-sqli', severity: 'high', title: 'raw-title', description: 'd', location: { file: 'a.js', line: 1, column: 1 }, remediation: '' };
  const triagedFinding = { id: 'raw', skill: 'sast-sqli', severity: 'low', title: 'triaged-title', description: 'downgraded: not reachable', location: { file: 'a.js', line: 1, column: 1 }, remediation: '' };

  await writeFile(join(sastDir, 'sqli-results.json'), JSON.stringify({ findings: [rawFinding] }));
  await writeFile(join(sastDir, 'triaged.json'), JSON.stringify({ run: { tool: 'sast-skills', version: '0.1.0' }, findings: [triagedFinding] }));

  const { code, stdout } = await run(['export', '--format', 'json', '--triaged', '--input', sastDir]);
  expect(code).toBe(0);

  const parsed = JSON.parse(stdout);
  expect(parsed.findings).toHaveLength(1);
  expect(parsed.findings[0].title).toBe('triaged-title');
  expect(parsed.findings[0].severity).toBe('low');
});

test('export --input <dir> aggregates every *-results.json in the directory', async () => {
  const sastDir = join(workdir, 'sast');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(sastDir, { recursive: true });

  const sqliFinding = { id: 's1', skill: 'sast-sqli', severity: 'high', title: 'sqli-a', description: 'd', location: { file: 'a.js', line: 1, column: 1 }, remediation: '' };
  const xssFinding = { id: 'x1', skill: 'sast-xss', severity: 'medium', title: 'xss-a', description: 'd', location: { file: 'b.js', line: 2, column: 1 }, remediation: '' };

  await writeFile(join(sastDir, 'sqli-results.json'), JSON.stringify({ findings: [sqliFinding] }));
  await writeFile(join(sastDir, 'xss-results.json'), JSON.stringify({ findings: [xssFinding] }));

  const { code, stdout } = await run(['export', '--format', 'json', '--input', sastDir]);
  expect(code).toBe(0);

  const parsed = JSON.parse(stdout);
  expect(parsed.findings).toHaveLength(2);
  expect(parsed.findings.map((f) => f.id).sort()).toEqual(['s1', 'x1']);
});

test('export --output writes to the given file instead of stdout', async () => {
  const input = join(workdir, 'findings.json');
  const out = join(workdir, 'report.html');
  await writeFile(input, JSON.stringify(findingsFixture));

  const { code, stdout } = await run(['export', '--format', 'html', '--input', input, '--output', out]);
  expect(code).toBe(0);
  expect(stdout).toBe('');

  const fileContents = await readFile(out, 'utf8');
  expect(fileContents).toMatch(/<!DOCTYPE html>/i);
  expect(fileContents).toMatch(/SQL injection/);
});

test('export --format html produces an HTML report with a findings table', async () => {
  const input = join(workdir, 'findings.json');
  await writeFile(input, JSON.stringify(findingsFixture));

  const { code, stdout } = await run(['export', '--format', 'html', '--input', input]);
  expect(code).toBe(0);

  expect(stdout).toMatch(/<!DOCTYPE html>/i);
  expect(stdout).toMatch(/<table[^>]*>/);
  expect(stdout).toMatch(/SQL injection in \/api\/user/);
  expect(stdout).toMatch(/high/);
  expect(stdout).toMatch(/src\/api\/user\.js.*42/);
});

test('HTML output tags severity cells with a class for CSS styling', async () => {
  const input = join(workdir, 'findings.json');
  await writeFile(input, JSON.stringify(findingsFixture));

  const { stdout } = await run(['export', '--format', 'html', '--input', input]);
  expect(stdout).toMatch(/class="severity-high"/);
  expect(stdout).toMatch(/<style[^>]*>[\s\S]*\.severity-high\b/);
});

test('SARIF level maps severities: critical/high→error, medium→warning, low/info→note', async () => {
  const fixture = {
    run: { tool: 'sast-skills', version: '0.1.0' },
    findings: [
      { id: '1', skill: 's', severity: 'critical', title: 't', description: 'd', location: { file: 'x', line: 1, column: 1 }, remediation: '' },
      { id: '2', skill: 's', severity: 'high',     title: 't', description: 'd', location: { file: 'x', line: 1, column: 1 }, remediation: '' },
      { id: '3', skill: 's', severity: 'medium',   title: 't', description: 'd', location: { file: 'x', line: 1, column: 1 }, remediation: '' },
      { id: '4', skill: 's', severity: 'low',      title: 't', description: 'd', location: { file: 'x', line: 1, column: 1 }, remediation: '' },
      { id: '5', skill: 's', severity: 'info',     title: 't', description: 'd', location: { file: 'x', line: 1, column: 1 }, remediation: '' },
    ],
  };
  const input = join(workdir, 'findings.json');
  await writeFile(input, JSON.stringify(fixture));

  const { stdout } = await run(['export', '--format', 'sarif', '--input', input]);
  const levels = JSON.parse(stdout).runs[0].results.map((r) => r.level);
  expect(levels).toEqual(['error', 'error', 'warning', 'note', 'note']);
});

test('export --format sarif produces a valid SARIF 2.1.0 document', async () => {
  const input = join(workdir, 'findings.json');
  await writeFile(input, JSON.stringify(findingsFixture));

  const { code, stdout } = await run(['export', '--format', 'sarif', '--input', input]);
  expect(code).toBe(0);

  const sarif = JSON.parse(stdout);
  expect(sarif.version).toBe('2.1.0');
  expect(sarif.runs[0].tool.driver.name).toBe('sast-skills');
  expect(sarif.runs[0].tool.driver.rules.map((r) => r.id)).toContain('sast-sqli');

  const result = sarif.runs[0].results[0];
  expect(result.ruleId).toBe('sast-sqli');
  expect(result.level).toBe('error');
  expect(result.message.text).toMatch(/SQL injection/);
  expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('src/api/user.js');
  expect(result.locations[0].physicalLocation.region.startLine).toBe(42);
});
