# Contributing

Thanks for wanting to help. This project follows **test-driven development** end-to-end — red, green, refactor, one failing test at a time. TDD Guard is wired into the Claude Code session to enforce the cycle. If you're coding locally, run `npm test` frequently.

## Project layout

```text
bin/sast-skills.js          thin CLI shim — argv routing only
src/cli.js                  command router (install/update/uninstall/doctor)
src/commands/*.js           one file per command
src/prompts/clack.js        @clack/prompts wrapper
scripts/sync-skills.js      keep .agents/skills byte-identical to .claude/skills
scripts/scaffold-skill.js   create a new skill SKILL.md in both trees
sast-files/CLAUDE.md        Claude Code entry file shipped to users
sast-files/AGENTS.md        AGENTS.md entry file shipped to users
sast-files/.claude/skills/  canonical skill tree (edit these)
sast-files/.agents/skills/  generated mirror of .claude/skills (do NOT edit by hand)
test/*.test.js              vitest suites
```

## Setup

```bash
npm install
npm test
```

Node 20+ required.

## Adding a new vulnerability skill

1. Scaffold both trees:

   ```bash
   node scripts/scaffold-skill.js sast-yourcheck
   ```

   This creates `SKILL.md` stubs under `sast-files/.claude/skills/sast-yourcheck/` and the matching path in `.agents/skills/`.

2. Write the skill body in `sast-files/.claude/skills/sast-yourcheck/SKILL.md`.

3. Sync the mirror:

   ```bash
   npm run sync
   ```

   This rewrites `.agents/skills` from `.claude/skills`. A regression test catches drift; `prepublishOnly` runs sync before every publish.

4. Reference the skill in `sast-files/CLAUDE.md`, `sast-files/AGENTS.md`, and `README.md`. There are tests that fail if you forget.

5. If the skill's vuln class deserves a dedicated `sast-report` row, update that too.

## Editing `.claude/skills` vs `.agents/skills`

Always edit `.claude/skills`. `.agents/skills` is a generated mirror. `npm run sync` (or any `npm publish`) regenerates it. A test enforces byte-identical equality.

## Writing tests

- One new failing test at a time. Run it, watch it fail for the *right* reason, then implement the minimum to turn it green.
- Tests that spawn the CLI use a tmp `workdir` via `mkdtemp` — see [test/install.test.js](test/install.test.js).
- Tests that unit-test commands import them directly — see [test/install-interactive.test.js](test/install-interactive.test.js).

## Running the CLI locally

```bash
node bin/sast-skills.js install --yes --target /tmp/playground --assistant claude --scope project
node bin/sast-skills.js doctor --target /tmp/playground --assistant claude
```

## Publishing

`npm publish` runs `prepublishOnly`, which runs `npm run sync && npm test`. A dirty working tree or a failing test will abort the publish.

## License

By contributing you agree your work is released under the project's MIT license (see [LICENSE](LICENSE)).
