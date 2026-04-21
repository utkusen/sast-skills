import { defineConfig } from 'vitest/config';
import { VitestReporter } from 'tdd-guard-vitest';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const projectRoot = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    reporters: ['default', new VitestReporter(projectRoot)],
    include: ['test/**/*.test.js'],
  },
});
