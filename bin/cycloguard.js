#!/usr/bin/env node
const { spawnSync } = require('child_process');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const runnerPath = path.join(repoRoot, 'runner', 'src', 'index.ts');
const tsconfigPath = path.join(repoRoot, 'runner', 'tsconfig.json');
const tsNodeBin = require.resolve('ts-node/dist/bin.js', { paths: [repoRoot] });
const args = [tsNodeBin, '-P', tsconfigPath, runnerPath, ...process.argv.slice(2)];

const result = spawnSync(process.execPath, args, {
  stdio: 'inherit',
  cwd: repoRoot
});

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
