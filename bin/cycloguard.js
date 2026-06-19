#!/usr/bin/env node
const { execSync } = require('child_process');
const path = require('path');

const args = process.argv.slice(2).join(' ');
const runnerPath = path.resolve(__dirname, '..', 'runner', 'src', 'index.ts');

execSync(`npx ts-node "${runnerPath}" ${args}`, {
  stdio: 'inherit',
  cwd: path.resolve(__dirname, '..', 'runner')
});