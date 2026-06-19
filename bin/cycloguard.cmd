@echo off
cd /d "%~dp0..\runner"
npx ts-node src/index.ts %*