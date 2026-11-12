#!/usr/bin/env node
// F-037: --no-audit keeps plugin installs reproducible/offline. Advisory scanning
// is performed by .github/workflows/dependency_security.yml (npm audit), not here.
const childProcess = require('child_process');
const { packageJsonDirs } = require('./plugin_webpack_directories');

packageJsonDirs('pipe').forEach(pluginPath => {
  childProcess.spawn('npm', ['install', '--no-optional', '--no-audit'], {
    env: process.env,
    cwd: pluginPath,
    stdio: 'inherit',
  });
});
