#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.1.0 — Smart Browser Installer
// ═══════════════════════════════════════════════════════════════
// PROBLEM SOLVED:
//   rebrowser-playwright and playwright have DIFFERENT chromium revision
//   numbers. We must install for BOTH so runtime path resolution works
//   regardless of which package resolves the executable path.
//
// STRATEGY:
//   1. Install via `npx rebrowser-playwright install chromium`
//   2. Install via `npx playwright install chromium` (covers different revision)
//   3. Verify installations exist
// ═══════════════════════════════════════════════════════════════

'use strict';

var { execSync } = require('child_process');
var fs = require('fs');
var path = require('path');
var os = require('os');

function run(cmd, label) {
  console.log('[install-browsers] ' + label + '...');
  try {
    execSync(cmd, { stdio: 'inherit', timeout: 300000 });
    console.log('[install-browsers] \u2713 ' + label + ' OK');
    return true;
  } catch (e) {
    console.warn('[install-browsers] \u26A0 ' + label + ' failed: ' + (e.message || '').slice(0, 200));
    return false;
  }
}

function findChromium() {
  var locations = [];
  var home = process.env.USERPROFILE || process.env.HOME || '';
  if (process.platform === 'win32') {
    locations.push(path.join(home, 'AppData', 'Local', 'ms-playwright'));
  } else {
    locations.push(path.join(home, '.cache', 'ms-playwright'));
    locations.push(path.join(home, 'Library', 'Caches', 'ms-playwright'));
  }
  locations.push(path.join(process.cwd(), 'node_modules', 'playwright-core', '.local-browsers'));

  var found = [];
  locations.forEach(function(loc) {
    if (fs.existsSync(loc)) {
      fs.readdirSync(loc).forEach(function(entry) {
        if (entry.startsWith('chromium-')) found.push(path.join(loc, entry));
      });
    }
  });
  return found;
}

console.log('\n[install-browsers] === SENTINEL v7.1.0 Browser Installer ===');
console.log('[install-browsers] Platform: ' + process.platform + ' | Node: ' + process.version);

// Install for both packages
var ok1 = run('npx rebrowser-playwright install chromium', 'rebrowser-playwright chromium');
var ok2 = run('npx playwright install chromium', 'playwright chromium');

var dirs = findChromium();
if (dirs.length > 0) {
  console.log('[install-browsers] \u2713 Found ' + dirs.length + ' chromium installation(s):');
  dirs.forEach(function(d) { console.log('  ' + d); });
} else if (!ok1 && !ok2) {
  console.log('[install-browsers] \u26A0 No chromium found. Try manually:');
  console.log('  npx playwright install chromium');
}

console.log('[install-browsers] === Done ===\n');
