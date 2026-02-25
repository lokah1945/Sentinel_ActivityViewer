/**
 * BrowserPersistence v6.2.0
 * 
 * Manages persistent browser profiles for cross-session continuity.
 * When --persist=<dir> is used, the browser profile (cookies, localStorage,
 * cache, etc.) is preserved between runs.
 */

'use strict';

const fs = require('fs');
const path = require('path');

class BrowserPersistence {
  constructor(profileDir) {
    this.profileDir = profileDir;
  }

  ensureDir() {
    if (this.profileDir && !fs.existsSync(this.profileDir)) {
      fs.mkdirSync(this.profileDir, { recursive: true });
    }
  }

  getProfilePath() {
    return this.profileDir;
  }

  isNewProfile() {
    if (!this.profileDir) return true;
    return !fs.existsSync(path.join(this.profileDir, 'Default', 'Preferences'));
  }
}

module.exports = { BrowserPersistence };
