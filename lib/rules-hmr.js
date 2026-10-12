// lib/rules-hmr.js
// Hot Module Reloading for Security Rules (#43).
// Watches .dsh/rules.yaml and declarative rule definitions using Node.js stdlib fs watchers.
// Recompiles rules in-memory atomically without dropping active sessions or restarting dsh.

import fs from "node:fs";

export const DEFAULT_HMR_DEBOUNCE_MS = 150;

/**
 * Manages atomic hot reload watchers for rule definitions (#43).
 */
export class RulesHmrWatcher {
  /**
   * @param {{ debounceMs?: number, logger?: any }} [options]
   */
  constructor(options = {}) {
    this.debounceMs = options.debounceMs || DEFAULT_HMR_DEBOUNCE_MS;
    this.logger = options.logger || null;
    /** @type {Map<string, fs.FSWatcher>} */
    this.watchers = new Map();
    /** @type {NodeJS.Timeout | null} */
    this.debounceTimer = null;
    this.reloading = false;
  }

  /**
   * Attaches file watchers for declarative rules files.
   *
   * @param {any} rulesEngine - Instance of DeclarativeRulesEngine
   * @param {string[]} filePaths - Files or directories to watch
   * @param {(info: { path: string, timestamp: number }) => void} [onReload]
   * @returns {number} Count of successfully watched paths
   */
  watch(rulesEngine, filePaths = [], onReload = null) {
    if (!rulesEngine || !Array.isArray(filePaths)) return 0;
    let watchedCount = 0;

    for (const targetPath of filePaths) {
      if (!targetPath || typeof targetPath !== "string") continue;
      if (this.watchers.has(targetPath)) continue;

      try {
        if (!fs.existsSync(targetPath)) continue;

        const watcher = fs.watch(targetPath, { persistent: false }, (eventType, filename) => {
          this._handleFileChange(rulesEngine, targetPath, onReload);
        });

        watcher.on("error", (err) => {
          if (this.logger) this.logger.warn?.(`RulesHmrWatcher error on ${targetPath}:`, err);
          this.unwatch(targetPath);
        });

        this.watchers.set(targetPath, watcher);
        watchedCount += 1;
      } catch (err) {
        if (this.logger) this.logger.warn?.(`Failed to watch ${targetPath}:`, err);
      }
    }

    return watchedCount;
  }

  /**
   * Unwatches a specific file path.
   * @param {string} targetPath
   */
  unwatch(targetPath) {
    const watcher = this.watchers.get(targetPath);
    if (watcher) {
      try {
        watcher.close();
      } catch (_e) {}
      this.watchers.delete(targetPath);
    }
  }

  /**
   * Closes all active file watchers.
   */
  close() {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    for (const [p, watcher] of this.watchers.entries()) {
      try {
        watcher.close();
      } catch (_e) {}
    }
    this.watchers.clear();
  }

  /**
   * @private
   */
  _handleFileChange(rulesEngine, targetPath, onReload) {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this._triggerReload(rulesEngine, targetPath, onReload);
    }, this.debounceMs);
  }

  /**
   * @private
   */
  _triggerReload(rulesEngine, targetPath, onReload) {
    if (this.reloading) return;
    this.reloading = true;

    try {
      if (typeof rulesEngine.reload === "function") {
        rulesEngine.reload();
      } else if (typeof rulesEngine.loadRules === "function") {
        rulesEngine.loadRules();
      }

      if (typeof onReload === "function") {
        onReload({ path: targetPath, timestamp: Date.now() });
      }
    } catch (err) {
      if (this.logger) this.logger.error?.(`Failed to reload rules for ${targetPath}:`, err);
    } finally {
      this.reloading = false;
    }
  }
}
