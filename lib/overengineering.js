// lib/overengineering.js
// Overengineering guard limiting excessive file creation per session (#89).

export const DEFAULT_MAX_FILES_PER_SESSION = 10;

/**
 * Tracks and limits file creation within agent sessions to prevent codebase bloat and overengineering (#89).
 */
export class OverengineeringGuard {
  /**
   * @param {{ maxFilesPerSession?: number }} [options]
   */
  constructor(options = {}) {
    this.maxFilesPerSession =
      typeof options.maxFilesPerSession === "number" && options.maxFilesPerSession > 0
        ? options.maxFilesPerSession
        : (typeof options.maxCreatedFilesPerSession === "number" && options.maxCreatedFilesPerSession > 0
            ? options.maxCreatedFilesPerSession
            : DEFAULT_MAX_FILES_PER_SESSION);
    this.maxCreatedFilesPerSession = this.maxFilesPerSession;
    this._sessionFiles = new Map();
  }

  /**
   * Gets or initializes the Set of files created in this session.
   * @private
   */
  _getSessionSet(sessionId) {
    const key = sessionId || "default";
    if (!this._sessionFiles.has(key)) {
      this._sessionFiles.set(key, new Set());
    }
    return this._sessionFiles.get(key);
  }

  /**
   * Checks file creation against threshold and records new files.
   *
   * @param {string} sessionId
   * @param {string} filePath
   * @returns {{ allowed: boolean, reason?: string, count: number, limit: number, detail?: string }}
   */
  checkAndRecord(sessionId, filePath) {
    if (!filePath || typeof filePath !== "string") {
      return { allowed: true, count: this.getCount(sessionId), limit: this.maxFilesPerSession };
    }

    const cleanPath = filePath.trim().replace(/\\/g, "/");
    const set = this._getSessionSet(sessionId);

    // If file was already created/tracked in this session, modifying it is permitted
    if (set.has(cleanPath)) {
      return { allowed: true, count: set.size, limit: this.maxFilesPerSession };
    }

    // Check if adding this file exceeds limit
    if (set.size >= this.maxCreatedFilesPerSession) {
      return {
        allowed: false,
        reason: "overengineering-file-limit",
        count: set.size + 1,
        limit: this.maxCreatedFilesPerSession,
        detail: `Created ${set.size + 1} files in session, exceeding limit of ${this.maxCreatedFilesPerSession} files (#89)`,
      };
    }

    set.add(cleanPath);
    return { allowed: true, count: set.size, limit: this.maxFilesPerSession };
  }

  /**
   * Returns current count of created files in session.
   * @param {string} sessionId
   * @returns {number}
   */
  getCount(sessionId) {
    const key = sessionId || "default";
    const set = this._sessionFiles.get(key);
    return set ? set.size : 0;
  }

  /**
   * Clears session tracked files.
   * @param {string} sessionId
   */
  reset(sessionId) {
    const key = sessionId || "default";
    this._sessionFiles.delete(key);
  }

  /**
   * Clears all session tracking.
   */
  clear() {
    this._sessionFiles.clear();
  }
}
