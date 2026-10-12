// lib/artifacts.js
// Session Artifact Registry: tracks files created during current session
// to permit safe auto-cleanup of temporary artifacts without approval prompt spam (#100).

import path from "node:path";

/**
 * Normalizes file paths for consistent artifact matching across relative and absolute forms.
 *
 * @param {string} filePath
 * @param {string} [workspaceDir]
 * @returns {string}
 */
export function normalizeArtifactPath(filePath, workspaceDir) {
  if (typeof filePath !== "string" || !filePath.trim()) return "";
  let p = filePath.trim().replace(/^["']|["']$/g, "");
  p = p.replace(/\\/g, "/");

  if (workspaceDir && typeof workspaceDir === "string") {
    const ws = workspaceDir.replace(/\\/g, "/").replace(/\/+$/, "");
    if (p.startsWith(ws + "/")) {
      p = p.slice(ws.length + 1);
    }
  }

  p = p.replace(/^\.\//, "");
  return p;
}

/**
 * Registry tracking temporary artifacts created within agent sessions (#100).
 */
export class ArtifactRegistry {
  /**
   * @param {{ workspaceDir?: string }} [options]
   */
  constructor(options = {}) {
    this.workspaceDir = options.workspaceDir || "";
    /** @type {Map<string, Set<string>>} */
    this._sessions = new Map();
  }

  /**
   * Records a created or written artifact for a session.
   *
   * @param {string} sessionId
   * @param {string} filePath
   * @returns {boolean} True if new artifact added, false if already tracked or invalid
   */
  recordArtifact(sessionId, filePath) {
    const sid = String(sessionId || "default");
    const norm = normalizeArtifactPath(filePath, this.workspaceDir);
    if (!norm) return false;

    let set = this._sessions.get(sid);
    if (!set) {
      set = new Set();
      this._sessions.set(sid, set);
    }
    const had = set.has(norm);
    set.add(norm);
    return !had;
  }

  /**
   * Checks whether a specific file was created as an artifact in the given session.
   *
   * @param {string} sessionId
   * @param {string} filePath
   * @returns {boolean}
   */
  isSessionArtifact(sessionId, filePath) {
    const sid = String(sessionId || "default");
    const norm = normalizeArtifactPath(filePath, this.workspaceDir);
    if (!norm) return false;

    const set = this._sessions.get(sid);
    if (!set) return false;
    return set.has(norm);
  }

  /**
   * Checks whether ALL provided files are artifacts created in the given session.
   *
   * @param {string} sessionId
   * @param {string[]} filePaths
   * @returns {boolean}
   */
  areAllSessionArtifacts(sessionId, filePaths) {
    if (!Array.isArray(filePaths) || filePaths.length === 0) return false;
    const sid = String(sessionId || "default");
    const set = this._sessions.get(sid);
    if (!set || set.size === 0) return false;

    for (const fp of filePaths) {
      const norm = normalizeArtifactPath(fp, this.workspaceDir);
      if (!norm || !set.has(norm)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Removes an artifact from session tracking (e.g. after deletion).
   *
   * @param {string} sessionId
   * @param {string} filePath
   * @returns {boolean}
   */
  removeArtifact(sessionId, filePath) {
    const sid = String(sessionId || "default");
    const norm = normalizeArtifactPath(filePath, this.workspaceDir);
    if (!norm) return false;

    const set = this._sessions.get(sid);
    if (!set) return false;
    return set.delete(norm);
  }

  /**
   * Returns list of recorded artifacts for a session.
   *
   * @param {string} sessionId
   * @returns {string[]}
   */
  getArtifacts(sessionId) {
    const sid = String(sessionId || "default");
    const set = this._sessions.get(sid);
    if (!set) return [];
    return Array.from(set);
  }

  /**
   * Returns total count of artifacts recorded for a session.
   *
   * @param {string} sessionId
   * @returns {number}
   */
  count(sessionId) {
    const sid = String(sessionId || "default");
    const set = this._sessions.get(sid);
    return set ? set.size : 0;
  }

  /**
   * Clears tracked artifacts for a specific session.
   *
   * @param {string} sessionId
   */
  clearSession(sessionId) {
    const sid = String(sessionId || "default");
    this._sessions.delete(sid);
  }

  /**
   * Clears all session artifacts across the entire registry.
   */
  clearAll() {
    this._sessions.clear();
  }
}
