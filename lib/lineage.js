// lib/lineage.js
// Subagent hierarchy and parentSession lineage authority (#98).
// Tracks session ancestry trees and propagates authority/policies down the lineage chain.

export class LineageManager {
  constructor() {
    /** @type {Map<string, string>} childSessionId -> parentSessionId */
    this.parentMap = new Map();
    /** @type {Map<string, string>} childSessionId -> explicit rootSessionId */
    this.rootMap = new Map();
    /** @type {Map<string, Set<string>>} parentSessionId -> Set of childSessionIds */
    this.childrenMap = new Map();
  }

  /**
   * Registers parent-child session relationship.
   * Prevents circular parent-child references.
   *
   * @param {string} childSessionId
   * @param {string} parentSessionId
   * @param {string} [rootSessionId]
   * @returns {boolean} True if successfully registered, false if invalid or circular
   */
  registerLineage(childSessionId, parentSessionId, rootSessionId = null) {
    if (!childSessionId || !parentSessionId) return false;
    if (childSessionId === parentSessionId) return false;

    // Check circular references: walking upwards from parent must not reach child
    let curr = parentSessionId;
    const visited = new Set([childSessionId]);
    while (curr) {
      if (visited.has(curr)) return false;
      visited.add(curr);
      curr = this.parentMap.get(curr);
    }

    this.parentMap.set(childSessionId, parentSessionId);
    if (rootSessionId && rootSessionId !== childSessionId) {
      this.rootMap.set(childSessionId, rootSessionId);
    }

    if (!this.childrenMap.has(parentSessionId)) {
      this.childrenMap.set(parentSessionId, new Set());
    }
    this.childrenMap.get(parentSessionId).add(childSessionId);

    return true;
  }

  /**
   * Retrieves the direct parent session ID for a session.
   * @param {string} sessionId
   * @returns {string|null}
   */
  getParent(sessionId) {
    if (!sessionId) return null;
    return this.parentMap.get(sessionId) || null;
  }

  /**
   * Retrieves the ultimate root session ID for a session.
   * @param {string} sessionId
   * @returns {string}
   */
  getRoot(sessionId) {
    if (!sessionId) return "";
    if (this.rootMap.has(sessionId)) {
      return this.rootMap.get(sessionId);
    }

    let curr = sessionId;
    const visited = new Set();
    while (curr && !visited.has(curr)) {
      visited.add(curr);
      const parent = this.parentMap.get(curr);
      if (!parent) break;
      curr = parent;
    }
    return curr;
  }

  /**
   * Returns ancestry array from current session up to root: [sessionId, parentId, ..., rootId].
   * @param {string} sessionId
   * @returns {string[]}
   */
  getLineage(sessionId) {
    if (!sessionId) return [];
    const chain = [];
    let curr = sessionId;
    const visited = new Set();

    while (curr && !visited.has(curr)) {
      visited.add(curr);
      chain.push(curr);
      curr = this.parentMap.get(curr);
    }

    return chain;
  }

  /**
   * Checks whether ancestorSessionId is an ancestor of childSessionId.
   * @param {string} childSessionId
   * @param {string} ancestorSessionId
   * @returns {boolean}
   */
  hasLineageAuthority(childSessionId, ancestorSessionId) {
    if (!childSessionId || !ancestorSessionId) return false;
    if (childSessionId === ancestorSessionId) return true;

    const lineage = this.getLineage(childSessionId);
    return lineage.includes(ancestorSessionId);
  }

  /**
   * Resolves effective policy walking up the lineage hierarchy.
   * Evaluates getPolicyFn(sessionId). If undefined or null, falls back to parent, then root.
   *
   * @param {string} sessionId
   * @param {(id: string) => any} getPolicyFn
   * @returns {any}
   */
  resolveEffectivePolicy(sessionId, getPolicyFn) {
    if (!sessionId || typeof getPolicyFn !== "function") return null;

    const lineage = this.getLineage(sessionId);
    for (const sid of lineage) {
      try {
        const policy = getPolicyFn(sid);
        if (policy !== undefined && policy !== null) {
          return {
            policy,
            sourceSessionId: sid,
            inherited: sid !== sessionId,
          };
        }
      } catch {
        // Continue upward traversal on error
      }
    }

    return null;
  }

  /**
   * Removes tracking for a session and unlinks from its parent.
   * @param {string} sessionId
   * @returns {boolean}
   */
  clearSession(sessionId) {
    if (!sessionId) return false;
    const parent = this.parentMap.get(sessionId);
    if (parent && this.childrenMap.has(parent)) {
      this.childrenMap.get(parent).delete(sessionId);
    }
    this.parentMap.delete(sessionId);
    this.rootMap.delete(sessionId);
    this.childrenMap.delete(sessionId);
    return true;
  }

  /**
   * Clears all lineage mappings.
   */
  clearAll() {
    this.parentMap.clear();
    this.rootMap.clear();
    this.childrenMap.clear();
  }

  /**
   * Returns current statistics for debugging and auditing.
   * @returns {{ trackedSessions: number, rootSessions: number }}
   */
  getStats() {
    return {
      trackedSessions: this.parentMap.size,
      parentCount: this.childrenMap.size,
    };
  }
}
