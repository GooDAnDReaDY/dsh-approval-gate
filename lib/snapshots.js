// lib/snapshots.js
// Pre-execution Snapshots (#77), Undo/Rollback (#76), and Dual-level Cleanup (#78).
// Zero external dependencies; safe filesystem operations with in-memory metadata.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const DEFAULT_MAX_SNAPSHOTS_PER_SESSION = 50;
export const DEFAULT_MAX_SNAPSHOT_BYTES = 1024 * 1024; // 1 MB

export class SnapshotManager {
  /**
   * @param {Record<string, any>} [options]
   */
  constructor(options = {}) {
    this.maxSnapshotsPerSession = Number(options.maxSnapshotsPerSession) || DEFAULT_MAX_SNAPSHOTS_PER_SESSION;
    this.maxSnapshotBytes = Number(options.maxSnapshotBytes) || DEFAULT_MAX_SNAPSHOT_BYTES;
    this.workspaceDir = options.workspaceDir ? path.resolve(options.workspaceDir) : "";

    /** @type {Map<string, Record<string, any>>} snapshotId -> Snapshot */
    this.snapshots = new Map();
    /** @type {Map<string, string[]>} sessionId -> [snapshotId, ...] */
    this.sessionIndex = new Map();
    /** @type {Map<string, string>} callId -> snapshotId */
    this.callIndex = new Map();
  }

  /**
   * Resolves absolute file path within workspace or host.
   * @param {string} targetPath
   * @returns {string}
   */
  resolvePath(targetPath) {
    if (!targetPath || typeof targetPath !== "string") return "";
    if (path.isAbsolute(targetPath)) return path.normalize(targetPath);
    if (this.workspaceDir) return path.resolve(this.workspaceDir, targetPath);
    return path.resolve(targetPath);
  }

  /**
   * Captures a pre-execution snapshot before file mutation (#77).
   * @param {string} targetPath - Relative or absolute path to target file
   * @param {Record<string, any>} [meta] - Metadata (sessionId, callId, tool)
   * @returns {Record<string, any>} Created snapshot record
   */
  takeSnapshot(targetPath, meta = {}) {
    const resolved = this.resolvePath(targetPath);
    if (!resolved) {
      return { success: false, error: "invalid-target-path" };
    }

    const sessionId = String(meta.sessionId || "default");
    const callId = meta.callId ? String(meta.callId) : null;
    const tool = meta.tool ? String(meta.tool) : "unknown";

    let existed = false;
    let content = null;
    let tooLarge = false;
    let size = 0;

    try {
      if (fs.existsSync(resolved)) {
        existed = true;
        const stat = fs.statSync(resolved);
        size = stat.size;
        if (size > this.maxSnapshotBytes) {
          tooLarge = true;
        } else {
          content = fs.readFileSync(resolved, "utf8");
        }
      }
    } catch {
      // If file unreadable or permission error, proceed safely
      existed = false;
    }

    const id = "snap_" + Date.now() + "_" + crypto.randomBytes(4).toString("hex");
    const snapshot = {
      id,
      sessionId,
      callId,
      tool,
      targetPath: resolved,
      originalPath: targetPath,
      existed,
      content,
      size,
      tooLarge,
      createdAt: Date.now(),
      rolledBack: false,
      rolledBackAt: null,
    };

    this.snapshots.set(id, snapshot);

    if (callId) {
      this.callIndex.set(callId, id);
    }

    if (!this.sessionIndex.has(sessionId)) {
      this.sessionIndex.set(sessionId, []);
    }
    const sessionList = this.sessionIndex.get(sessionId);
    sessionList.push(id);

    // Evict oldest if exceeding maxSnapshotsPerSession
    if (sessionList.length > this.maxSnapshotsPerSession) {
      const evictedId = sessionList.shift();
      if (evictedId) {
        const evicted = this.snapshots.get(evictedId);
        if (evicted && evicted.callId) {
          this.callIndex.delete(evicted.callId);
        }
        this.snapshots.delete(evictedId);
      }
    }

    return snapshot;
  }

  /**
   * Retrieves a snapshot by ID.
   * @param {string} id
   * @returns {Record<string, any> | null}
   */
  getSnapshot(id) {
    return this.snapshots.get(id) || null;
  }

  /**
   * Retrieves a snapshot by tool callId.
   * @param {string} callId
   * @returns {Record<string, any> | null}
   */
  getSnapshotByCallId(callId) {
    const id = this.callIndex.get(String(callId));
    return id ? this.getSnapshot(id) : null;
  }

  /**
   * Retrieves all snapshots for a session.
   * @param {string} sessionId
   * @returns {Record<string, any>[]}
   */
  getSnapshots(sessionId) {
    const ids = this.sessionIndex.get(String(sessionId)) || [];
    const res = [];
    for (const id of ids) {
      const snap = this.snapshots.get(id);
      if (snap) res.push(snap);
    }
    return res;
  }

  /**
   * Undoes a file change by rolling back to its pre-execution snapshot (#76).
   * @param {string} snapshotIdOrCallback - Snapshot ID or Call ID
   * @returns {{ success: boolean, error?: string, snapshotId?: string, targetPath?: string, restoredExisted?: boolean }}
   */
  rollbackSnapshot(snapshotIdOrCallback) {
    if (!snapshotIdOrCallback) {
      return { success: false, error: "snapshot-id-required" };
    }

    let snap = this.snapshots.get(snapshotIdOrCallback);
    if (!snap) {
      const id = this.callIndex.get(String(snapshotIdOrCallback));
      if (id) snap = this.snapshots.get(id);
    }

    if (!snap) {
      return { success: false, error: "snapshot-not-found" };
    }

    if (snap.rolledBack) {
      return { success: false, error: "snapshot-already-rolled-back", snapshotId: snap.id };
    }

    if (snap.tooLarge) {
      return { success: false, error: "snapshot-size-limit-exceeded", snapshotId: snap.id };
    }

    try {
      if (snap.existed && snap.content !== null) {
        // Restore previous content
        const dir = path.dirname(snap.targetPath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(snap.targetPath, snap.content, "utf8");
      } else if (!snap.existed) {
        // File was newly created by this call: delete it to undo
        if (fs.existsSync(snap.targetPath)) {
          fs.unlinkSync(snap.targetPath);
        }
      }

      snap.rolledBack = true;
      snap.rolledBackAt = Date.now();

      return {
        success: true,
        snapshotId: snap.id,
        targetPath: snap.targetPath,
        restoredExisted: snap.existed,
        rolledBackAt: snap.rolledBackAt,
      };
    } catch (err) {
      return {
        success: false,
        error: "rollback-io-error",
        detail: String(err && err.message || err),
        snapshotId: snap.id,
      };
    }
  }

  /**
   * Cleans up snapshots for a single session safely (#78).
   * @param {string} sessionId
   * @returns {{ cleared: number, sessionId: string }}
   */
  clearSnapshots(sessionId) {
    const sId = String(sessionId || "default");
    const ids = this.sessionIndex.get(sId) || [];
    let cleared = 0;
    for (const id of ids) {
      const snap = this.snapshots.get(id);
      if (snap && snap.callId) {
        this.callIndex.delete(snap.callId);
      }
      if (this.snapshots.delete(id)) {
        cleared++;
      }
    }
    this.sessionIndex.delete(sId);
    return { cleared, sessionId: sId };
  }

  /**
   * Cleans up snapshots globally across all sessions (#78).
   * @returns {{ cleared: number }}
   */
  clearAllSnapshots() {
    const total = this.snapshots.size;
    this.snapshots.clear();
    this.sessionIndex.clear();
    this.callIndex.clear();
    return { cleared: total };
  }

  /**
   * Returns snapshot usage metrics and statistics.
   * @returns {{ totalSnapshots: number, sessionCount: number, totalBytes: number }}
   */
  getStats() {
    let totalBytes = 0;
    for (const snap of this.snapshots.values()) {
      totalBytes += snap.size || 0;
    }
    return {
      totalSnapshots: this.snapshots.size,
      sessionCount: this.sessionIndex.size,
      totalBytes,
    };
  }
}
