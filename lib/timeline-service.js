// lib/timeline-service.js
// Session Audit Timeline, Learned Rules & WebServer REST Service for DSH Approval Gate (#82, #60, #74, #86, #84, #49, #116).

import { generateDiffLines, groupHunks, formatUnifiedDiff } from "./diff-viewer.js";

/**
 * @typedef {Object} TimelineEvent
 * @property {string} id
 * @property {string} sessionId
 * @property {string | number} [turnId]
 * @property {number} timestamp
 * @property {string} tool
 * @property {string} [command]
 * @property {string} [snippet]
 * @property {'allow' | 'deny' | 'ask' | 'preempted'} verdict
 * @property {string} [stage]
 * @property {string} [reason]
 * @property {number} [durationMs]
 * @property {number | null} [expiresAt]
 * @property {number | null} [countdownSec]
 * @property {Object} [diffMeta]
 */

/**
 * TimelineService: records call history per session and exposes query & webServer routes (#82).
 */
export class TimelineService {
  /**
   * @param {{ maxEventsPerSession?: number, turnCardTracker?: any, learner?: any, engine?: any }} [options]
   */
  constructor(options = {}) {
    this.maxEventsPerSession = options.maxEventsPerSession || 500;
    this.turnCardTracker = options.turnCardTracker || null;
    this.learner = options.learner || null;
    this.engine = options.engine || null;
    /** @type {Map<string, TimelineEvent[]>} */
    this._sessions = new Map();
    this._nextId = 1;
    this.customRules = [];
    this.whitelistPaths = [];
  }

  /**
   * Records a security gate event into session timeline (#82).
   *
   * @param {Object} raw
   * @returns {TimelineEvent}
   */
  recordEvent(raw) {
    const sid = String(raw.sessionId || "default");
    const tid = raw.turnId !== undefined && raw.turnId !== null ? raw.turnId : "active";

    let list = this._sessions.get(sid);
    if (!list) {
      list = [];
      this._sessions.set(sid, list);
    }

    const id = `evt_${Date.now()}_${this._nextId++}`;
    const timestamp = raw.timestamp || Date.now();
    let countdownSec = null;
    let expiresAt = null;

    if (raw.verdict === "ask" && typeof raw.timeoutMs === "number" && raw.timeoutMs > 0) {
      expiresAt = timestamp + raw.timeoutMs;
      countdownSec = Math.max(0, Math.round(raw.timeoutMs / 1000));
    }

    /** @type {TimelineEvent} */
    const evt = {
      id,
      sessionId: sid,
      turnId: tid,
      timestamp,
      tool: raw.tool || "bash",
      command: raw.command || "",
      snippet: raw.snippet || "",
      verdict: raw.verdict || "allow",
      stage: raw.stage || "",
      reason: raw.reason || "",
      durationMs: raw.durationMs || 0,
      expiresAt,
      countdownSec,
      diffMeta: raw.diffMeta || null,
    };

    list.push(evt);
    if (list.length > this.maxEventsPerSession) {
      list.splice(0, list.length - this.maxEventsPerSession);
    }

    // Also forward to TurnCardTracker if attached (#86)
    if (this.turnCardTracker && typeof this.turnCardTracker.recordCall === "function") {
      this.turnCardTracker.recordCall(sid, tid, {
        tool: evt.tool,
        command: evt.command,
        snippet: evt.snippet,
        verdict: evt.verdict,
        reason: evt.reason,
        durationMs: evt.durationMs,
        timestamp: evt.timestamp,
      });
    }

    return evt;
  }

  /**
   * Retrieves timeline events for a given session with optional filtering (#82).
   *
   * @param {string} sessionId
   * @param {Object} [options]
   * @param {'all' | 'blocked' | 'allowed' | 'ask'} [options.filter='all']
   * @param {number} [options.limit=100]
   * @param {number} [options.offset=0]
   * @returns {{ total: number, events: TimelineEvent[] }}
   */
  getEvents(sessionId, options = {}) {
    const sid = String(sessionId || "default");
    const list = this._sessions.get(sid) || [];
    const filter = options.filter || "all";
    const limit = typeof options.limit === "number" ? Math.max(1, options.limit) : 100;
    const offset = typeof options.offset === "number" ? Math.max(0, options.offset) : 0;

    let filtered = list;
    if (filter === "blocked") {
      filtered = list.filter((e) => e.verdict === "deny");
    } else if (filter === "allowed") {
      filtered = list.filter((e) => e.verdict === "allow");
    } else if (filter === "ask") {
      filtered = list.filter((e) => e.verdict === "ask");
    }

    const total = filtered.length;
    const reversed = filtered.slice().reverse();
    const paginated = reversed.slice(offset, offset + limit);

    return { total, events: paginated };
  }

  /**
   * Clears timeline events for a specific session.
   *
   * @param {string} sessionId
   */
  clearSession(sessionId) {
    const sid = String(sessionId || "default");
    this._sessions.delete(sid);
  }

  /**
   * Registers REST HTTP routes on ctx.webServer for browser UI interaction (#82, #74, #86, #84, #49, #116).
   *
   * @param {any} ctx Cordis context
   * @param {Object} [options]
   * @param {string} [options.prefix='/dsh-approval-gate']
   */
  registerRoutes(ctx, options = {}) {
    const prefix = options.prefix || "/dsh-approval-gate";
    if (!ctx || !ctx.webServer || typeof ctx.webServer.register !== "function") {
      return;
    }

    const jsonResponse = (res, status, data) => {
      res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      });
      res.end(JSON.stringify(data));
    };

    const parseBody = (req) =>
      new Promise((resolve) => {
        let body = "";
        req.on("data", (c) => { body += c; });
        req.on("end", () => {
          try { resolve(JSON.parse(body || "{}")); }
          catch { resolve({}); }
        });
      });

    // 1. GET /timeline
    const timelineRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/timeline`,
        method: "GET",
        handler: async (req, res) => {
          try {
            const url = new URL(req.url, "http://127.0.0.1");
            const sid = url.searchParams.get("sessionId") || "default";
            const filter = url.searchParams.get("filter") || "all";
            const limit = parseInt(url.searchParams.get("limit") || "100", 10);
            const data = this.getEvents(sid, { filter, limit });
            jsonResponse(res, 200, { ok: true, sessionId: sid, ...data });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    // 2. GET /turn-card
    const turnCardRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/turn-card`,
        method: "GET",
        handler: async (req, res) => {
          try {
            const url = new URL(req.url, "http://127.0.0.1");
            const sid = url.searchParams.get("sessionId") || "default";
            const tid = url.searchParams.get("turnId") || "active";
            const lang = url.searchParams.get("lang") || "en";
            let card = null;
            if (this.turnCardTracker && typeof this.turnCardTracker.buildTurnCard === "function") {
              card = this.turnCardTracker.buildTurnCard(sid, tid, { lang });
            }
            jsonResponse(res, 200, { ok: true, sessionId: sid, turnId: tid, card });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    // 3. POST /diff
    const diffRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/diff`,
        method: "POST",
        handler: async (req, res) => {
          try {
            const parsed = await parseBody(req);
            const oldText = parsed.oldText || "";
            const newText = parsed.newText || "";
            const contextLines = typeof parsed.contextLines === "number" ? parsed.contextLines : 3;
            const diffLines = generateDiffLines(oldText, newText);
            const hunks = groupHunks(diffLines, { contextLines });
            const diffText = formatUnifiedDiff(hunks, {
              oldFile: parsed.filename ? `a/${parsed.filename}` : "a/original",
              newFile: parsed.filename ? `b/${parsed.filename}` : "b/modified",
            });
            jsonResponse(res, 200, { ok: true, hunks, diffText, linesCount: diffLines.length });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    // 4. GET /learned-rules (#84)
    const learnedRulesRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/learned-rules`,
        method: "GET",
        handler: async (req, res) => {
          try {
            const url = new URL(req.url, "http://127.0.0.1");
            const sid = url.searchParams.get("sessionId") || "default";
            const rules = (this.learner && typeof this.learner.getLearnedRules === "function")
              ? this.learner.getLearnedRules(sid)
              : [];
            jsonResponse(res, 200, { ok: true, sessionId: sid, rules });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    // 5. POST /learned-rules/revoke (#84)
    const revokeLearnedRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/learned-rules/revoke`,
        method: "POST",
        handler: async (req, res) => {
          try {
            const body = await parseBody(req);
            const sid = body.sessionId || "default";
            const key = body.key || "";
            let revoked = false;
            if (this.learner && typeof this.learner.revoke === "function" && key) {
              revoked = this.learner.revoke(sid, key);
            }
            jsonResponse(res, 200, { ok: true, revoked, key });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    // 6. GET /mode (#116)
    const modeRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/mode`,
        method: "GET",
        handler: async (req, res) => {
          try {
            const mode = this.engine?.mode || "hybrid";
            jsonResponse(res, 200, { ok: true, mode });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    // 7. GET & POST /rules (#49)
    const rulesRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/rules`,
        method: "GET",
        handler: async (req, res) => {
          jsonResponse(res, 200, { ok: true, rules: this.customRules, whitelistPaths: this.whitelistPaths });
        },
      });
    const updateRulesRoute = () =>
      ctx.webServer.register({
        path: `${prefix}/rules`,
        method: "POST",
        handler: async (req, res) => {
          try {
            const body = await parseBody(req);
            if (Array.isArray(body.rules)) this.customRules = body.rules;
            if (Array.isArray(body.whitelistPaths)) this.whitelistPaths = body.whitelistPaths;
            jsonResponse(res, 200, { ok: true, rules: this.customRules, whitelistPaths: this.whitelistPaths });
          } catch (err) {
            jsonResponse(res, 500, { ok: false, error: String(err && err.message || err) });
          }
        },
      });

    const routes = [timelineRoute, turnCardRoute, diffRoute, learnedRulesRoute, revokeLearnedRoute, modeRoute, rulesRoute, updateRulesRoute];
    for (const r of routes) {
      if (typeof ctx.effect === "function") ctx.effect(r, `dsh-approval-gate: ${r.name}`);
      else r();
    }
  }
}
