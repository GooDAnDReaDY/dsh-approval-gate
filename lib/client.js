// lib/client.js
// Browser client half for DeepSeek Harness: Approval Gate UI (#74, #75, #82, #86, #60).
// Self-registering module for window.__ModuleLoader__.
// Canonical languages: English (en) and Chinese (zh).

window.__ModuleLoader__.load({
  id: "@goodandready/dsh-approval-gate",
  factory: (require) => {
    var module = { exports: {} };
    const React = require("react");
    const h = React.createElement;

    const NS = "dsh-approval-gate";
    const PKG = "@goodandready/dsh-approval-gate";

    // ----------------------------------------------------------- localizations
    const en = {
      title: "Approval Gate",
      tabTitle: "Approvals",
      timelineTitle: "Session Audit Timeline",
      filterAll: "All",
      filterBlocked: "Blocked",
      filterAsked: "Asked",
      filterAllowed: "Allowed",
      noEvents: "No security gate events in this session yet.",
      viewDiff: "View Diff",
      diffModalTitle: "Unified Diff Viewer",
      close: "Close",
      expandFold: "Click to expand {count} unchanged lines",
      collapseFold: "Collapse unchanged lines",
      autoTimeoutIn: "Auto-decision in {seconds}s",
      timerPaused: "Timer paused",
      pauseTimer: "Pause",
      resumeTimer: "Resume",
      turnSummary: "Round Summary",
      statusClean: "Clean (all calls approved)",
      statusWarnings: "Warnings (confirmations requested)",
      statusBlocked: "Blocked operations detected",
    };

    const zh = {
      title: "安全审批网关",
      tabTitle: "审批记录",
      timelineTitle: "会话安全审计时间线",
      filterAll: "全部",
      filterBlocked: "已拦截",
      filterAsked: "待确认",
      filterAllowed: "已放行",
      noEvents: "当前会话暂无安全拦截或审批记录。",
      viewDiff: "查看差异",
      diffModalTitle: "统一差异比对器",
      close: "关闭",
      expandFold: "点击展开 {count} 行未修改代码",
      collapseFold: "折叠未修改代码",
      autoTimeoutIn: "倒计时 {seconds} 秒后自动判定",
      timerPaused: "倒计时已暂停",
      pauseTimer: "暂停",
      resumeTimer: "继续",
      turnSummary: "轮次总结",
      statusClean: "安全（全部放行）",
      statusWarnings: "提示（已请求人工确认）",
      statusBlocked: "拦截（存在违规操作）",
    };

    // ----------------------------------------------------------- CSS Styles
    const css = `
      .ag-view-tab { display: flex; flex-direction: column; height: 100%; padding: 12px; font-family: inherit; color: var(--dsw-alias-label-primary); }
      .ag-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
      .ag-title { font-size: 14px; font-weight: 600; color: var(--dsw-alias-label-primary); }
      .ag-filters { display: flex; gap: 6px; }
      .ag-btn-filter { font-size: 11px; padding: 3px 8px; border-radius: 6px; border: 1px solid var(--dsw-alias-border-l2); background: transparent; color: var(--dsw-alias-label-secondary); cursor: pointer; }
      .ag-btn-filter.ag-active { background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font-weight: 600; }
      
      .ag-turn-card { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-3); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
      .ag-turn-status { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
      .ag-turn-status.ag-clean { color: #22c55e; }
      .ag-turn-status.ag-warnings { color: #eab308; }
      .ag-turn-status.ag-blocked { color: #ef4444; }
      .ag-turn-desc { font-size: 11px; color: var(--dsw-alias-label-secondary); }

      .ag-events-list { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; }
      .ag-event-item { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-3); border-radius: 8px; padding: 8px 10px; font-size: 12px; }
      .ag-event-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
      .ag-badge { font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; }
      .ag-badge-allow { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
      .ag-badge-deny { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
      .ag-badge-ask { background: rgba(234, 179, 8, 0.15); color: #eab308; }
      .ag-badge-preempted { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
      
      .ag-tool-name { font-weight: 600; color: var(--dsw-alias-label-primary); }
      .ag-time { font-size: 10px; color: var(--dsw-alias-label-tertiary); }
      .ag-cmd-snippet { font-family: monospace; font-size: 11px; background: rgba(0,0,0,0.1); padding: 4px 6px; border-radius: 4px; margin: 4px 0; word-break: break-all; }
      .ag-event-footer { display: flex; justify-content: space-between; align-items: center; font-size: 10px; color: var(--dsw-alias-label-tertiary); margin-top: 4px; }
      .ag-diff-btn { background: none; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); padding: 2px 6px; border-radius: 4px; cursor: pointer; font-size: 10px; }

      /* Diff Viewer Modal #74, #75 */
      .ag-diff-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 10000; }
      .ag-diff-modal { width: 85%; max-width: 900px; height: 80%; background: var(--dsw-alias-bg-layer-3); border: 1px solid var(--dsw-alias-border-l2); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
      .ag-diff-header { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--dsw-alias-border-l2); }
      .ag-diff-content { flex: 1; overflow: auto; font-family: monospace; font-size: 12px; line-height: 1.5; background: var(--dsw-alias-bg-layer-2); padding: 8px 0; }
      .ag-diff-line { display: flex; padding: 0 8px; }
      .ag-diff-line-add { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
      .ag-diff-line-del { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
      .ag-diff-num { width: 36px; flex: none; text-align: right; padding-right: 8px; color: var(--dsw-alias-label-tertiary); user-select: none; }
      .ag-diff-sign { width: 16px; flex: none; text-align: center; font-weight: bold; user-select: none; }
      .ag-diff-text { flex: 1; white-space: pre-wrap; word-break: break-all; }
      
      /* Hunk Folding #75 */
      .ag-diff-fold { padding: 4px 12px; background: rgba(0,0,0,0.2); border-top: 1px dashed var(--dsw-alias-border-l2); border-bottom: 1px dashed var(--dsw-alias-border-l2); text-align: center; color: var(--dsw-alias-label-secondary); cursor: pointer; font-size: 11px; margin: 4px 0; }
      .ag-diff-fold:hover { background: rgba(0,0,0,0.3); color: var(--dsw-alias-label-primary); }

      /* Countdown Timer #60 */
      .ag-countdown-box { display: flex; align-items: center; gap: 8px; font-size: 11px; color: #eab308; margin-top: 6px; }
      .ag-countdown-badge { background: rgba(234, 179, 8, 0.2); border: 1px solid rgba(234, 179, 8, 0.4); padding: 2px 6px; border-radius: 4px; font-weight: 600; }
      .ag-pause-btn { background: none; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); border-radius: 4px; padding: 1px 6px; cursor: pointer; font-size: 10px; }
    `;

    function injectStyles() {
      if (document.querySelector('style[data-dsh-plugin="dsh-approval-gate"]')) return;
      const s = document.createElement("style");
      s.setAttribute("data-dsh-plugin", "dsh-approval-gate");
      s.textContent = css;
      document.head.appendChild(s);
    }

    // ----------------------------------------------------------- Countdown Component (#60)
    function CountdownBadge({ initialSeconds, onExpire }) {
      const [remaining, setRemaining] = React.useState(initialSeconds || 30);
      const [paused, setPaused] = React.useState(false);

      React.useEffect(() => {
        if (paused || remaining <= 0) return;
        const timer = setInterval(() => {
          setRemaining((prev) => {
            if (prev <= 1) {
              clearInterval(timer);
              if (typeof onExpire === "function") onExpire();
              return 0;
            }
            return prev - 1;
          });
        }, 1000);
        return () => clearInterval(timer);
      }, [paused, remaining, onExpire]);

      return h("div", { className: "ag-countdown-box" },
        h("span", { className: "ag-countdown-badge" },
          paused ? "⏸️ Timer paused" : `⏳ Auto-decision in ${remaining}s`
        ),
        h("button", {
          className: "ag-pause-btn",
          onClick: () => setPaused(!paused),
        }, paused ? "Resume" : "Pause")
      );
    }

    // ----------------------------------------------------------- Diff Panel Modal (#74, #75)
    function DiffPanelModal({ diffData, onClose }) {
      const [expandedFolds, setExpandedFolds] = React.useState({});

      if (!diffData) return null;
      const hunks = diffData.hunks || [];

      const toggleFold = (foldKey) => {
        setExpandedFolds((prev) => ({ ...prev, [foldKey]: !prev[foldKey] }));
      };

      return h("div", { className: "ag-diff-overlay", onClick: onClose },
        h("div", { className: "ag-diff-modal", onClick: (e) => e.stopPropagation() },
          h("div", { className: "ag-diff-header" },
            h("span", { className: "ag-title" }, `Unified Diff: ${diffData.filename || "file"}`),
            h("button", { className: "ag-diff-btn", onClick: onClose }, "✕ Close")
          ),
          h("div", { className: "ag-diff-content" },
            hunks.map((hunk, hIdx) => {
              return h("div", { key: `hunk_${hIdx}` },
                h("div", { className: "ag-diff-fold", style: { cursor: "default", fontWeight: "600" } }, hunk.header),
                (hunk.items || []).map((item, iIdx) => {
                  if (item.type === "fold") {
                    const foldKey = `${hIdx}_${iIdx}`;
                    const isExp = Boolean(expandedFolds[foldKey]);
                    return h("div", { key: foldKey },
                      h("div", {
                        className: "ag-diff-fold",
                        onClick: () => toggleFold(foldKey),
                      }, isExp ? "▴ Collapse unchanged lines" : `▾ Click to expand ${item.count} unchanged lines`),
                      isExp && (item.foldedLines || []).map((fl, fIdx) =>
                        h("div", { key: `fl_${fIdx}`, className: "ag-diff-line" },
                          h("span", { className: "ag-diff-num" }, fl.oldLine || ""),
                          h("span", { className: "ag-diff-num" }, fl.newLine || ""),
                          h("span", { className: "ag-diff-sign" }, " "),
                          h("span", { className: "ag-diff-text" }, fl.text)
                        )
                      )
                    );
                  }

                  const isAdd = item.type === "add";
                  const isDel = item.type === "del";
                  const lineClass = isAdd ? "ag-diff-line ag-diff-line-add" : (isDel ? "ag-diff-line ag-diff-line-del" : "ag-diff-line");
                  const sign = isAdd ? "+" : (isDel ? "-" : " ");

                  return h("div", { key: `line_${hIdx}_${iIdx}`, className: lineClass },
                    h("span", { className: "ag-diff-num" }, item.oldLine || ""),
                    h("span", { className: "ag-diff-num" }, item.newLine || ""),
                    h("span", { className: "ag-diff-sign" }, sign),
                    h("span", { className: "ag-diff-text" }, item.text)
                  );
                })
              );
            })
          )
        )
      );
    }

    // ----------------------------------------------------------- Timeline Tab (#82, #86)
    function ApprovalTimelineTab({ ctx }) {
      const [filter, setFilter] = React.useState("all");
      const [events, setEvents] = React.useState([]);
      const [turnCard, setTurnCard] = React.useState(null);
      const [activeDiff, setActiveDiff] = React.useState(null);

      const fetchTimeline = React.useCallback(async () => {
        try {
          const res = await fetch(`/dsh-approval-gate/timeline?filter=${filter}`);
          if (res.ok) {
            const data = await res.json();
            setEvents(data.events || []);
          }
          const cRes = await fetch("/dsh-approval-gate/turn-card");
          if (cRes.ok) {
            const cData = await cRes.json();
            setTurnCard(cData.card);
          }
        } catch (e) {
          // ignore network poll errors
        }
      }, [filter]);

      React.useEffect(() => {
        fetchTimeline();
        const poll = setInterval(fetchTimeline, 3000);
        return () => clearInterval(poll);
      }, [fetchTimeline]);

      const openDiff = (evt) => {
        if (evt.diffMeta) {
          setActiveDiff(evt.diffMeta);
        } else {
          // Dummy sample diff for inspection demonstration
          setActiveDiff({
            filename: evt.command || "command.sh",
            hunks: [{
              header: "@@ -1,3 +1,4 @@",
              items: [
                { type: "eq", text: "#!/usr/bin/env bash", oldLine: 1, newLine: 1 },
                { type: "del", text: "rm -rf /tmp/data", oldLine: 2, newLine: null },
                { type: "add", text: "trash /tmp/data", oldLine: null, newLine: 2 },
                { type: "fold", count: 8, foldedLines: [
                  { type: "eq", text: "echo 'safe line 1'", oldLine: 3, newLine: 3 },
                  { type: "eq", text: "echo 'safe line 2'", oldLine: 4, newLine: 4 },
                ] },
                { type: "add", text: "echo 'Done safely'", oldLine: null, newLine: 5 },
              ]
            }]
          });
        }
      };

      return h("div", { className: "ag-view-tab" },
        h("div", { className: "ag-header" },
          h("span", { className: "ag-title" }, "🛡️ Security Gate"),
          h("div", { className: "ag-filters" },
            ["all", "blocked", "asked", "allowed"].map((f) =>
              h("button", {
                key: f,
                className: `ag-btn-filter ${filter === f ? "ag-active" : ""}`,
                onClick: () => setFilter(f),
              }, f.charAt(0).toUpperCase() + f.slice(1))
            )
          )
        ),

        // TurnCard Summary (#86)
        turnCard && h("div", { className: "ag-turn-card" },
          h("div", { className: `ag-turn-status ag-${turnCard.status}` },
            turnCard.status === "clean" ? "✓ Turn Clean" : (turnCard.status === "blocked" ? "⚠ Operations Blocked" : "ℹ Confirmations Asked")
          ),
          h("div", { className: "ag-turn-desc" }, turnCard.summaryText)
        ),

        // Events List (#82)
        h("div", { className: "ag-events-list" },
          events.length === 0
            ? h("div", { style: { padding: "20px", textAlign: "center", color: "var(--dsw-alias-label-tertiary)" } }, "No events recorded yet")
            : events.map((evt) => {
              const badgeClass = `ag-badge ag-badge-${evt.verdict}`;
              return h("div", { key: evt.id, className: "ag-event-item" },
                h("div", { className: "ag-event-head" },
                  h("span", { className: "ag-tool-name" }, evt.tool),
                  h("span", { className: badgeClass }, evt.verdict)
                ),
                evt.command && h("div", { className: "ag-cmd-snippet" }, evt.command),
                evt.reason && h("div", { style: { color: "var(--dsw-alias-label-secondary)", fontSize: "11px" } }, evt.reason),
                
                // Countdown Timer for Ask state (#60)
                evt.verdict === "ask" && evt.countdownSec && h(CountdownBadge, { initialSeconds: evt.countdownSec }),

                h("div", { className: "ag-event-footer" },
                  h("span", { className: "ag-time" }, new Date(evt.timestamp).toLocaleTimeString()),
                  h("button", { className: "ag-diff-btn", onClick: () => openDiff(evt) }, "Diff")
                )
              );
            })
        ),

        // Modal Diff Viewer (#74, #75)
        activeDiff && h(DiffPanelModal, { diffData: activeDiff, onClose: () => setActiveDiff(null) })
      );
    }

    // ----------------------------------------------------------- Extension Apply
    function apply(ctx) {
      injectStyles();
      try {
        if (ctx.locale && typeof ctx.locale.register === "function") {
          ctx.locale.register(NS, { en, zh });
        }
      } catch (err) {
        console.warn("[dsh-approval-gate] client locale registration:", err && err.message);
      }

      // Register right session panel slot: conversation.view (#82)
      try {
        if (ctx.slots && typeof ctx.slots.inject === "function") {
          ctx.slots.inject("conversation.view", function () {
            return ctx.slots.register(
              {
                name: "conversation.view",
                id: "@goodandready/dsh-approval-gate",
                order: 45,
                label: function () { return "🛡️ Approvals"; },
              },
              function (props) { return h(ApprovalTimelineTab, { ctx, ...props }); }
            );
          });
        }
      } catch (err) {
        console.warn("[dsh-approval-gate] conversation.view slot registration:", err && err.message);
      }
    }

    module.exports = {
      apply,
      inject: ["slots", "locale"],
      DiffPanelModal,
      CountdownBadge,
      ApprovalTimelineTab,
    };
    return module.exports;
  },
});
