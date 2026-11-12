// lib/client.js — Browser client half for DeepSeek Harness: Approval Gate UI.
// Self-registering CJS factory for window.__ModuleLoader__. Canonical locales: en, zh.

window.__ModuleLoader__.load({
  id: '@goodandready/dsh-approval-gate',
  factory: (require) => {
    var module = { exports: {} };
    const React = require('react');
    const h = React.createElement;
    const NS = 'dsh-approval-gate';
    const PKG = '@goodandready/dsh-approval-gate';
    const CONFIG_EVENT = 'dsh-approval-gate:config-changed';

    // ----------------------------------------------------------- UI primitives
    let ChevronIcon = null;
    try {
      const primitives = require('@deepseek-ai/dsh-client-ui-primitives');
      ChevronIcon = primitives && (primitives.IconChevronDownOutline14 || primitives.IconChevronDownOutline);
    } catch (err) {
      console.warn('[dsh-approval-gate] ui-primitives unavailable, using fallback chevron:', (err && err.message) || err);
    }

    function FallbackChevron({ open }) {
      return h(
        'svg',
        { className: `ag-chev ${open ? 'ag-chev-open' : ''}`, width: 14, height: 14, viewBox: '0 0 14 14', fill: 'none', 'aria-hidden': 'true' },
        h('path', { d: 'M3.5 5.25L7 8.75L10.5 5.25', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round' })
      );
    }

    function Chevron({ open }) {
      if (ChevronIcon) {
        return h('span', { className: `ag-chev ${open ? 'ag-chev-open' : ''}`, 'aria-hidden': 'true' }, h(ChevronIcon, { 'aria-hidden': true }));
      }
      return h(FallbackChevron, { open });
    }

    // ----------------------------------------------------------- localizations
    const en = {
      title: 'Approval Gate', tabTitle: 'Approvals', timelineTitle: 'Session Audit Timeline',
      securityGateTitle: 'Security Gate', filterAll: 'All', filterBlocked: 'Blocked', filterAsked: 'Asked', filterAllowed: 'Allowed',
      noEvents: 'No security gate events in this session yet.', turnClean: 'Turn Clean', turnBlocked: 'Operations Blocked', turnAsked: 'Confirmations Asked',
      viewDiff: 'View Diff', diffBtn: 'Diff', diffModalTitle: 'Unified Diff Preview: {file}',
      diffCollapse: 'Collapse unchanged lines', diffExpand: 'Click to expand {n} unchanged lines', close: 'Close',
      autoTimeoutIn: 'Auto-decision in {s}s', timerPaused: 'Timer paused', pauseTimer: 'Pause', resumeTimer: 'Resume',
      turnSummary: 'Turn Security Summary', settingsTitle: 'Approval Gate',
      settingsSubtitle: 'Configure rules, path whitelists and learned auto-approvals',
      showToolbarBadgeLabel: 'Show toolbar mode badge', showToolbarBadgeDesc: 'Display the active gate mode pill in the top toolbar',
      settingsLoading: 'Loading plugin settings...', settingsUnavailable: 'Host settings service is unavailable.', settingsLoadError: 'Failed to load plugin settings.',
      rulesEditorTitle: 'Rule & Whitelist Editor', whitelistPaths: 'Whitelisted Paths (Skip Confirmation)',
      pathPlaceholder: '/workspace/temp', addPath: 'Add Path', removePath: 'Remove path {path}',
      learnedRulesTitle: 'Learned Auto-Approval Rules', learnedRulesDesc: 'Commands auto-approved in this session after repeated user confirmations.',
      colTool: 'Tool', colCommand: 'Command / Target', colHits: 'Hits', colAction: 'Action',
      revoke: 'Revoke', noLearnedRules: 'No learned rules in this session yet.', toastAutoApproved: 'Auto-approved: {cmd}',
      modeBadgeTitle: 'Approval Gate mode: {mode}', modeStrict: 'Strict', modeHybrid: 'Hybrid', modeAuto: 'Auto', modeManual: 'Manual',
      errorFetch: 'Failed to load data ({detail}).', errorSave: 'Failed to save change ({detail}).', fallbackFile: 'file', fallbackCmd: 'cmd.sh',
    };

    const zh = {
      title: '审批门控', tabTitle: '审批记录', timelineTitle: '会话安全审计时间线',
      securityGateTitle: '安全门控', filterAll: '全部', filterBlocked: '已拦截', filterAsked: '待确认', filterAllowed: '已放行',
      noEvents: '当前会话尚无安全门控事件。', turnClean: '本轮安全通过', turnBlocked: '操作已拦截', turnAsked: '需要确认',
      viewDiff: '查看差异', diffBtn: '差异', diffModalTitle: '统一差异预览：{file}',
      diffCollapse: '收起未变更行', diffExpand: '点击展开 {n} 行未变更代码', close: '关闭',
      autoTimeoutIn: '{s} 秒后自动决策', timerPaused: '倒计时已暂停', pauseTimer: '暂停', resumeTimer: '继续',
      turnSummary: '本轮安全摘要', settingsTitle: '审批门控',
      settingsSubtitle: '配置安全规则、路径白名单及自学习免确认规则',
      showToolbarBadgeLabel: '显示工具栏模式徽章', showToolbarBadgeDesc: '在顶部工具栏显示当前安全门控模式',
      settingsLoading: '正在加载插件设置...', settingsUnavailable: '宿主设置服务当前不可用。', settingsLoadError: '加载插件设置失败。',
      rulesEditorTitle: '规则与白名单编辑器', whitelistPaths: '白名单路径（跳过确认）',
      pathPlaceholder: '/workspace/temp', addPath: '添加路径', removePath: '移除路径 {path}',
      learnedRulesTitle: '已学习的自动放行规则', learnedRulesDesc: '在多次用户确认后，当前会话自动放行的命令规则。',
      colTool: '工具', colCommand: '命令 / 目标', colHits: '次数', colAction: '操作',
      revoke: '撤销', noLearnedRules: '当前会话尚无自动放行规则。', toastAutoApproved: '已自动放行：{cmd}',
      modeBadgeTitle: '审批门控模式：{mode}', modeStrict: '严格模式', modeHybrid: '混合模式', modeAuto: '自动放行', modeManual: '全手动确认',
      errorFetch: '加载数据失败（{detail}）。', errorSave: '保存修改失败（{detail}）。', fallbackFile: '文件', fallbackCmd: 'cmd.sh',
    };

    function formatTemplate(template, vars) {
      if (!vars || typeof template !== 'string') return String(template || '');
      return template.replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined ? String(vars[k]) : m));
    }

    function createTranslator(t, ctx) {
      const bound = typeof t === 'function' ? t : (ctx && ctx.locale && typeof ctx.locale.bind === 'function' ? ctx.locale.bind(NS) : null);
      return (key, vars) => {
        let text = bound ? bound(key, vars) : undefined;
        if (!text || text === key || text === `${NS}.${key}`) text = Object.prototype.hasOwnProperty.call(en, key) ? en[key] : key;
        return formatTemplate(text, vars);
      };
    }

    // ----------------------------------------------------------- CSS Styles
    const css = `
      .ag-view-tab { display: flex; flex-direction: column; height: 100%; padding: 12px; font-family: inherit; color: var(--dsw-alias-label-primary); }
      .ag-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
      .ag-title { font-size: 14px; font-weight: 600; color: var(--dsw-alias-label-primary); }
      .ag-filters { display: flex; gap: 6px; flex-wrap: wrap; }
      .ag-btn-filter { font-size: 11px; padding: 3px 8px; border-radius: 6px; border: 1px solid var(--dsw-alias-border-l2); background: transparent; color: var(--dsw-alias-label-secondary); cursor: pointer; }
      .ag-btn-filter.ag-active { background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font-weight: 600; }
      .ag-turn-card { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-3); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
      .ag-turn-status { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
      .ag-turn-status.ag-clean { color: var(--dsw-alias-state-success-primary); }
      .ag-turn-status.ag-warnings { color: var(--dsw-alias-state-warn-primary); }
      .ag-turn-status.ag-blocked { color: var(--dsw-alias-state-error-primary); }
      .ag-turn-desc { font-size: 11px; color: var(--dsw-alias-label-secondary); }
      .ag-events-list { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; }
      .ag-event-item { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-3); border-radius: 8px; padding: 8px 10px; font-size: 12px; }
      .ag-event-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
      .ag-badge { font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; display: inline-flex; align-items: center; gap: 4px; }
      .ag-badge-allow { background: color-mix(in srgb, var(--dsw-alias-state-success-primary) 15%, transparent); color: var(--dsw-alias-state-success-primary); }
      .ag-badge-deny { background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 15%, transparent); color: var(--dsw-alias-state-error-primary); }
      .ag-badge-ask { background: color-mix(in srgb, var(--dsw-alias-state-warn-primary) 15%, transparent); color: var(--dsw-alias-state-warn-primary); }
      .ag-badge-preempted { background: color-mix(in srgb, var(--dsw-alias-state-brand-primary) 15%, transparent); color: var(--dsw-alias-state-brand-primary); }
      .ag-chip-remove { background: transparent; border: 0; color: inherit; cursor: pointer; font-size: 12px; line-height: 1; padding: 0 2px; opacity: 0.8; }
      .ag-chip-remove:hover { opacity: 1; }
      .ag-tool-name { font-weight: 600; color: var(--dsw-alias-label-primary); }
      .ag-time { font-size: 10px; color: var(--dsw-alias-label-tertiary); }
      .ag-cmd-snippet { font-family: monospace; font-size: 11px; background: color-mix(in srgb, var(--dsw-alias-bg-layer-2) 85%, var(--dsw-alias-bg-layer-3)); padding: 4px 6px; border-radius: 4px; margin: 4px 0; word-break: break-all; }
      .ag-event-footer { display: flex; justify-content: space-between; align-items: center; font-size: 10px; color: var(--dsw-alias-label-tertiary); margin-top: 4px; }
      .ag-diff-btn { background: none; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }
      .ag-error { font-size: 12px; padding: 8px 10px; border-radius: 6px; margin-bottom: 10px; color: var(--dsw-alias-state-error-primary); background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 12%, transparent); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-error-primary) 30%, transparent); }
      .ag-note { font-size: 12px; color: var(--dsw-alias-label-tertiary); margin-bottom: 8px; }
      .ag-toggle-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--dsw-alias-border-l2); margin-bottom: 8px; cursor: pointer; }
      .ag-diff-overlay { position: fixed; inset: 0; background: color-mix(in srgb, var(--dsw-alias-bg-layer-1) 70%, transparent); backdrop-filter: blur(2px); display: flex; align-items: center; justify-content: center; z-index: 10000; }
      .ag-diff-modal { width: 85%; max-width: 900px; height: 80%; background: var(--dsw-alias-bg-layer-3); border: 1px solid var(--dsw-alias-border-l2); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 8px 32px color-mix(in srgb, var(--dsw-alias-label-primary) 20%, transparent); }
      .ag-diff-header { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--dsw-alias-border-l2); }
      .ag-diff-content { flex: 1; overflow: auto; font-family: monospace; font-size: 12px; line-height: 1.5; background: var(--dsw-alias-bg-layer-2); padding: 8px 0; }
      .ag-diff-line { display: flex; padding: 0 8px; }
      .ag-diff-line-add { background: color-mix(in srgb, var(--dsw-alias-state-success-primary) 15%, transparent); color: var(--dsw-alias-state-success-primary); }
      .ag-diff-line-del { background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 15%, transparent); color: var(--dsw-alias-state-error-primary); }
      .ag-diff-num { width: 36px; flex: none; text-align: right; padding-right: 8px; color: var(--dsw-alias-label-tertiary); user-select: none; }
      .ag-diff-sign { width: 16px; flex: none; text-align: center; font-weight: bold; user-select: none; }
      .ag-diff-text { flex: 1; white-space: pre-wrap; word-break: break-all; }
      .ag-diff-fold { padding: 4px 12px; background: color-mix(in srgb, var(--dsw-alias-bg-layer-3) 75%, transparent); border-top: 1px dashed var(--dsw-alias-border-l2); border-bottom: 1px dashed var(--dsw-alias-border-l2); text-align: center; color: var(--dsw-alias-label-secondary); cursor: pointer; font-size: 11px; margin: 4px 0; }
      .ag-diff-fold:hover { background: var(--dsw-alias-bg-layer-3); color: var(--dsw-alias-label-primary); }
      .ag-countdown-box { display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--dsw-alias-state-warn-primary); margin-top: 6px; }
      .ag-countdown-badge { background: color-mix(in srgb, var(--dsw-alias-state-warn-primary) 18%, transparent); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-warn-primary) 40%, transparent); padding: 2px 6px; border-radius: 4px; font-weight: 600; }
      .ag-pause-btn { background: none; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); border-radius: 4px; padding: 1px 6px; cursor: pointer; font-size: 10px; }
      .ag-card { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-3); border-radius: 12px; list-style: none; margin-bottom: 12px; }
      .ag-card-head { appearance: none; width: 100%; font: inherit; color: inherit; text-align: left; cursor: pointer; background: 0 0; border: 0; border-radius: 12px; display: flex; align-items: center; gap: 12px; padding: 14px 16px; }
      .ag-card-title { color: var(--dsw-alias-label-primary); font-size: 15px; font-weight: 600; line-height: 1.4; }
      .ag-card-sub { color: var(--dsw-alias-label-secondary); font-size: 13px; }
      .ag-card-body { border-top: 1px solid var(--dsw-alias-border-l2); margin: 0 16px; padding: 12px 0 16px; }
      .ag-chev { margin-left: auto; flex: none; display: inline-flex; align-items: center; color: var(--dsw-alias-label-tertiary); transition: transform .16s; }
      .ag-chev-open { transform: rotate(180deg); }
      .ag-sec-title { font-size: 13px; font-weight: 600; color: var(--dsw-alias-label-primary); margin: 12px 0 6px; }
      .ag-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 6px; }
      .ag-table th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); font-weight: 500; }
      .ag-table td { padding: 6px 8px; border-bottom: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-primary); }
      .ag-btn-revoke { background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 15%, transparent); color: var(--dsw-alias-state-error-primary); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-error-primary) 30%, transparent); border-radius: 4px; padding: 2px 8px; cursor: pointer; font-size: 11px; }
      .ag-input { height: 30px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 6px; padding: 0 8px; font-size: 12px; }
      .ag-toast { position: fixed; bottom: 80px; left: 50%; transform: translateX(-50%); background: var(--dsw-alias-bg-layer-3); border: 1px solid var(--dsw-alias-state-success-primary); color: var(--dsw-alias-label-primary); border-radius: 20px; padding: 6px 14px; font-size: 12px; display: flex; align-items: center; gap: 6px; box-shadow: 0 4px 16px color-mix(in srgb, var(--dsw-alias-label-primary) 18%, transparent); z-index: 9999; animation: agFade .2s ease-in; }
      @keyframes agFade { from { opacity: 0; transform: translate(-50%, 8px); } to { opacity: 1; transform: translate(-50%, 0); } }
      .ag-mode-badge { font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 10px; text-transform: uppercase; letter-spacing: 0.5px; cursor: default; }
      .ag-mode-auto { background: color-mix(in srgb, var(--dsw-alias-state-success-primary) 18%, transparent); color: var(--dsw-alias-state-success-primary); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-success-primary) 40%, transparent); }
      .ag-mode-hybrid { background: color-mix(in srgb, var(--dsw-alias-state-warn-primary) 18%, transparent); color: var(--dsw-alias-state-warn-primary); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-warn-primary) 40%, transparent); }
      .ag-mode-strict { background: color-mix(in srgb, var(--dsw-alias-state-brand-primary) 18%, transparent); color: var(--dsw-alias-state-brand-primary); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-brand-primary) 40%, transparent); }
      .ag-mode-manual { background: color-mix(in srgb, var(--dsw-alias-label-secondary) 18%, transparent); color: var(--dsw-alias-label-secondary); border: 1px solid color-mix(in srgb, var(--dsw-alias-label-secondary) 40%, transparent); }
    `;

    function injectStyles() {
      if (typeof document === 'undefined' || !document.head) return;
      if (document.querySelector(`style[data-dsh-plugin="${NS}"]`)) return;
      const s = document.createElement('style');
      s.setAttribute('data-dsh-plugin', NS);
      s.textContent = css;
      document.head.appendChild(s);
    }

    function getConfigScope(ctx) {
      const forms = (ctx && typeof ctx.get === 'function' ? ctx.get('configForms') : null) || (ctx && ctx.configForms) || (ctx && ctx.services && ctx.services.configForms);
      return forms && typeof forms.get === 'function' ? forms.get(NS) : null;
    }

    function useSettingsSnapshot(scope) {
      return React.useSyncExternalStore(
        React.useMemo(() => (scope && scope.subscribe ? (cb) => scope.subscribe(cb) : () => () => {}), [scope]),
        React.useCallback(() => (scope && scope.getSnapshot ? scope.getSnapshot() : { status: 'loading' }), [scope]),
        React.useCallback(() => ({ status: 'loading' }), [])
      );
    }

    class ErrorBoundary extends React.Component {
      constructor(props) { super(props); this.state = { failed: false }; }
      static getDerivedStateFromError() { return { failed: true }; }
      componentDidCatch(err) { console.warn('[dsh-approval-gate] UI boundary caught error:', (err && err.message) || err); }
      render() { return this.state.failed ? null : this.props.children; }
    }

    // ----------------------------------------------------------- Countdown
    function CountdownBadge({ initialSeconds, onExpire, t, ctx }) {
      const tr = createTranslator(t, ctx);
      const [remaining, setRemaining] = React.useState(initialSeconds || 30);
      const [paused, setPaused] = React.useState(false);
      React.useEffect(() => {
        if (paused || remaining <= 0) return undefined;
        const timer = setInterval(() => {
          setRemaining((prev) => {
            if (prev <= 1) { clearInterval(timer); if (typeof onExpire === 'function') onExpire(); return 0; }
            return prev - 1;
          });
        }, 1000);
        return () => clearInterval(timer);
      }, [paused, remaining, onExpire]);
      return h('div', { className: 'ag-countdown-box' },
        h('span', { className: 'ag-countdown-badge' }, paused ? `⏸ ${tr('timerPaused')}` : `⏳ ${tr('autoTimeoutIn', { s: remaining })}`),
        h('button', { type: 'button', className: 'ag-pause-btn', onClick: () => setPaused(!paused) }, paused ? tr('resumeTimer') : tr('pauseTimer'))
      );
    }

    // ----------------------------------------------------------- Floating Toast
    function AutoApprovalToast({ message, onDismiss, t, ctx }) {
      const tr = createTranslator(t, ctx);
      React.useEffect(() => {
        const timer = setTimeout(() => { if (onDismiss) onDismiss(); }, 3000);
        return () => clearTimeout(timer);
      }, [onDismiss]);
      if (!message) return null;
      return h('div', { className: 'ag-toast', onClick: onDismiss }, h('span', null, `⚡ ${tr('toastAutoApproved', { cmd: message })}`));
    }

    // ----------------------------------------------------------- Gate Mode Badge
    function GateModeBadge({ t, ctx }) {
      const tr = createTranslator(t, ctx);
      const [mode, setMode] = React.useState('hybrid');
      const [visible, setVisible] = React.useState(true);
      React.useEffect(() => {
        let active = true;
        fetch('/dsh-approval-gate/mode')
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
          .then((d) => {
            if (!active || !d) return;
            if (d.mode) setMode(d.mode);
            if (typeof d.showToolbarBadge === 'boolean') setVisible(d.showToolbarBadge);
          })
          .catch((err) => { console.warn('[dsh-approval-gate] mode fetch error:', (err && err.message) || err); });
        const onConfigChanged = (ev) => {
          if (ev && ev.detail && typeof ev.detail.showToolbarBadge === 'boolean') setVisible(ev.detail.showToolbarBadge);
        };
        if (typeof window !== 'undefined' && window.addEventListener) window.addEventListener(CONFIG_EVENT, onConfigChanged);
        return () => {
          active = false;
          if (typeof window !== 'undefined' && window.removeEventListener) window.removeEventListener(CONFIG_EVENT, onConfigChanged);
        };
      }, []);
      if (!visible) return null;
      const modeKeys = { strict: 'modeStrict', hybrid: 'modeHybrid', auto: 'modeAuto', manual: 'modeManual' };
      const modeLabel = tr(modeKeys[mode] || 'modeHybrid');
      return h('span', { className: `ag-mode-badge ag-mode-${mode}`, title: tr('modeBadgeTitle', { mode: modeLabel }) }, `🛡 ${modeLabel}`);
    }

    // ----------------------------------------------------------- Diff Panel Modal
    function DiffPanelModal({ diffData, onClose, t, ctx }) {
      const tr = createTranslator(t, ctx);
      const [expandedFolds, setExpandedFolds] = React.useState({});
      if (!diffData) return null;
      const hunks = diffData.hunks || [];
      const toggleFold = (foldKey) => setExpandedFolds((prev) => ({ ...prev, [foldKey]: !prev[foldKey] }));
      return h('div', { className: 'ag-diff-overlay', onClick: onClose },
        h('div', { className: 'ag-diff-modal', onClick: (e) => e.stopPropagation() },
          h('div', { className: 'ag-diff-header' },
            h('span', { className: 'ag-title' }, tr('diffModalTitle', { file: diffData.filename || tr('fallbackFile') })),
            h('button', { type: 'button', className: 'ag-diff-btn', onClick: onClose }, `✕ ${tr('close')}`)
          ),
          h('div', { className: 'ag-diff-content' },
            hunks.map((hunk, hIdx) =>
              h('div', { key: `hunk_${hIdx}` },
                h('div', { className: 'ag-diff-fold', style: { cursor: 'default', fontWeight: '600' } }, hunk.header),
                (hunk.items || []).map((item, iIdx) => {
                  if (item.type === 'fold') {
                    const foldKey = `${hIdx}_${iIdx}`;
                    const isExp = Boolean(expandedFolds[foldKey]);
                    return h('div', { key: foldKey },
                      h('div', { className: 'ag-diff-fold', onClick: () => toggleFold(foldKey) }, isExp ? `▴ ${tr('diffCollapse')}` : `▾ ${tr('diffExpand', { n: item.count })}`),
                      isExp && (item.foldedLines || []).map((fl, fIdx) =>
                        h('div', { key: `fl_${fIdx}`, className: 'ag-diff-line' },
                          h('span', { className: 'ag-diff-num' }, fl.oldLine || ''), h('span', { className: 'ag-diff-num' }, fl.newLine || ''),
                          h('span', { className: 'ag-diff-sign' }, ' '), h('span', { className: 'ag-diff-text' }, fl.content)
                        )
                      )
                    );
                  }
                  const cls = item.type === 'add' ? 'ag-diff-line ag-diff-line-add' : item.type === 'del' ? 'ag-diff-line ag-diff-line-del' : 'ag-diff-line';
                  const sign = item.type === 'add' ? '+' : item.type === 'del' ? '-' : ' ';
                  return h('div', { key: `line_${iIdx}`, className: cls },
                    h('span', { className: 'ag-diff-num' }, item.oldLine || ''), h('span', { className: 'ag-diff-num' }, item.newLine || ''),
                    h('span', { className: 'ag-diff-sign' }, sign), h('span', { className: 'ag-diff-text' }, item.content)
                  );
                })
              )
            )
          )
        )
      );
    }

    // ----------------------------------------------------------- Settings Card Component
    function ApprovalGateSettingsCard({ ctx, t, view }) {
      const tr = createTranslator(t, ctx);
      const isSummary = view === 'summary';
      const isPage = view === 'page';
      const [open, setOpen] = React.useState(isPage);
      const [learnedRules, setLearnedRules] = React.useState([]);
      const [whitelist, setWhitelist] = React.useState([]);
      const [newPath, setNewPath] = React.useState('');
      const [errorMsg, setErrorMsg] = React.useState('');
      const scope = React.useMemo(() => getConfigScope(ctx), [ctx]);
      const snapshot = useSettingsSnapshot(scope);
      const cfgStatus = (snapshot && snapshot.status) || 'loading';
      const showBadge = snapshot && snapshot.value && typeof snapshot.value.showToolbarBadge === 'boolean' ? snapshot.value.showToolbarBadge : true;

      const reportErr = (prefix, key, err) => {
        const detail = (err && err.message) || String(err);
        console.warn(`[dsh-approval-gate] ${prefix}:`, detail);
        setErrorMsg(tr(key, { detail }));
      };

      const fetchSettings = React.useCallback(async () => {
        try {
          setErrorMsg('');
          const [lrRes, rRes] = await Promise.all([fetch('/dsh-approval-gate/learned-rules'), fetch('/dsh-approval-gate/rules')]);
          if (!lrRes.ok) throw new Error(`HTTP ${lrRes.status}`);
          if (!rRes.ok) throw new Error(`HTTP ${rRes.status}`);
          const [lrData, rData] = await Promise.all([lrRes.json(), rRes.json()]);
          setLearnedRules(lrData.rules || []);
          setWhitelist(rData.whitelistPaths || []);
        } catch (err) {
          reportErr('settings fetch error', 'errorFetch', err);
        }
      }, []);

      React.useEffect(() => { if (!isSummary && open) fetchSettings(); }, [isSummary, open, fetchSettings]);

      const saveWhitelist = async (nextList, prevList) => {
        setWhitelist(nextList);
        setErrorMsg('');
        try {
          const res = await fetch('/dsh-approval-gate/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ whitelistPaths: nextList }) });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
        } catch (err) {
          setWhitelist(prevList);
          reportErr('save rules error', 'errorSave', err);
        }
      };

      const addPath = () => {
        const trimmed = newPath.trim();
        if (!trimmed) return;
        setNewPath('');
        saveWhitelist([...whitelist, trimmed], whitelist);
      };

      const revokeRule = async (key) => {
        const prev = learnedRules;
        setLearnedRules((list) => list.filter((r) => r.key !== key));
        setErrorMsg('');
        try {
          const res = await fetch('/dsh-approval-gate/learned-rules/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key }) });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
        } catch (err) {
          setLearnedRules(prev);
          reportErr('revoke rule error', 'errorSave', err);
        }
      };

      const toggleToolbarBadge = async (checked) => {
        if (!scope || typeof scope.set !== 'function') return;
        setErrorMsg('');
        try {
          await scope.set('showToolbarBadge', checked);
          if (typeof window !== 'undefined' && window.dispatchEvent) window.dispatchEvent(new CustomEvent(CONFIG_EVENT, { detail: { showToolbarBadge: checked } }));
        } catch (err) {
          reportErr('configForms set error', 'errorSave', err);
        }
      };

      const renderConfigToggle = () => {
        if (!scope) return h('div', { className: 'ag-note' }, tr('settingsUnavailable'));
        if (cfgStatus === 'loading') return h('div', { className: 'ag-note' }, tr('settingsLoading'));
        if (cfgStatus === 'error') return h('div', { className: 'ag-error' }, tr('settingsLoadError'));
        return h('label', { className: 'ag-toggle-row' },
          h('div', null, h('div', { className: 'ag-sec-title', style: { margin: 0 } }, tr('showToolbarBadgeLabel')), h('div', { className: 'ag-card-sub', style: { fontSize: '12px' } }, tr('showToolbarBadgeDesc'))),
          h('input', { type: 'checkbox', checked: showBadge, onChange: (e) => toggleToolbarBadge(Boolean(e.target.checked)) })
        );
      };

      if (isSummary) {
        return h('span', { className: 'ag-card-sub' }, tr('settingsSubtitle'));
      }
      return h(ErrorBoundary, null,
        h('div', { className: 'ag-card', 'data-dsh-plugin': NS },
          h('button', { type: 'button', className: 'ag-card-head', onClick: () => setOpen(!open), 'aria-expanded': open },
            h('div', null, h('div', { className: 'ag-card-title' }, `🛡 ${tr('settingsTitle')}`), h('div', { className: 'ag-card-sub' }, tr('settingsSubtitle'))),
            h(Chevron, { open })
          ),
          open && h('div', { className: 'ag-card-body' },
            errorMsg && h('div', { className: 'ag-error', role: 'alert' }, errorMsg),
            renderConfigToggle(),
            h('div', { className: 'ag-sec-title' }, tr('whitelistPaths')),
            h('div', { style: { display: 'flex', gap: '6px', marginBottom: '8px' } },
              h('input', { className: 'ag-input', placeholder: tr('pathPlaceholder'), value: newPath, style: { flex: 1 }, onChange: (e) => setNewPath(e.target.value), onKeyDown: (e) => { if (e.key === 'Enter') addPath(); } }),
              h('button', { type: 'button', className: 'ag-diff-btn', onClick: addPath }, `+ ${tr('addPath')}`)
            ),
            whitelist.length > 0 && h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '12px' } },
              whitelist.map((p, idx) =>
                h('span', { key: `${p}_${idx}`, className: 'ag-badge ag-badge-allow' },
                  h('span', null, p),
                  h('button', { type: 'button', className: 'ag-chip-remove', 'aria-label': tr('removePath', { path: p }), onClick: () => saveWhitelist(whitelist.filter((_, i) => i !== idx), whitelist) }, '×')
                )
              )
            ),
            h('div', { className: 'ag-sec-title' }, tr('learnedRulesTitle')),
            h('div', { className: 'ag-note' }, tr('learnedRulesDesc')),
            learnedRules.length === 0
              ? h('div', { className: 'ag-note' }, tr('noLearnedRules'))
              : h('table', { className: 'ag-table' },
                  h('thead', null, h('tr', null, h('th', null, tr('colTool')), h('th', null, tr('colCommand')), h('th', null, tr('colHits')), h('th', null, tr('colAction')))),
                  h('tbody', null, learnedRules.map((rule) =>
                    h('tr', { key: rule.key },
                      h('td', null, rule.tool || 'bash'),
                      h('td', { style: { fontFamily: 'monospace' } }, rule.command || rule.key),
                      h('td', null, rule.count || 1),
                      h('td', null, h('button', { type: 'button', className: 'ag-btn-revoke', onClick: () => revokeRule(rule.key) }, tr('revoke')))
                    )
                  ))
                )
          )
        )
      );
    }

    // ----------------------------------------------------------- Timeline Tab
    function ApprovalTimelineTab({ ctx, t }) {
      const tr = createTranslator(t, ctx);
      const [filter, setFilter] = React.useState('all');
      const [events, setEvents] = React.useState([]);
      const [turnCard, setTurnCard] = React.useState(null);
      const [activeDiff, setActiveDiff] = React.useState(null);
      const [errorMsg, setErrorMsg] = React.useState('');

      const fetchTimeline = React.useCallback(async () => {
        try {
          const [res, cRes] = await Promise.all([fetch(`/dsh-approval-gate/timeline?filter=${filter}`), fetch('/dsh-approval-gate/turn-card')]);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          if (!cRes.ok) throw new Error(`HTTP ${cRes.status}`);
          const [data, cData] = await Promise.all([res.json(), cRes.json()]);
          setEvents(data.events || []);
          setTurnCard(cData.card);
          setErrorMsg('');
        } catch (err) {
          const detail = (err && err.message) || String(err);
          console.warn('[dsh-approval-gate] timeline fetch error:', detail);
          setErrorMsg(tr('errorFetch', { detail }));
        }
      }, [filter]);

      React.useEffect(() => {
        fetchTimeline();
        const poll = setInterval(fetchTimeline, 3000);
        return () => clearInterval(poll);
      }, [fetchTimeline]);

      const filterMeta = [
        { id: 'all', key: 'filterAll' },
        { id: 'blocked', key: 'filterBlocked' },
        { id: 'asked', key: 'filterAsked' },
        { id: 'allowed', key: 'filterAllowed' },
      ];

      return h(ErrorBoundary, null,
        h('div', { className: 'ag-view-tab', 'data-dsh-plugin': NS },
          h('div', { className: 'ag-header' },
            h('span', { className: 'ag-title' }, `🛡 ${tr('securityGateTitle')}`),
            h('div', { className: 'ag-filters' }, filterMeta.map((f) =>
              h('button', { type: 'button', key: f.id, className: `ag-btn-filter ${filter === f.id ? 'ag-active' : ''}`, onClick: () => setFilter(f.id) }, tr(f.key))
            ))
          ),
          errorMsg && h('div', { className: 'ag-error', role: 'alert' }, errorMsg),
          turnCard && h('div', { className: 'ag-turn-card' },
            h('div', { className: `ag-turn-status ag-${turnCard.status}` },
              turnCard.status === 'clean' ? `✓ ${tr('turnClean')}` : turnCard.status === 'blocked' ? `⚠ ${tr('turnBlocked')}` : `ℹ ${tr('turnAsked')}`
            ),
            h('div', { className: 'ag-turn-desc' }, turnCard.summaryText)
          ),
          h('div', { className: 'ag-events-list' },
            events.length === 0
              ? h('div', { className: 'ag-note', style: { padding: '20px', textAlign: 'center' } }, tr('noEvents'))
              : events.map((evt) =>
                  h('div', { key: evt.id, className: 'ag-event-item' },
                    h('div', { className: 'ag-event-head' },
                      h('span', { className: 'ag-tool-name' }, evt.tool),
                      h('span', { className: `ag-badge ag-badge-${evt.verdict}` }, evt.verdict)
                    ),
                    evt.command && h('div', { className: 'ag-cmd-snippet' }, evt.command),
                    evt.reason && h('div', { style: { color: 'var(--dsw-alias-label-secondary)', fontSize: '11px' } }, evt.reason),
                    evt.verdict === 'ask' && evt.countdownSec && h(CountdownBadge, { initialSeconds: evt.countdownSec, t, ctx }),
                    h('div', { className: 'ag-event-footer' },
                      h('span', { className: 'ag-time' }, new Date(evt.timestamp).toLocaleTimeString()),
                      h('button', { type: 'button', className: 'ag-diff-btn', onClick: () => setActiveDiff(evt.diffMeta || { filename: evt.command || tr('fallbackCmd'), hunks: [] }) }, tr('diffBtn'))
                    )
                  )
                )
          ),
          activeDiff && h(DiffPanelModal, { diffData: activeDiff, onClose: () => setActiveDiff(null), t, ctx })
        )
      );
    }

    // ----------------------------------------------------------- Extension Apply
    function apply(ctx) {
      injectStyles();
      const registerLocale = () => {
        try {
          if (ctx.locale && typeof ctx.locale.register === 'function') return ctx.locale.register(NS, { en, zh });
        } catch (err) {
          console.warn('[dsh-approval-gate] client locale registration:', (err && err.message) || err);
        }
        return undefined;
      };
      if (typeof ctx.effect === 'function') ctx.effect(registerLocale, 'dsh-approval-gate: dictionaries');
      else registerLocale();

      const boundT = ctx.locale && typeof ctx.locale.bind === 'function' ? ctx.locale.bind(NS) : null;
      const tr = createTranslator(boundT, ctx);
      const safeInject = (slotName, fn) => {
        try {
          if (ctx.slots && typeof ctx.slots.inject === 'function') ctx.slots.inject(slotName, fn);
        } catch (err) {
          console.warn(`[dsh-approval-gate] ${slotName} slot registration:`, (err && err.message) || err);
        }
      };

      safeInject('conversation.view', () =>
        ctx.slots.register({ name: 'conversation.view', id: PKG, order: 45, label: () => `🛡 ${tr('tabTitle')}` }, (props) => h(ApprovalTimelineTab, { ctx, t: boundT, ...props }))
      );
      safeInject('plugins.item', () =>
        ctx.slots.register({ name: 'plugins.item', id: PKG, key: PKG, order: 45, label: () => tr('settingsTitle'), locale: NS, inject: () => ({ ctx }) }, ApprovalGateSettingsCard)
      );
      safeInject('plugins.row.config', () =>
        ctx.slots.register({ name: 'plugins.row.config', key: `${PKG}#${NS}`, locale: NS, inject: () => ({ ctx }) }, ApprovalGateSettingsCard)
      );
      safeInject('conversation.session.header.utilities', () =>
        ctx.slots.register({ name: 'conversation.session.header.utilities', id: `${PKG}:mode-badge`, order: 25, locale: NS, inject: () => ({ ctx }) }, (props) => h(GateModeBadge, { ctx, t: boundT, ...props }))
      );
    }

    module.exports = { apply, inject: ['slots', 'locale'], en, zh, DiffPanelModal, CountdownBadge, ApprovalTimelineTab, ApprovalGateSettingsCard, AutoApprovalToast, GateModeBadge };
    return module.exports;
  },
});
