// terminal.js — extracted from terminal.html
// All Jinja2 variables are passed via window.PAGE_DATA (set inline in the template).
const { cluster, requestName, namespaces, namespace: initialNs } = window.PAGE_DATA;

    lucide.createIcons();

    // ── Constants ──
    let   activeNs    = namespaces[0] || initialNs;
    const WS_URL      = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/terminal/${cluster}/${requestName}`;

    // Declared early to avoid TDZ errors if loadPods() is called before
    // the pod-list section of the script is reached (e.g. via a resolved Promise).
    let knownPods      = new Set();
    let refreshInterval = null;

    function _applyNsTabStyle(ns) {
      document.querySelectorAll('.ns-tab').forEach(btn => {
        const active = btn.dataset.ns === ns;
        btn.style.background  = active ? 'rgba(99,102,241,0.15)' : 'var(--surface-2)';
        btn.style.borderColor = active ? 'var(--accent)'         : 'var(--border)';
        btn.style.color       = active ? '#a5b4fc'               : 'var(--text-dim)';
        btn.style.fontWeight  = active ? '600'                   : '400';
      });
    }

    function switchNamespace(ns) {
      activeNs = ns;
      _applyNsTabStyle(ns);
      // Reset pod selection only when panes are already initialised
      if (typeof paneA !== 'undefined' && paneA) {
        paneA.currentPod = null;
        paneA.podLabel.textContent = 'No pod selected';
        if (paneB) { paneB.currentPod = null; paneB.podLabel.textContent = 'No pod selected'; }
      }
      loadPods();
    }

    // ── Utilities ──
    function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

    function showBanner(type, html, autoDismissMs) {
      const div = document.createElement('div');
      div.className = `banner banner-${type}`;
      div.innerHTML = `<span style="flex:1;">${html}</span><button class="banner-close" onclick="this.parentElement.remove()">✕</button>`;
      document.getElementById('banners').appendChild(div);
      if (autoDismissMs) setTimeout(() => div.remove(), autoDismissMs);
    }

    // ── Expiry countdown ──
    (function() {
      const el = document.getElementById('terminal-countdown');
      if (!el) return;
      const expires = new Date(el.dataset.expires);
      function tick() {
        const diff = Math.floor((expires - Date.now()) / 1000);
        if (diff <= 0) { el.textContent = 'Expired'; el.style.color = 'var(--danger)'; return; }
        const h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60), s = diff % 60;
        el.textContent = h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
        el.style.color = diff < 300 ? 'var(--danger)' : diff < 900 ? 'var(--warning)' : 'var(--success)';
        setTimeout(tick, 1000);
      }
      tick();
      // Re-sync expiry time from server every 30s to prevent clock drift
      setInterval(async () => {
        try {
          const d = await fetch(`/api/status/${cluster}/${requestName}`).then(r => r.json());
          const ea = d?.status?.expiresAt;
          if (ea) { expires.setTime(new Date(ea).getTime()); }
        } catch(_) {}
      }, 30000);
    })();

    // ========================================================================
    // ========================================================================
    // Terminal capture helpers
    // ========================================================================

    // Returns the active pane (whichever has focus)
    function _activePane() {
      return (activePaneId === 'b' && paneB) ? paneB : paneA;
    }

    // Copy full terminal buffer as plain text to clipboard
    function copyTerminalOutput() {
      const pane = _activePane();
      if (!pane || !pane.term) {
        if (typeof showToast === 'function') showToast('No terminal active', 'warning');
        return;
      }
      const buf = pane.term.buffer.active;
      const lines = [];
      for (let i = 0; i < buf.length; i++) {
        lines.push(buf.getLine(i).translateToString(true));
      }
      // Strip trailing blank lines
      while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
      const text = lines.join('\n');
      navigator.clipboard.writeText(text).then(() => {
        if (typeof showToast === 'function') showToast('Output copied to clipboard', 'success', 2500);
      }).catch(() => {
        if (typeof showToast === 'function') showToast('Clipboard access denied', 'error');
      });
    }


    // ========================================================================
    // TermPane — one terminal pane (xterm + websocket + tabs)
    // ========================================================================
    class TermPane {
      constructor(id) {
        this.id        = id;       // 'a' or 'b'
        this.term      = null;
        this.fitAddon  = null;
        this.ws        = null;
        this.currentPod = null;
        this.shellActive = false;  // true only when a shell is confirmed connected
        this.noShellPods = new Set();
        this._reconnectTimer = null;
        this._activityTimer  = null;
        this._opening = false;
        this._destroyed = false;

        // DOM refs
        this.el         = document.getElementById(`pane-${id}`);
        this.podLabel   = document.getElementById(`pane-${id}-pod`);
        this.statusDot  = document.getElementById(`pane-${id}-dot`);
        this.statusText = document.getElementById(`pane-${id}-status`);
        this.tabBar     = document.getElementById(`pane-${id}-tabs`);
        this.termEl     = document.getElementById(`pane-${id}-term`);

        this._openWS();
        this.el.addEventListener('click', () => setActivePane(this.id), { capture: true });
      }

      // ── WebSocket ──
      _openWS() {
        if (this._opening) return;
        this._opening = true;
        this._retryCount = this._retryCount || 0;
        this.ws = new WebSocket(WS_URL);
        this.ws.onopen  = () => {
          this._opening = false;
          this._retryCount = 0;
          this._startHeartbeat();
          if (this._pendingPodMsg) {
            this.ws.send(this._pendingPodMsg);
            this._pendingPodMsg = null;
          } else if (this.currentPod) {
            // Reconnect after disconnect — clear stale no-shell cache so the pod
            // gets a fresh probe (previous failure may have been transient pressure)
            this.noShellPods.delete(this.currentPod);
            this.ws.send(JSON.stringify({type: 'select_pod', pod: this.currentPod, namespace: activeNs}));
          }
        };
        this.ws.onclose = () => {
          this._opening = false;
          this.shellActive = false;
          if (this._destroyed) return;  // intentional close — no reconnect
          if (this.id === activePaneId) setQuickCmdsEnabled(false);
          this._setStatus(false, 'Disconnected');
          if (this.term) this.term.write('\r\n\x1b[31mSession closed\x1b[0m\r\n');
          this._retryCount++;
          if (this._retryCount > 10) {
            this._setStatus(false, 'Reconnect failed');
            if (this.term) this.term.write('\r\n\x1b[31mConnection lost — max retries exceeded.\x1b[0m\r\n');
            showBanner('error', '🔌 Connection lost — <a href="" onclick="location.reload();return false;" style="color:#fca5a5;text-decoration:underline;">Reload page</a>', 0);
            return;
          }
          const delay = Math.min(2000 * Math.pow(1.5, this._retryCount - 1), 30000);
          showBanner('warning', `⟳ Reconnecting… (${this._retryCount}/10)`, Math.min(delay + 500, 5000));
          this._reconnectTimer = setTimeout(() => this._openWS(), delay);
        };
        this.ws.onerror = () => {
          if (this.term) this.term.write('\r\n\x1b[31mConnection error\x1b[0m\r\n');
        };
        this.ws.onmessage = (ev) => this._onMessage(ev);
      }

      _onMessage(ev) {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === 'connected') {
            this.shellActive = true;
            this._setStatus(true, 'Connected');
            this.podLabel.textContent = `Connected to: ${msg.pod}`;
            document.getElementById(`pane-${this.id}-disconnect`).style.display = 'inline-block';
            if (this.id === activePaneId) setQuickCmdsEnabled(true);
            return;
          }
          if (msg.type === 'no_shell') {
            this.shellActive = false;
            this.noShellPods.add(msg.pod);
            this._setStatus(false, 'No shell');
            if (this.id === activePaneId) setQuickCmdsEnabled(false);
            this.switchTab('logs');
            this.loadLogs(msg.pod);
            return;
          }
          if (msg.type === 'pod_error') {
            this.shellActive = false;
            this._setStatus(false, msg.status === '404' ? 'Not found' : 'Access denied');
            this.podLabel.textContent = msg.status === '404'
              ? `${msg.pod} — no longer exists`
              : `${msg.pod} — access denied`;
            if (this.id === activePaneId) setQuickCmdsEnabled(false);
            // Show error in the terminal pane rather than switching to logs (which also fails)
            this.switchTab('terminal');
            if (this.term) this.term.write(`\r\n\x1b[31m${msg.message}\x1b[0m\r\n`);
            return;
          }
          if (msg.type === 'idle_warning') {
            const m = Math.ceil(msg.seconds_left / 60);
            showBanner('warning', `<strong>⏰ Idle warning:</strong> Session closes in ~${m}min due to inactivity.`, 30000);
            return;
          }
          if (msg.type === 'idle_timeout') {
            showBanner('danger', `<strong>🔒 Session expired</strong> — auto-revoked. <a href="/" style="color:inherit;text-decoration:underline;">Dashboard</a>`);
            setQuickCmdsEnabled(false);
            return;
          }
          if (msg.type === 'broadcast') {
            showBanner('info', `<strong>📣 ${escapeHtml(msg.from || 'Admin')}:</strong> ${escapeHtml(msg.message)}`, 60000);
            return;
          }
          if (msg.type === 'revoked') {
            const by = msg.revoked_by ? ` by ${escapeHtml(msg.revoked_by)}` : '';
            showBanner('danger', `<strong>🚫 Access revoked${by}</strong> — your session has been terminated. <a href="/status/${cluster}/${requestName}" style="color:inherit;text-decoration:underline;">View status</a>`);
            setQuickCmdsEnabled(false);
            setTimeout(() => { window.location.href = `/status/${cluster}/${requestName}`; }, 4000);
            return;
          }
          if (msg.type === 'expired') {
            this._retryCount = 999; // stop reconnect loop
            this._setStatus(false, 'Expired');
            showBanner('danger', `<strong>🔒 Access expired</strong> — your session is no longer active. <a href="/status/${cluster}/${requestName}" style="color:inherit;text-decoration:underline;">View status</a>`);
            setQuickCmdsEnabled(false);
            return;
          }
          if (msg.type === 'disconnected_pod') {
            this.shellActive = false;
            this.currentPod = null;
            this._setStatus(false, 'Disconnected');
            this.podLabel.textContent = 'Select a pod';
            this.tabBar.style.display = 'none';
            document.getElementById(`pane-${this.id}-disconnect`).style.display = 'none';
            if (this.id === activePaneId) setQuickCmdsEnabled(false);
            if (this.term) this.term.write('\r\n\x1b[33mDisconnected from pod.\x1b[0m\r\n');
            return;
          }
        } catch (_) {}
        if (this.term) this.term.write(ev.data);
      }

      _setStatus(connected, text) {
        connected ? this.statusDot.classList.add('connected') : this.statusDot.classList.remove('connected');
        this.statusText.textContent = text;
      }

      _startHeartbeat() {
        if (this._activityTimer) clearInterval(this._activityTimer);
        this._activityTimer = setInterval(() => {
          if (this.ws && this.ws.readyState === WebSocket.OPEN)
            this.ws.send(JSON.stringify({type: 'activity'}));
        }, 30000);
      }

      send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(data);
      }

      // ── Select pod ──
      selectPod(podName) {
        this.currentPod = podName;
        this.tabBar.style.display = 'flex';
        loadPodInfo(podName);

        const podData = (window._podData || []).find(p => p.name === podName);
        if (this.noShellPods.has(podName) || (podData && podData.hasShell === false)) {
          this._setStatus(false, 'No shell');
          this.podLabel.textContent = `${podName} · logs only`;
          if (this.id === activePaneId) setQuickCmdsEnabled(false);
          this.switchTab('logs');
          this.loadLogs(podName);
          return;
        }

        // Init xterm if needed
        if (!this.term) {
          this.termEl.innerHTML = '';
          this.term = new Terminal({
            cursorBlink: true, fontSize: 13,
            fontFamily: "'JetBrains Mono', monospace",
            theme: { background: '#0a0e1a', foreground: '#e2e8f0', cursor: '#6366f1', selectionBackground: '#334155' },
          });
          this.fitAddon = new FitAddon.FitAddon();
          this.term.loadAddon(this.fitAddon);
          this.term.open(this.termEl);
          this.term.onData((d) => this.send(d));
          window.addEventListener('resize', () => this.fit());
        }

        this.switchTab('terminal');
        this._setStatus(false, 'Connecting…');
        this.podLabel.textContent = `Connecting to: ${podName}`;

        const msg = JSON.stringify({type: 'select_pod', pod: podName, namespace: activeNs});
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(msg);
        } else {
          // WS still connecting — queue the message; _openWS onopen will drain it
          this._pendingPodMsg = msg;
        }
      }

      fit() {
        if (this.fitAddon) requestAnimationFrame(() => this.fitAddon.fit());
      }

      focus() {
        if (this.term) this.term.focus();
      }

      // ── Tabs ──
      switchTab(name) {
        const tabEl = this.tabBar;
        tabEl.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        const btn = tabEl.querySelector(`.tab[onclick*="'${this.id}','${name}'"]`);
        if (btn) btn.classList.add('active');
        ['terminal','logs','events'].forEach(n => {
          const tc = document.getElementById(`pane-${this.id}-${n}-tab`);
          if (tc) tc.classList.toggle('active', n === name);
        });
        if (name === 'terminal') this.fit();
        lucide.createIcons();
      }

      async loadLogs(podName) {
        const el = document.getElementById(`pane-${this.id}-logs`);
        el.innerHTML = '<div style="color:var(--text-dim);padding:16px;">Loading logs…</div>';
        try {
          const d = await fetch(`/api/terminal/${cluster}/${requestName}/${podName}/logs?namespace=${encodeURIComponent(activeNs)}`).then(r => r.json());
          if (d.error) { el.innerHTML = `<div style="color:var(--danger);padding:16px;">Error: ${d.error}</div>`; return; }
          if (!d.logs || !d.logs.trim()) {
            el.innerHTML = '<div style="color:var(--text-dim);padding:16px;">No logs available for this pod.</div>';
            return;
          }
          // Add section breaks before lines that start with a timestamp (ISO-8601 or k8s log format)
          const _tsRe = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/;
          const _lvRe = /\b(error|err|fatal|critical|warn(?:ing)?|info|debug|trace)\b/i;
          function _logClass(line) {
            const lv = (line.match(_lvRe) || [])[1] || '';
            const l = lv.toLowerCase();
            if (/^(error|err|fatal|critical)$/.test(l)) return 'll-error';
            if (/^warn/.test(l)) return 'll-warn';
            if (l === 'debug' || l === 'trace') return 'll-debug';
            if (l === 'info') return 'll-info';
            return '';
          }
          let prev = null;
          el.innerHTML = d.logs.split('\n').map(l => {
            const m = l.match(_tsRe);
            let out = '';
            if (m) {
              const day = m[1].slice(0, 10);
              if (prev && prev !== day) {
                out += `<div class="log-section-break">${escapeHtml(day)}</div>`;
              }
              prev = day;
            }
            const cls = _logClass(l);
            return out + `<div class="log-line${cls ? ' ' + cls : ''}">${escapeHtml(l)}</div>`;
          }).join('');
          el.scrollTop = el.scrollHeight;
        } catch(e) { el.innerHTML = `<div style="color:var(--danger);padding:16px;">${e.message}</div>`; }
      }

      async loadEvents(podName) {
        const el = document.getElementById(`pane-${this.id}-events`);
        el.innerHTML = '<div style="color:var(--text-dim);padding:16px;">Loading events…</div>';
        try {
          const d = await fetch(`/api/terminal/${cluster}/${requestName}/${podName}/events?namespace=${encodeURIComponent(activeNs)}`).then(r => r.json());
          if (d.error) { el.innerHTML = `<div style="color:var(--danger);padding:16px;">Error: ${d.error}</div>`; return; }
          if (d.forbidden) { el.innerHTML = '<div style="color:var(--text-dim);padding:16px;">⚠️ Events not available.</div>'; return; }
          if (!d.events.length) { el.innerHTML = '<div style="color:var(--text-dim);padding:16px;">No events found.</div>'; return; }
          el.innerHTML = d.events.map(e => `
            <div class="event-item ${escapeHtml(e.type.toLowerCase())}">
              <div class="event-header"><span class="event-type">${escapeHtml(e.reason||'')}</span><span class="event-time">${escapeHtml(e.lastTimestamp||'')}</span></div>
              <div class="event-message">${escapeHtml(e.message||'')}</div>
            </div>`).join('');
        } catch(e) { el.innerHTML = `<div style="color:var(--danger);padding:16px;">${e.message}</div>`; }
      }

      destroy() {
        this._destroyed = true;
        clearInterval(this._activityTimer);
        clearTimeout(this._reconnectTimer);
        if (this.ws) { try { this.ws.close(); } catch(_){} this.ws = null; }
        if (this.term) { try { this.term.dispose(); } catch(_){} this.term = null; }
        if (this.termEl) { this.termEl.innerHTML = ''; }
      }
    }

    // ========================================================================
    // Global pane management
    // ========================================================================
    let paneA = new TermPane('a');
    let paneB = null;

    // Initial namespace tab styling + first pod load — runs here so paneA is ready.
    _applyNsTabStyle(activeNs);
    loadPods();
    let activePaneId = 'a';
    let splitOpen = false;
    let _cmdsEnabled = false;

    function setActivePane(id) {
      activePaneId = id;
      document.getElementById('pane-a').classList.toggle('focused', id === 'a');
      if (paneB) document.getElementById('pane-b').classList.toggle('focused', id === 'b');
      const activePane = id === 'a' ? paneA : paneB;
      setQuickCmdsEnabled(activePane ? activePane.shellActive : false);
      const label = document.getElementById('active-pane-label');
      if (label) label.textContent = splitOpen ? `Active: Pane ${id.toUpperCase()}` : '';
    }

    function toggleSplit() {
      if (splitOpen) return; // button is faded when split open — use ✕ on pane to close
      openSplit();
    }

    function openSplit() {
      splitOpen = true;
      sessionStorage.setItem('k8s_janus_split', '1');
      document.getElementById('pane-b').style.display = 'flex';
      document.getElementById('term-resize-handle').style.display = 'flex';
      document.getElementById('pane-a-close').style.display = '';
      document.getElementById('split-btn').classList.add('active');
      // Reset any manual widths so both panes start at 50/50
      var elA = document.getElementById('pane-a');
      elA.style.flex = ''; elA.style.width = '';
      if (!paneB) paneB = new TermPane('b');
      setActivePane('b');
      paneA.fit();
      lucide.createIcons();
    }

    function closeSplit() {
      splitOpen = false;
      sessionStorage.removeItem('k8s_janus_split');
      document.getElementById('pane-b').style.display = 'none';
      document.getElementById('term-resize-handle').style.display = 'none';
      document.getElementById('pane-a-close').style.display = 'none';
      document.getElementById('split-btn').classList.remove('active');
      if (paneB) { paneB.destroy(); paneB = null; }
      // Reset pane-a width so it fills the full wrapper
      var elA = document.getElementById('pane-a');
      elA.style.flex = ''; elA.style.width = '';
      setActivePane('a');
      paneA.fit();
      document.getElementById('active-pane-label').textContent = '';
    }

    function disconnectPod(id) {
      const pane = id === 'a' ? paneA : paneB;
      if (!pane || !pane.ws || pane.ws.readyState !== WebSocket.OPEN) return;
      pane.ws.send(JSON.stringify({type: 'disconnect_pod'}));
    }

    // Restore split state from previous session
    if (sessionStorage.getItem('k8s_janus_split')) openSplit();

    // Called by tab buttons onclick="paneTab('a','terminal')"
    function paneTab(id, name) {
      const pane = id === 'a' ? paneA : paneB;
      if (!pane) return;
      pane.switchTab(name);
      if (name === 'logs' && pane.currentPod) pane.loadLogs(pane.currentPod);
      else if (name === 'events' && pane.currentPod) pane.loadEvents(pane.currentPod);
      setActivePane(id);
    }

    // ── Quick commands ──────────────────────────────────────────────────────
    // Default commands seeded on first use — fully editable/deletable like user commands
    const _DEFAULT_CMDS = [
      { label: 'env | sort',    command: 'env | sort' },
      { label: 'ps aux',        command: 'ps aux' },
      { label: 'df -h',         command: 'df -h' },
      { label: 'cat /etc/hosts',command: 'cat /etc/hosts' },
      { label: 'curl /healthz', command: 'for p in 8080 80 8000 3000; do r=$(curl -sf http://localhost:$p/healthz 2>/dev/null) && echo ":$p/healthz \u2192 $r" && break; done || echo "no healthz found"' },
      { label: 'exit',          command: 'exit' },
    ];
    let _userCmds = [];   // {id, label, command} from API / localStorage

    const _LS_KEY = 'k8s_janus_quick_cmds';
    const _SEEDED_KEY = 'k8s_janus_cmds_seeded';

    async function loadUserCmds() {
      try {
        const res = await fetch('/api/quick-commands');
        if (res.ok) {
          const data = await res.json();
          if (data.db_enabled === false) {
            // DB not available — use localStorage
            try { _userCmds = JSON.parse(localStorage.getItem(_LS_KEY) || '[]'); } catch(_) { _userCmds = []; }
            // Seed defaults into localStorage if first time
            if (!localStorage.getItem(_SEEDED_KEY) && _userCmds.length === 0) {
              _userCmds = _DEFAULT_CMDS.map((c, i) => ({ id: 'ls-' + i, label: c.label, command: c.command }));
              _saveLocalFallback();
              localStorage.setItem(_SEEDED_KEY, '1');
            }
            return;
          }
          _userCmds = data.commands || [];
          // Seed defaults into DB if first time (no commands yet)
          if (_userCmds.length === 0 && !localStorage.getItem(_SEEDED_KEY)) {
            for (const c of _DEFAULT_CMDS) await saveUserCmd(null, c.label, c.command);
            localStorage.setItem(_SEEDED_KEY, '1');
            // re-fetch after seeding
            const r2 = await fetch('/api/quick-commands');
            if (r2.ok) { const d2 = await r2.json(); _userCmds = d2.commands || []; }
          }
          return;
        }
      } catch (_) {}
      // Network/auth failure — use localStorage
      try { _userCmds = JSON.parse(localStorage.getItem(_LS_KEY) || '[]'); } catch(_) { _userCmds = []; }
    }

    function _saveLocalFallback() {
      try { localStorage.setItem(_LS_KEY, JSON.stringify(_userCmds)); } catch(_) {}
    }

    function renderQuickCmds() {
      const toolbar = document.getElementById('quick-cmd-toolbar');
      toolbar.innerHTML = '';
      _userCmds.forEach(c => {
        const btn = document.createElement('button');
        btn.className = 'quick-cmd-btn';
        btn.disabled = !_cmdsEnabled;
        btn.title = c.command.trim();
        btn.innerHTML = `<i data-lucide="terminal" style="width:11px;height:11px;flex-shrink:0;"></i><span style="overflow:hidden;text-overflow:ellipsis;">${_esc(c.label)}</span>`;
        btn.onclick = () => sendQuickCmd(c.command.endsWith('\r') ? c.command : c.command + '\r');
        toolbar.appendChild(btn);
      });
      lucide.createIcons({ nodes: [toolbar] });
    }

    // ── Quick commands manage modal ──
    let _qcmdEditingId = null;  // which row is in inline-edit mode inside the manage modal

    function openQcmdManage() {
      document.getElementById('qcmd-new-label').value = '';
      document.getElementById('qcmd-new-cmd').value = '';
      _qcmdEditingId = null;
      _renderManageList();
      document.getElementById('qcmd-modal-backdrop').style.display = '';
      const modal = document.getElementById('qcmd-modal');
      modal.style.display = 'flex';
      lucide.createIcons({ nodes: [modal] });
    }

    function closeQcmdManage() {
      document.getElementById('qcmd-modal-backdrop').style.display = 'none';
      document.getElementById('qcmd-modal').style.display = 'none';
      _qcmdEditingId = null;
    }

    function _renderManageList() {
      const list = document.getElementById('qcmd-manage-list');
      if (!_userCmds.length) {
        list.innerHTML = '<div style="text-align:center;color:var(--text-dim);font-size:0.82rem;padding:12px 0;">No commands yet — add one below.</div>';
        return;
      }
      list.innerHTML = '';
      _userCmds.forEach(c => {
        const isEditing = _qcmdEditingId === c.id;
        const row = document.createElement('div');
        row.style.cssText = 'background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:8px 10px;';

        if (isEditing) {
          row.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:6px;">
              <input id="qcmd-edit-label-${_esc(c.id)}" value="${_esc(c.label)}" maxlength="100"
                style="background:var(--surface-3);border:1px solid var(--accent);border-radius:5px;padding:5px 8px;color:var(--text);font-size:0.82rem;outline:none;width:100%;box-sizing:border-box;">
              <input id="qcmd-edit-cmd-${_esc(c.id)}" value="${_esc(c.command.replace(/\r$/, ''))}"
                style="background:var(--surface-3);border:1px solid var(--accent);border-radius:5px;padding:5px 8px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:0.78rem;outline:none;width:100%;box-sizing:border-box;"
                onkeydown="if(event.key==='Enter')_saveManageEdit('${_esc(c.id)}');if(event.key==='Escape')_cancelManageEdit()">
              <div style="display:flex;justify-content:flex-end;gap:6px;">
                <button onclick="_cancelManageEdit()" style="padding:4px 10px;background:var(--surface-3);border:1px solid var(--border);border-radius:5px;color:var(--text-muted);font-size:0.78rem;cursor:pointer;">Cancel</button>
                <button onclick="_saveManageEdit('${_esc(c.id)}')" style="padding:4px 10px;background:var(--accent);border:none;border-radius:5px;color:#fff;font-size:0.78rem;font-weight:600;cursor:pointer;">Save</button>
              </div>
            </div>`;
        } else {
          row.innerHTML = `
            <div style="display:flex;align-items:center;gap:8px;">
              <div style="flex:1;min-width:0;">
                <div style="font-size:0.82rem;font-weight:500;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${_esc(c.label)}</div>
                <div style="font-size:0.73rem;color:var(--text-dim);font-family:'JetBrains Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;">${_esc(c.command.replace(/\r$/, ''))}</div>
              </div>
              <button onclick="_startManageEdit('${_esc(c.id)}')" title="Edit"
                style="flex-shrink:0;background:none;border:none;color:var(--text-dim);cursor:pointer;padding:3px;border-radius:4px;display:flex;"
                onmouseover="this.style.color='var(--text)';this.style.background='rgba(255,255,255,0.06)'"
                onmouseout="this.style.color='var(--text-dim)';this.style.background='none'">
                <i data-lucide="pencil" style="width:13px;height:13px;"></i>
              </button>
              <button onclick="_deleteManageCmd('${_esc(c.id)}')" title="Delete"
                style="flex-shrink:0;background:none;border:none;color:var(--text-dim);cursor:pointer;padding:3px;border-radius:4px;display:flex;"
                onmouseover="this.style.color='var(--danger)';this.style.background='rgba(239,68,68,0.08)'"
                onmouseout="this.style.color='var(--text-dim)';this.style.background='none'">
                <i data-lucide="trash-2" style="width:13px;height:13px;"></i>
              </button>
            </div>`;
        }
        list.appendChild(row);
      });
      lucide.createIcons({ nodes: [list] });
    }

    function _startManageEdit(id) { _qcmdEditingId = id; _renderManageList(); setTimeout(() => { const el = document.getElementById('qcmd-edit-label-' + id); if (el) el.focus(); }, 30); }
    function _cancelManageEdit() { _qcmdEditingId = null; _renderManageList(); }
    function _saveManageEdit(id) {
      const label   = (document.getElementById('qcmd-edit-label-' + id) || {}).value?.trim();
      const command = (document.getElementById('qcmd-edit-cmd-'   + id) || {}).value?.trim();
      if (!label || !command) return;
      _qcmdEditingId = null;
      saveUserCmd(id, label, command);
    }
    function _deleteManageCmd(id) { deleteUserCmd(id); _renderManageList(); }

    async function addQcmdFromManage() {
      const label   = document.getElementById('qcmd-new-label').value.trim();
      const command = document.getElementById('qcmd-new-cmd').value.trim();
      if (!label || !command) return;
      document.getElementById('qcmd-new-label').value = '';
      document.getElementById('qcmd-new-cmd').value   = '';
      await saveUserCmd(null, label, command);
      _renderManageList();
    }

    async function saveUserCmd(id, label, command) {
      label = (label || '').trim();
      command = (command || '').trim();
      if (!label || !command) return;

      try {
        if (id) {
          const res = await fetch(`/api/quick-commands/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({label, command}),
          });
          if (res.ok) {
            const rec = await res.json();
            _userCmds = _userCmds.map(c => c.id === id ? rec : c);
          }
        } else {
          const res = await fetch('/api/quick-commands', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({label, command}),
          });
          if (res.ok) {
            const rec = await res.json();
            _userCmds.push(rec);
          } else {
            // DB unavailable — store locally
            const localId = 'l-' + Date.now();
            _userCmds.push({id: localId, label, command});
            _saveLocalFallback();
          }
        }
      } catch(_) {
        // Offline fallback
        if (id) {
          _userCmds = _userCmds.map(c => c.id === id ? {...c, label, command} : c);
        } else {
          _userCmds.push({id: 'l-' + Date.now(), label, command});
        }
        _saveLocalFallback();
      }
      renderQuickCmds();
      if (document.getElementById('qcmd-modal').style.display !== 'none') _renderManageList();
    }

    async function deleteUserCmd(id) {
      try {
        await fetch(`/api/quick-commands/${id}`, {method: 'DELETE'});
      } catch(_) {}
      _userCmds = _userCmds.filter(c => c.id !== id);
      _saveLocalFallback();
      renderQuickCmds();
      if (document.getElementById('qcmd-modal').style.display !== 'none') _renderManageList();
    }

    function sendQuickCmd(cmd) {
      const pane = activePaneId === 'a' ? paneA : paneB;
      if (pane) {
        pane.send(cmd);
        pane.switchTab('terminal');
        pane.focus();
      }
    }

    function setQuickCmdsEnabled(enabled) {
      _cmdsEnabled = enabled;
      document.querySelectorAll('.quick-cmd-btn').forEach(b => b.disabled = !enabled);
    }

    function _esc(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    loadUserCmds().then(renderQuickCmds);

    // ========================================================================
    // Pod list (shared sidebar)
    // ========================================================================
    function loadPods() {
      fetch(`/api/terminal/${cluster}/${requestName}/pods?namespace=${encodeURIComponent(activeNs)}`)
        .then(async r => {
          if (!r.ok) {
            let msg = `HTTP ${r.status}`;
            try { const j = await r.json(); msg = j.error || msg; } catch(_) {}
            throw new Error(msg);
          }
          return r.json();
        })
        .then(data => {
          const podList  = document.getElementById('pod-list');
          const podCount = document.getElementById('pod-count');
          if (data.error) {
            podList.innerHTML = `<div class="loading-pods" style="color:var(--danger);flex-direction:column;gap:8px;">
              <i data-lucide="alert-circle" style="width:28px;height:28px;"></i>
              <span>${data.error}</span>
            </div>`;
            lucide.createIcons({ nodes: [podList] });
            return;
          }
          if (!data.pods.length) { podList.innerHTML = '<div class="loading-pods">No running pods found</div>'; podCount.textContent = '0 pods'; return; }

          podCount.textContent = `${data.pods.length} pod${data.pods.length !== 1 ? 's' : ''}`;
          window._podData = data.pods;

          const nowPods = new Set(data.pods.map(p => p.name));
          const newPods = [...nowPods].filter(n => !knownPods.has(n));
          const gonePods = [...knownPods].filter(n => !nowPods.has(n));
          knownPods = nowPods;

          const activeA = paneA.currentPod;
          const activeB = paneB ? paneB.currentPod : null;

          // Remove placeholder (Loading pods... / error) on first successful load
          podList.querySelectorAll('.loading-pods').forEach(el => el.remove());

          // Build a map of existing DOM items so we can update in-place
          // instead of nuking the whole list on every 5s poll.
          const existingItems = {};
          podList.querySelectorAll('.pod-item[data-pod]').forEach(el => {
            existingItems[el.dataset.pod] = el;
          });

          const podListChanged = newPods.length > 0 || gonePods.length > 0;

          if (podListChanged) {
            // Remove pods that disappeared
            gonePods.forEach(name => { if (existingItems[name]) existingItems[name].remove(); });
          }

          let iconsNeedRefresh = podListChanged;

          data.pods.forEach(pod => {
            const noShell = pod.hasShell === false || paneA.noShellPods.has(pod.name);
            const selA    = activeA === pod.name;
            const selB    = activeB === pod.name;
            const isNew   = newPods.includes(pod.name);

            const paneTag = selA && selB ? ' <span style="color:var(--accent);font-size:0.65rem;">A+B</span>'
                          : selA ? ' <span style="color:var(--accent);font-size:0.65rem;">A</span>'
                          : selB ? ' <span style="color:var(--accent-2);font-size:0.65rem;">B</span>' : '';
            const shellHint = noShell ? ' <span style="color:var(--warning);font-size:0.65rem;font-weight:600;">NO SHELL</span>' : '';

            // Health signal badges
            const badgeStyle = 'font-size:0.6rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:3px;';
            let healthBadges = '';
            if (pod.terminating) {
              healthBadges += `<span style="${badgeStyle}background:rgba(var(--warning-rgb,255,165,0),0.2);color:var(--warning);">TERM</span>`;
            }
            if (pod.oom) {
              healthBadges += `<span style="${badgeStyle}background:rgba(var(--danger-rgb,220,50,47),0.2);color:var(--danger);">OOM</span>`;
            }
            const waitingReasons = pod.waitingReasons || [];
            if (waitingReasons.includes('CrashLoopBackOff')) {
              healthBadges += `<span style="${badgeStyle}background:rgba(var(--danger-rgb,220,50,47),0.2);color:var(--danger);">CRASH</span>`;
            } else if (waitingReasons.length > 0) {
              healthBadges += `<span style="${badgeStyle}background:rgba(var(--warning-rgb,255,165,0),0.15);color:var(--warning);">${escapeHtml(waitingReasons[0])}</span>`;
            }
            const restarts = pod.restarts || 0;
            const restartBadge = restarts > 0
              ? `<span style="${badgeStyle}background:rgba(var(--warning-rgb,255,165,0),0.15);color:var(--warning);">${restarts}R</span>`
              : '';

            // Icon: danger for crash/oom/terminating, warning for restarts, normal otherwise
            const hasDanger  = pod.oom || waitingReasons.includes('CrashLoopBackOff') || pod.terminating;
            const hasWarning = !hasDanger && restarts > 0;
            const iconName   = noShell ? 'terminal-square' : (hasDanger ? 'triangle-alert' : 'box');
            const iconColor  = hasDanger ? 'var(--danger)' : (hasWarning ? 'var(--warning)' : (noShell ? 'var(--warning)' : ''));

            const wantClass = 'pod-item' + (selA || selB ? ' selected' : '');

            // Build status line text
            const statusText = noShell ? 'logs only' : pod.status;

            // Signature string to detect any meaningful change
            const sig = `${pod.status}|${pod.oom}|${pod.terminating}|${restarts}|${waitingReasons.join(',')}`;

            let item = existingItems[pod.name];
            if (!item) {
              // New pod — create and render
              item = document.createElement('div');
              item.dataset.pod    = pod.name;
              item.dataset.status = pod.status;
              item.dataset.sig    = sig;
              item.onclick = () => {
                const targetPane = (splitOpen && activePaneId === 'b') ? paneB : paneA;
                document.querySelectorAll('.pod-item').forEach(e => e.classList.remove('selected'));
                item.classList.add('selected');
                setActivePane(targetPane.id);
                targetPane.selectPod(pod.name);
              };
              item.className = wantClass;
              item.innerHTML = `
                <div class="pod-icon">
                  <i data-lucide="${iconName}" style="width:15px;height:15px;${iconColor ? 'color:' + iconColor + ';' : ''}"></i>
                </div>
                <div class="pod-info">
                  <div class="pod-name">${escapeHtml(pod.name)}${isNew ? ' <span style="color:var(--success);font-size:0.65rem;font-weight:600;">NEW</span>' : ''}${shellHint}${paneTag}${healthBadges}${restartBadge}</div>
                  <div class="pod-status ${escapeHtml(pod.status.toLowerCase())}">${statusText}</div>
                </div>
              `;
              podList.appendChild(item);
              if (isNew) { item.classList.add('pod-new'); setTimeout(() => item.classList.remove('pod-new'), 3000); }
              iconsNeedRefresh = true;
            } else {
              // Existing pod — only update if something meaningful changed
              const sigChanged  = item.dataset.sig !== sig;
              const selChanged  = item.className !== wantClass;
              if (sigChanged || selChanged || paneTag) {
                item.dataset.status = pod.status;
                item.dataset.sig    = sig;
                item.className = wantClass;
                item.querySelector('.pod-icon').innerHTML =
                  `<i data-lucide="${iconName}" style="width:15px;height:15px;${iconColor ? 'color:' + iconColor + ';' : ''}"></i>`;
                item.querySelector('.pod-name').innerHTML =
                  `${escapeHtml(pod.name)}${shellHint}${paneTag}${healthBadges}${restartBadge}`;
                item.querySelector('.pod-status').className =
                  `pod-status ${escapeHtml(pod.status.toLowerCase())}`;
                item.querySelector('.pod-status').textContent = statusText;
                if (sigChanged) iconsNeedRefresh = true;
              }
            }
          });

          if (iconsNeedRefresh) lucide.createIcons({ nodes: [podList] });
        })
        .catch(err => {
          document.getElementById('pod-list').innerHTML = `<div class="loading-pods" style="color:var(--danger);">Failed to load pods: ${escapeHtml(err.message)}</div>`;
        });
    }

    refreshInterval = setInterval(loadPods, 5000);

    // ── Pod info panel ──
    function _fmtAge(seconds) {
      if (seconds == null) return '—';
      if (seconds < 60)   return seconds + 's';
      if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
      if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
      return Math.floor(seconds / 86400) + 'd ' + Math.floor((seconds % 86400) / 3600) + 'h';
    }

    function _row(label, value) {
      return `<div style="display:flex;gap:6px;align-items:baseline;">
        <span style="color:var(--text-dim);min-width:52px;flex-shrink:0;">${label}</span>
        <span style="font-family:'JetBrains Mono',monospace;color:var(--text);word-break:break-all;">${value}</span>
      </div>`;
    }

    async function loadPodInfo(podName) {
      const panel   = document.getElementById('pod-info-panel');
      const content = document.getElementById('pod-info-content');
      const ns      = window.PAGE_DATA.namespace;
      const clusterVal = window.PAGE_DATA.cluster;
      panel.style.display = '';
      content.innerHTML   = '<span style="color:var(--text-dim);">Loading…</span>';
      try {
        const r = await fetch(`/api/pod-info/${encodeURIComponent(clusterVal)}/${encodeURIComponent(ns)}/${encodeURIComponent(podName)}`);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        let html = '';
        html += _row('Age', _fmtAge(d.ageSeconds));
        (d.containers || []).forEach(c => {
          if (d.containers.length > 1) {
            html += `<div style="color:var(--text-dim);font-weight:600;margin-top:4px;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.05em;">${escapeHtml(c.name)}</div>`;
          }
          html += _row('Image', escapeHtml(c.image || '—'));
          const req = c.requests || {}, lim = c.limits || {};
          if (req.cpu || req.memory || lim.cpu || lim.memory) {
            html += _row('CPU', `req ${req.cpu||'—'} / lim ${lim.cpu||'—'}`);
            html += _row('Mem', `req ${req.memory||'—'} / lim ${lim.memory||'—'}`);
          }
          if (c.volumeMounts && c.volumeMounts.length) {
            html += `<div style="color:var(--text-dim);margin-top:2px;font-size:0.68rem;">Volumes</div>`;
            c.volumeMounts.forEach(v => {
              html += `<div style="padding-left:4px;font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(v.name)}: ${escapeHtml(v.mountPath)}">${escapeHtml(v.name)} → ${escapeHtml(v.mountPath)}</div>`;
            });
          }
        });
        content.innerHTML = html;
      } catch(e) {
        content.innerHTML = `<span style="color:var(--danger);">Failed to load</span>`;
      }
    }

    // ── Resize: re-fit all panes on window resize ──
    window.addEventListener('resize', () => {
      paneA.fit();
      if (paneB) paneB.fit();
    });

    // ── Drag-to-resize split panes ──
    (function() {
      var handle   = document.getElementById('term-resize-handle');
      var wrapper  = document.getElementById('panes-wrapper');
      var elA      = document.getElementById('pane-a');
      var elB      = document.getElementById('pane-b');
      var dragging = false, startX = 0, startW = 0;

      handle.addEventListener('mousedown', function(e) {
        if (!splitOpen) return;
        dragging = true;
        startX   = e.clientX;
        startW   = elA.getBoundingClientRect().width;
        handle.classList.add('dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
      });

      document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        var total     = wrapper.getBoundingClientRect().width;
        var handleW   = handle.offsetWidth;
        var available = total - handleW;
        var delta     = e.clientX - startX;
        var newA      = Math.max(150, Math.min(startW + delta, available - 150));
        elA.style.flex  = 'none';
        elA.style.width = newA + 'px';
        elB.style.flex  = '1';
        elB.style.width = '';
        paneA.fit();
        if (paneB) paneB.fit();
      });

      document.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false;
        handle.classList.remove('dragging');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      });
    })();

    // ── Visibility reconnect — try reconnect when tab regains focus ──
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'visible') return;
      [paneA, paneB].forEach(p => {
        if (!p) return;
        if (!p.ws || p.ws.readyState === WebSocket.CLOSED) {
          p._retryCount = 0;  // reset so reconnect attempts are fresh
          p._openWS();
        }
      });
    });

    // ── Activity-based idle timeout (4h, warn 15 min before) ──
    (function() {
      const _ACT_KEY   = 'janus_last_activity_ts';
      const _IDLE_MS   = 4 * 60 * 60 * 1000;  // 4 hours
      const _WARN_MS   = 15 * 60 * 1000;       // 15 min warning
      function _touch() { localStorage.setItem(_ACT_KEY, Date.now()); }
      ['keypress', 'click', 'scroll'].forEach(ev => document.addEventListener(ev, _touch, { passive: true }));
      _touch();  // mark activity on page load
      let _warnShown = false;
      setInterval(() => {
        const last = parseInt(localStorage.getItem(_ACT_KEY) || Date.now());
        const idle = Date.now() - last;
        if (idle >= _IDLE_MS) {
          window.location = '/logout';
        } else if (idle >= (_IDLE_MS - _WARN_MS) && !_warnShown) {
          _warnShown = true;
          const remaining = Math.ceil((_IDLE_MS - idle) / 60000);
          showBanner('warning', `⚠️ Inactive for a while — you will be signed out in ~${remaining} min due to inactivity.`, 60000);
        }
      }, 60000);
    })();

    // ── Cleanup ──
    window.addEventListener('beforeunload', () => {
      clearInterval(refreshInterval);
      paneA.destroy();
      if (paneB) paneB.destroy();
    });
