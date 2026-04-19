// index.js — extracted from index.html
// Variables passed via window.PAGE_DATA (set inline in the template):
//   userEmail:    current user's email
//   isAdmin:      boolean
//   oidcEnabled:  boolean
//   accessRequests: array of {name, cluster, clusterDisplay, namespace, phase, requester}
const { userEmail, isAdmin, oidcEnabled, accessRequests } = window.PAGE_DATA;

    lucide.createIcons();

    // ── My Requests pagination + detail ──
    var _myAllRows = [], _myFilteredRows = [], _myPage = 1, _myPerPage = 25, _myOpenDetail = null;

    function _myGetAllRows() { return Array.from(document.querySelectorAll('#my-requests-tbody tr.my-req-row')); }

    function myRenderPage() {
      var total = _myFilteredRows.length;
      var totalPages = Math.max(1, Math.ceil(total / _myPerPage));
      if (_myPage > totalPages) _myPage = totalPages;
      var start = (_myPage - 1) * _myPerPage, end = Math.min(start + _myPerPage, total);
      _myAllRows.forEach(function(r) { r.style.display = 'none'; });
      _myFilteredRows.forEach(function(r, i) { r.style.display = (i >= start && i < end) ? '' : 'none'; });
      var bar = document.getElementById('my-pagination-bar');
      var infoEl = document.getElementById('my-pg-info-text');
      var pgPages = document.getElementById('my-pg-pages');
      if (infoEl) infoEl.textContent = total === 0 ? '' : 'Showing ' + (start+1) + '–' + end + ' of ' + total;
      if (!pgPages || !bar) return;
      pgPages.innerHTML = '';
      if (totalPages <= 1) { bar.style.display = 'none'; return; }
      bar.style.display = 'flex';
      function mkBtn(label, page, isActive, isDisabled) {
        var b = document.createElement('button');
        b.className = 'pg-btn' + (isActive ? ' active' : '');
        b.textContent = label; b.disabled = isDisabled;
        if (!isDisabled) b.onclick = function() { _myPage = page; myCloseDetail(); myRenderPage(); };
        return b;
      }
      pgPages.appendChild(mkBtn('‹', _myPage-1, false, _myPage===1));
      var ws = Math.max(1, _myPage-2), we = Math.min(totalPages, _myPage+2);
      if (ws > 1) { pgPages.appendChild(mkBtn('1', 1, false, false)); if (ws > 2) { var e = document.createElement('span'); e.textContent='…'; e.style.cssText='padding:0 4px;color:var(--text-dim);'; pgPages.appendChild(e); } }
      for (var p = ws; p <= we; p++) pgPages.appendChild(mkBtn(p, p, p===_myPage, p===_myPage));
      if (we < totalPages) { if (we < totalPages-1) { var e2 = document.createElement('span'); e2.textContent='…'; e2.style.cssText='padding:0 4px;color:var(--text-dim);'; pgPages.appendChild(e2); } pgPages.appendChild(mkBtn(totalPages, totalPages, false, false)); }
      pgPages.appendChild(mkBtn('›', _myPage+1, false, _myPage===totalPages));
    }

    function mySetPerPage(val) { _myPerPage = parseInt(val); _myPage = 1; myCloseDetail(); myRenderPage(); }

    function toggleMyDetailBtn(btn) {
      var row = btn.closest('tr.my-req-row');
      var d = row.dataset;
      var nssEl = document.getElementById('my-ns-' + d.name);
      var reasonEl = document.getElementById('my-reason-' + d.name);
      var nss = JSON.parse((nssEl && nssEl.textContent) || '[]');
      var reason = JSON.parse((reasonEl && reasonEl.textContent) || '""');
      toggleMyDetail(d.name, d.cluster, d.clusterDisplay, d.requester, nss, d.phase, d.ttl, d.expires, reason, d.approvedBy, btn);
    }

    function myCloseDetail() {
      if (_myOpenDetail) {
        var ex = document.getElementById('my-detail-row-' + _myOpenDetail);
        if (ex) ex.remove();
        var btn = document.getElementById('my-detail-btn-' + _myOpenDetail);
        if (btn) { btn.classList.remove('open'); var ic = btn.querySelector('i'); if (ic) ic.style.transform = ''; }
        _myOpenDetail = null;
      }
    }

    function toggleMyDetail(name, cluster, clusterDisplay, requester, namespaces, phase, ttl, expiresAt, reason, approvedBy, btn) {
      if (_myOpenDetail === name) { myCloseDetail(); return; }
      myCloseDetail();
      _myOpenDetail = name;
      btn.classList.add('open');
      var icon = btn.querySelector('i'); if (icon) icon.style.transform = 'rotate(180deg)';

      var nsHtml = namespaces.map(function(n) { return '<span class="ns-chip">'+n+'</span>'; }).join('');
      var ttlNum = parseInt(ttl) || 3600;
      var h = Math.floor(ttlNum/3600), m = Math.floor((ttlNum%3600)/60);
      var ttlStr = (phase === 'Active' && expiresAt)
        ? '<span class="ttl-remaining" data-expires="'+expiresAt+'">…</span>'
        : (h && m ? h+'h '+m+'m' : h ? h+'h' : m+'m');

      var actionsHtml = '';
      if (phase === 'Pending') {
        actionsHtml = '<button class="cancel-btn" data-cluster="'+cluster+'" data-name="'+name+'" onclick="withdrawRequest(this.dataset.cluster,this.dataset.name,this)">'
          +'<i data-lucide="undo-2" style="width:12px;height:12px;"></i> Withdraw</button>';
      } else if (phase === 'Active') {
        actionsHtml = '<button class="cancel-btn" data-cluster="'+cluster+'" data-name="'+name+'" onclick="cancelRequest(this.dataset.cluster,this.dataset.name,\'Active\',this)">'
          +'<i data-lucide="x-circle" style="width:12px;height:12px;"></i> Cancel session</button>';
      }
      if (isAdmin && (phase === 'Active' || phase === 'Approved')) {
        actionsHtml += ' <button class="revoke-btn" data-cluster="'+cluster+'" data-name="'+name+'" data-requester="'+requester+'" onclick="inlineRevokeUser(this.dataset.cluster,this.dataset.name,this.dataset.requester)">'
          +'<i data-lucide="shield-off" style="width:12px;height:12px;"></i> Revoke</button>';
      }

      var panelHtml =
        '<div class="detail-panel">'
        +'<div class="detail-section"><span class="detail-label">Request ID</span>'
        +'<span class="detail-value"><a href="/status/'+cluster+'/'+name+'" style="color:var(--accent);font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;">'+name+'</a></span></div>'
        +'<div class="detail-section"><span class="detail-label">Requester</span><span class="detail-value">'+requester+'</span></div>'
        +'<div class="detail-section"><span class="detail-label">Cluster</span>'
        +'<span class="detail-value"><code style="color:#fb923c;background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.25);">'+clusterDisplay+'</code></span></div>'
        +'<div class="detail-section" style="grid-column:1/-1;"><span class="detail-label">Namespaces ('+namespaces.length+')</span>'
        +'<div style="margin-top:4px;">'+nsHtml+'</div></div>'
        +(reason ? '<div class="detail-section" style="grid-column:1/-1;"><span class="detail-label">Reason</span><span class="detail-value" style="font-style:italic;">'+reason+'</span></div>' : '')
        +'<div class="detail-section"><span class="detail-label">TTL / Remaining</span><span class="detail-value">'+ttlStr+'</span></div>'
        +(approvedBy ? '<div class="detail-section"><span class="detail-label">Approved by</span><span class="detail-value">'+approvedBy+'</span></div>' : '')
        +(actionsHtml ? '<div class="detail-actions">'+actionsHtml+'</div>' : '')
        +'</div>';

      var row = document.querySelector('tr.my-req-row[data-name="'+name+'"]');
      var detailRow = document.createElement('tr');
      detailRow.id = 'my-detail-row-' + name;
      detailRow.className = 'detail-row';
      detailRow.innerHTML = '<td colspan="6">'+panelHtml+'</td>';
      row.insertAdjacentElement('afterend', detailRow);
      lucide.createIcons({ nodes: [detailRow] });
      updateTtlRemaining();
    }

    // TTL remaining countdown for Active requests
    function updateTtlRemaining() {
      document.querySelectorAll('.ttl-remaining').forEach(function(el) {
        var expires = new Date(el.dataset.expires);
        var diff = Math.floor((expires - Date.now()) / 1000);
        if (diff <= 0) {
          el.textContent = 'Expired'; el.style.color = 'var(--danger)';
        } else {
          var h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60), s = diff % 60;
          el.textContent = h > 0 ? h + 'h ' + m + 'm left' : m + 'm ' + s + 's left';
          el.style.color = diff < 300 ? 'var(--danger)' : diff < 900 ? 'var(--warning)' : 'var(--success)';
        }
      });
    }
    updateTtlRemaining();
    setInterval(updateTtlRemaining, 1000);

    // Init pagination
    _myAllRows = _myGetAllRows();
    _myFilteredRows = _myAllRows.slice();
    myRenderPage();

    async function withdrawRequest(cluster, name, btn) {
      if (!confirm('Withdraw this pending request?')) return;
      btn.disabled = true; btn.textContent = 'Withdrawing…';
      try {
        var resp = await fetch('/cancel/' + cluster + '/' + name, { method: 'POST', headers: {'Accept': 'application/json'} });
        var data = await resp.json();
        if (data.ok) {
          _mySetRowPhase(name, 'Cancelled');
          myCloseDetail();
        } else {
          alert('Withdraw failed: ' + (data.error || 'unknown error'));
          btn.disabled = false; btn.textContent = 'Withdraw';
        }
      } catch(e) {
        alert('Withdraw failed: ' + e);
        btn.disabled = false; btn.textContent = 'Withdraw';
      }
    }

    async function cancelRequest(cluster, name, phase, btn) {
      var label = 'Cancel your active session?';
      if (!confirm(label)) return;
      btn.disabled = true; btn.textContent = 'Cancelling…';
      try {
        var resp = await fetch('/cancel/' + cluster + '/' + name, { method: 'POST', headers: {'Accept': 'application/json'} });
        var data = await resp.json();
        if (data.ok) {
          _mySetRowPhase(name, 'Cancelled');
          myCloseDetail();
        } else {
          alert('Cancel failed: ' + (data.error || 'unknown error'));
          btn.disabled = false; btn.textContent = 'Cancel session';
        }
      } catch(e) {
        alert('Cancel failed: ' + e);
        btn.disabled = false; btn.textContent = 'Cancel session';
      }
    }

    async function inlineRevokeUser(cluster, name, requester) {
      if (!isAdmin) return;
      if (!confirm('Revoke access for ' + requester + '?')) return;
      try {
        var resp = await fetch('/revoke/' + cluster + '/' + name, { method: 'POST', headers: {'Accept': 'application/json'} });
        var data = await resp.json();
        if (data.ok) { _mySetRowPhase(name, 'Revoked'); myCloseDetail(); }
        else alert('Revoke failed: ' + (data.error || 'unknown'));
      } catch(e) { alert('Revoke failed: ' + e); }
    }

    function _mySetRowPhase(name, phase) {
      var row = document.querySelector('tr.my-req-row[data-name="'+name+'"]');
      if (!row) return;
      var badge = row.querySelector('.badge');
      if (badge) {
        badge.className = 'badge badge-' + phase.toLowerCase();
        badge.innerHTML = '<span class="badge-dot"></span>' + phase;
      }
      row.dataset.phase = phase;
      // Remove terminal links and replace name link with plain span for non-active phases
      var inactive = !['Active', 'Approved'].includes(phase);
      if (inactive) {
        // Name cell: replace <a> with <span>
        var nameLink = row.querySelector('td a[href*="/terminal/"]');
        if (nameLink) {
          var span = document.createElement('span');
          span.style.cssText = nameLink.style.cssText;
          span.title = nameLink.title;
          span.textContent = nameLink.textContent;
          nameLink.replaceWith(span);
        }
        // Actions cell: remove Terminal button
        row.querySelectorAll('a[href*="/terminal/"]').forEach(function(el) { el.remove(); });
      }
      _myAllRows = _myGetAllRows();
      _myFilteredRows = _myAllRows.slice();
      myRenderPage();
    }

    // ── Single cluster, multi-NS selector ──
    let _currentCluster = '';
    let _nsSelected = new Set();   // selected namespaces for the current cluster

    function _updateSubmitState() {
      const count = _nsSelected.size;
      document.getElementById('submit-btn').disabled = !_currentCluster || count === 0;
      const countEl = document.getElementById('ns-selected-count');
      if (count > 0) {
        countEl.textContent = count + ' selected';
        countEl.style.display = '';
      } else {
        countEl.style.display = 'none';
      }
      document.getElementById('submit-label').textContent = 'Submit Request';
    }

    async function onClusterChange(clusterName) {
      _currentCluster = clusterName;
      _nsSelected = new Set();
      _updateSubmitState();
      document.getElementById('pod-preview').style.display = 'none';

      const section  = document.getElementById('ns-section');
      const loading  = document.getElementById('ns-loading');
      const grid     = document.getElementById('ns-grid');

      section.style.display = '';
      loading.style.display = '';
      loading.style.color   = 'var(--text-dim)';
      loading.textContent   = 'Loading namespaces…';
      grid.style.display    = 'none';
      grid.innerHTML        = '';
      document.getElementById('ns-filter').style.display = 'none';

      try {
        const resp = await fetch('/namespaces/' + encodeURIComponent(clusterName));
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const namespaces = await resp.json();

        loading.style.display = 'none';
        const nsFilter = document.getElementById('ns-filter');
        if (!namespaces.length) {
          loading.style.display = '';
          loading.textContent = 'No namespaces available';
          nsFilter.style.display = 'none';
          return;
        }

        grid.innerHTML = namespaces.map(ns => `
          <div class="ns-item" data-ns="${ns.replace(/"/g,'&quot;')}"
               onclick="toggleNs('${ns.replace(/'/g,"\\'")}', this)"
               onmouseenter="previewPods('${ns.replace(/'/g,"\\'")}', this)"
               onmouseleave="hidePreview()">
            <div class="ns-check">
              <svg width="9" height="9" viewBox="0 0 9 9" fill="none">
                <path d="M1.5 4.5L3.5 6.5L7.5 2.5" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </div>
            <span class="ns-name">${ns}</span>
          </div>
        `).join('');
        grid.style.display = '';
        nsFilter.value = '';
        nsFilter.style.display = namespaces.length > 6 ? '' : 'none';
        _restoreNsPrefs(namespaces);
      } catch (e) {
        loading.style.display = '';
        loading.style.color   = 'var(--danger)';
        loading.textContent   = 'Failed to load namespaces';
      }
    }

    // ── Namespace filter ──
    function filterNs(q) {
      const term = q.trim().toLowerCase();
      document.querySelectorAll('#ns-grid .ns-item').forEach(el => {
        el.style.display = el.dataset.ns.toLowerCase().includes(term) ? '' : 'none';
      });
    }

    // ── Namespace preference persistence ──
    const _NS_PREF_PREFIX = 'janus_ns_prefs_';
    function _nsPrefKey() {
      const email = document.getElementById('requester').value.trim().toLowerCase();
      return email ? _NS_PREF_PREFIX + email : null;
    }
    function _saveNsPrefs() {
      const key = _nsPrefKey();
      if (!key || !_currentCluster) return;
      localStorage.setItem(key, JSON.stringify({ cluster: _currentCluster, namespaces: [..._nsSelected] }));
    }
    function _restoreNsPrefs(availableNs) {
      const key = _nsPrefKey();
      if (!key) return;
      try {
        const saved = JSON.parse(localStorage.getItem(key) || 'null');
        if (!saved || saved.cluster !== _currentCluster) return;
        const avSet = new Set(availableNs);
        saved.namespaces.forEach(ns => {
          if (!avSet.has(ns)) return;
          _nsSelected.add(ns);
          const el = document.querySelector(`.ns-item[data-ns="${CSS.escape(ns)}"]`);
          if (el) el.classList.add('selected');
        });
        _updateSubmitState();
      } catch { /* ignore */ }
    }

    function toggleNs(ns, itemEl) {
      if (_nsSelected.has(ns)) {
        _nsSelected.delete(ns);
        itemEl.classList.remove('selected');
      } else {
        _nsSelected.add(ns);
        itemEl.classList.add('selected');
      }
      _saveNsPrefs();
      _updateSubmitState();
    }

    function _positionPopover(triggerEl) {
      const podPreview = document.getElementById('pod-preview');
      const rect = triggerEl.getBoundingClientRect();
      const pw = 260;
      let left = rect.right + 8;
      if (left + pw > window.innerWidth - 8) left = rect.left - pw - 8;
      podPreview.style.left = left + 'px';
      podPreview.style.top  = Math.min(rect.top, window.innerHeight - 200) + 'px';
    }

    let _previewTimer = null;
    async function previewPods(ns, triggerEl) {
      if (!_currentCluster) return;
      clearTimeout(_previewTimer);
      const podPreview = document.getElementById('pod-preview');
      const podList    = document.getElementById('pod-list');
      const label      = document.getElementById('pod-preview-label');

      label.textContent = ns;
      podList.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:4px;">Loading…</div>';
      podPreview.style.display = 'block';
      if (triggerEl) _positionPopover(triggerEl);

      try {
        const resp = await fetch('/api/pods/' + encodeURIComponent(_currentCluster) + '/' + encodeURIComponent(ns));
        const data = await resp.json();
        if (data.error || !data.pods.length) {
          podList.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:4px;">No pods</div>';
          return;
        }
        podList.innerHTML = data.pods.map(pod => {
          const sc = pod.status === 'Running' ? 'var(--success)' : 'var(--text-dim)';
          return `<div style="display:flex;align-items:center;gap:6px;padding:4px 6px;background:var(--surface-2);border-radius:4px;">
            <div style="width:5px;height:5px;border-radius:50%;background:${sc};flex-shrink:0;"></div>
            <div style="flex:1;font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${pod.name}</div>
            <div style="font-size:0.68rem;color:var(--text-dim);">${pod.ready}/${pod.total}</div>
          </div>`;
        }).join('');
      } catch (e) {
        podList.innerHTML = '<div style="color:var(--danger);font-size:0.75rem;padding:4px;">Failed</div>';
      }
    }

    function hidePreview() {
      _previewTimer = setTimeout(() => {
        document.getElementById('pod-preview').style.display = 'none';
      }, 150);
    }

    async function submitMultiRequest() {
      const requester = document.getElementById('requester').value.trim();
      const reason    = document.getElementById('reason').value.trim();
      const ttl_hours = parseInt(document.getElementById('ttl_hours').value, 10);

      if (!requester || !reason) { alert('Please fill in your email and reason.'); return; }
      if (!_currentCluster || !_nsSelected.size) { alert('Select a cluster and at least one namespace.'); return; }

      const targets = [..._nsSelected].map(ns => ({ cluster: _currentCluster, namespace: ns }));

      const btn      = document.getElementById('submit-btn');
      const statusEl = document.getElementById('submit-status');
      btn.disabled = true;
      statusEl.style.display = '';
      statusEl.textContent   = 'Submitting…';

      try {
        const resp = await fetch('/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requester, reason, ttl_hours, targets }),
        });
        const data = await resp.json();

        if (data.error) {
          statusEl.style.color = 'var(--danger)';
          statusEl.textContent = data.error;
          btn.disabled = false;
          return;
        }

        let msg = '';
        if (data.created.length) msg += `${data.created.length} request${data.created.length > 1 ? 's' : ''} submitted. `;
        if (data.skipped.length) msg += `${data.skipped.length} skipped. `;
        if (data.errors.length)  msg += `${data.errors.length} failed. `;

        statusEl.style.color = data.errors.length && !data.created.length ? 'var(--danger)' : 'var(--success)';
        statusEl.textContent = msg.trim();

        if (data.created.length) {
          setTimeout(() => {
            window.location.href = `/status/${encodeURIComponent(_currentCluster)}/${encodeURIComponent(data.created[0])}`;
          }, 600);
        } else { btn.disabled = false; }
      } catch (e) {
        statusEl.style.color = 'var(--danger)';
        statusEl.textContent = 'Network error. Please try again.';
        btn.disabled = false;
      }
    }

    // ── Request history (localStorage) ──
    const HISTORY_KEY_PREFIX = 'k8s_janus_history_';

    function historyKey() {
      const email = document.getElementById('requester').value.trim().toLowerCase();
      return email ? HISTORY_KEY_PREFIX + email : null;
    }

    function loadHistory() {
      const key = historyKey();
      if (!key) return [];
      try { return JSON.parse(localStorage.getItem(key) || '[]'); } catch { return []; }
    }

    function saveHistory(entries) {
      const key = historyKey();
      if (!key) return;
      localStorage.setItem(key, JSON.stringify(entries.slice(0, 50)));
    }

    function recordRequest(name, cluster, clusterDisplay, namespace, phase) {
      const entries = loadHistory();
      const idx = entries.findIndex(e => e.name === name && e.cluster === cluster);
      const entry = { name, cluster, clusterDisplay, namespace, phase, ts: new Date().toISOString() };
      if (idx >= 0) entries[idx] = entry; else entries.unshift(entry);
      saveHistory(entries);
    }

    // Collect live CRD names from the current table
    const _liveNames = new Set();
    document.querySelectorAll('tbody td a').forEach(a => {
      const parts = a.getAttribute('href').split('/');
      if (parts.length >= 4) _liveNames.add(parts[2] + '/' + parts[3]);
    });

    function renderHistory() {
      const entries = loadHistory();
      const card = document.getElementById('history-card');
      const list = document.getElementById('history-list');

      const past = entries.filter(e => !_liveNames.has(e.cluster + '/' + e.name));
      if (past.length === 0) { card.style.display = 'none'; return; }

      card.style.display = '';

      const phaseColors = {
        Active: '#a5b4fc', Approved: '#34d399', Pending: '#fbbf24',
        Denied: '#fca5a5', Expired: '#94a3b8', Revoked: '#fca5a5', Failed: '#fca5a5'
      };

      let html = '<div class="table-wrap"><table><thead><tr><th>ID</th><th>Cluster</th><th>Namespace</th><th>Last Status</th><th>Requested</th></tr></thead><tbody>';
      past.forEach(e => {
        const color = phaseColors[e.phase] || 'var(--text-dim)';
        const dt = new Date(e.ts);
        const dtStr = dt.toLocaleDateString() + ' ' + dt.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
        html += `<tr>
          <td><a href="/status/${e.cluster}/${e.name}" style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;">${e.name}</a></td>
          <td><code>${e.clusterDisplay || e.cluster}</code></td>
          <td><code>${e.namespace}</code></td>
          <td><span style="font-size:0.78rem;font-weight:600;color:${color};">${e.phase}</span></td>
          <td style="font-size:0.78rem;color:var(--text-dim);white-space:nowrap;">${dtStr}</td>
        </tr>`;
      });
      html += '</tbody></table></div>';
      list.innerHTML = html;
      lucide.createIcons();
    }

    function clearHistory() {
      const key = historyKey();
      if (key) localStorage.removeItem(key);
      document.getElementById('history-card').style.display = 'none';
    }

    // Record requests from PAGE_DATA into history (updates phase for known entries)
    (accessRequests || []).forEach(function(ar) {
      if (userEmail && ar.requester && userEmail.toLowerCase() === ar.requester.toLowerCase()) {
        recordRequest(ar.name, ar.cluster, ar.clusterDisplay, ar.namespace, ar.phase);
      }
    });

    renderHistory();
    document.getElementById('requester').addEventListener('change', renderHistory);
    document.getElementById('requester').addEventListener('blur', renderHistory);

    // ── Restore last cluster + namespace selection on page load ──
    (function() {
      const key = _nsPrefKey();
      if (!key) return;
      try {
        const saved = JSON.parse(localStorage.getItem(key) || 'null');
        if (!saved || !saved.cluster) return;
        const sel = document.getElementById('cluster');
        if (!sel) return;
        // Check if saved cluster exists in the options
        const opt = Array.from(sel.options).find(o => o.value === saved.cluster);
        if (!opt) return;
        sel.value = saved.cluster;
        onClusterChange(saved.cluster); // loads namespaces; _restoreNsPrefs called inside
      } catch { /* ignore */ }
    })();

    // ── Toast system ──
    function showToast(msg, type = 'info', duration = 5000) {
      const icons = { info: 'info', warning: 'alert-triangle', error: 'alert-circle', success: 'check-circle' };
      const colors = { info: 'var(--info)', warning: 'var(--warning)', error: 'var(--danger)', success: 'var(--success)' };
      const t = document.createElement('div');
      t.className = 'toast' + (type === 'warning' ? ' warning' : '');
      t.innerHTML = `<i data-lucide="${icons[type]||'info'}" style="width:15px;height:15px;color:${colors[type]||'var(--info)'};"></i><span>${msg}</span>`;
      document.getElementById('toast-container').appendChild(t);
      lucide.createIcons({ nodes: [t] });
      setTimeout(() => t.remove(), duration);
    }

    // ── Session expiry warning (OIDC only, 24h cookie) ──
    if (oidcEnabled) {
      (function() {
        const SESSION_MS = 24 * 60 * 60 * 1000;
        const WARN_MS    = 60 * 60 * 1000; // warn 1h before expiry
        const loginKey   = 'janus_login_ts';
        // Always reset on page load — stale localStorage from a previous session
        // would make remaining negative and trigger an immediate /logout.
        localStorage.setItem(loginKey, Date.now());
        function checkExpiry() {
          const elapsed = Date.now() - parseInt(localStorage.getItem(loginKey) || Date.now());
          const remaining = SESSION_MS - elapsed;
          if (remaining <= 0) { window.location = '/logout'; return; }
          if (remaining <= WARN_MS) {
            const mins = Math.ceil(remaining / 60000);
            document.getElementById('session-banner').style.display = 'flex';
            document.getElementById('session-countdown').textContent = mins + ' minute' + (mins !== 1 ? 's' : '');
            lucide.createIcons({ nodes: [document.getElementById('session-banner')] });
          }
        }
        checkExpiry();
        setInterval(checkExpiry, 60000);
      })();
    }
