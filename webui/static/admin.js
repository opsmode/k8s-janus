// admin.js — extracted from admin.html
// All Jinja2 variables are passed via window.PAGE_DATA (set inline in the template).
const { clustersCount, approvalTtlOptions, userEmail, oidcEnabled } = window.PAGE_DATA;

    lucide.createIcons();

    // ── Setup card toggle (previously a tiny inline script) ──
    (function() {
      var body = document.getElementById('setup-body');
      var chevron = document.getElementById('setup-chevron');
      var hasclusters = clustersCount > 0;
      if (hasclusters) {
        body.style.display = 'none';
        chevron.style.transform = 'rotate(-90deg)';
      }
      window.toggleSetupCard = function() {
        var open = body.style.display !== 'none';
        body.style.display = open ? 'none' : '';
        chevron.style.transform = open ? 'rotate(-90deg)' : '';
      };
    })();

    // ── Refresh button ──
    function refreshPage() {
      var btn = document.getElementById('refresh-btn');
      btn.classList.add('spinning');
      btn.disabled = true;
      location.reload();
    }


    // ── TTL countdown ──
    function updateTtlRemaining() {
      document.querySelectorAll('.ttl-remaining').forEach(el => {
        var expires = new Date(el.dataset.expires);
        var diff = Math.floor((expires - Date.now()) / 1000);
        if (diff <= 0) {
          el.textContent = 'Expired';
          el.style.color = 'var(--danger)';
        } else {
          var h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60), s = diff % 60;
          el.textContent = h > 0 ? h + 'h ' + m + 'm left' : m + 'm ' + s + 's left';
          el.style.color = diff < 300 ? 'var(--danger)' : diff < 900 ? 'var(--warning)' : 'var(--success)';
        }
      });
    }
    setInterval(updateTtlRemaining, 1000);
    updateTtlRemaining();

    // ── Pagination + filter state ──
    var _allRows = [];
    var _filteredRows = [];
    var _currentPage = 1;
    var _perPage = 25;
    var _openDetail = null; // name of currently open detail row

    function _getAllRows() {
      return Array.from(document.querySelectorAll('#requests-tbody tr.req-row'));
    }

    function applyFilters() {
      _allRows = _getAllRows();
      var text    = document.getElementById('filter-text').value.toLowerCase().trim();
      var cluster = document.getElementById('filter-cluster').value;
      var phase   = document.getElementById('filter-phase').value;

      _filteredRows = _allRows.filter(function(row) {
        return (!text    || row.dataset.requester.includes(text) || row.dataset.namespace.includes(text) || row.dataset.name.toLowerCase().includes(text)) &&
               (!cluster || row.dataset.cluster === cluster) &&
               (!phase   || row.dataset.phase === phase);
      });

      _currentPage = 1;
      closeDetail();
      renderPage();
    }

    function renderPage() {
      var total = _filteredRows.length;
      var totalPages = Math.max(1, Math.ceil(total / _perPage));
      if (_currentPage > totalPages) _currentPage = totalPages;

      var start = (_currentPage - 1) * _perPage;
      var end   = Math.min(start + _perPage, total);

      // Hide all, show only page slice
      _allRows.forEach(function(r) { r.style.display = 'none'; });
      _filteredRows.forEach(function(r, i) {
        r.style.display = (i >= start && i < end) ? '' : 'none';
      });

      // Count text
      document.getElementById('count-text').textContent = total + ' request' + (total !== 1 ? 's' : '');

      // No results
      document.getElementById('no-results').style.display = total === 0 ? 'block' : 'none';

      // Pagination info
      document.getElementById('pg-info-text').textContent = total === 0 ? '' :
        'Showing ' + (start + 1) + '–' + end + ' of ' + total;

      // Pagination buttons
      var pgPages = document.getElementById('pg-pages');
      pgPages.innerHTML = '';
      if (totalPages <= 1) { document.getElementById('pagination-bar').style.display = 'none'; return; }
      document.getElementById('pagination-bar').style.display = 'flex';

      function mkBtn(label, page, isActive, isDisabled) {
        var b = document.createElement('button');
        b.className = 'pg-btn' + (isActive ? ' active' : '');
        b.textContent = label;
        b.disabled = isDisabled;
        if (!isDisabled) b.onclick = function() { _currentPage = page; closeDetail(); renderPage(); };
        return b;
      }

      pgPages.appendChild(mkBtn('‹', _currentPage - 1, false, _currentPage === 1));
      // Show window of pages
      var winStart = Math.max(1, _currentPage - 2);
      var winEnd   = Math.min(totalPages, _currentPage + 2);
      if (winStart > 1) { pgPages.appendChild(mkBtn('1', 1, false, false)); if (winStart > 2) { var e = document.createElement('span'); e.textContent = '…'; e.style.cssText = 'padding:0 4px;color:var(--text-dim);'; pgPages.appendChild(e); } }
      for (var p = winStart; p <= winEnd; p++) { pgPages.appendChild(mkBtn(p, p, p === _currentPage, p === _currentPage)); }
      if (winEnd < totalPages) { if (winEnd < totalPages - 1) { var e2 = document.createElement('span'); e2.textContent = '…'; e2.style.cssText = 'padding:0 4px;color:var(--text-dim);'; pgPages.appendChild(e2); } pgPages.appendChild(mkBtn(totalPages, totalPages, false, false)); }
      pgPages.appendChild(mkBtn('›', _currentPage + 1, false, _currentPage === totalPages));
    }

    function setPerPage(val) {
      _perPage = parseInt(val);
      _currentPage = 1;
      closeDetail();
      renderPage();
    }

    // ── Detail panel ──
    function toggleDetailBtn(btn) {
      var row = btn.closest('tr.req-row');
      var d = row.dataset;
      // Prefer embedded script tags (Jinja-rendered rows); fall back to button dataset (poll-inserted rows)
      var nssEl = document.getElementById('ns-' + d.name);
      var reasonEl = document.getElementById('reason-' + d.name);
      var nss = nssEl ? JSON.parse(nssEl.textContent || '[]') : JSON.parse(btn.dataset.namespaces || '[]');
      var reason = reasonEl ? JSON.parse(reasonEl.textContent || '""') : (btn.dataset.reason || '');
      toggleDetail(d.name, d.cluster, d.clusterDisplay, d.requester, nss, d.phase, d.ttl, d.expires, reason, d.approvedBy, btn);
    }

    var APPROVAL_TTL_OPTIONS = approvalTtlOptions;

    function _fmtSecs(s) {
      s = parseInt(s);
      var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
      return h && m ? h+'h '+m+'m' : h ? h+'h' : m+'m';
    }

    function _buildTtlSelect(name) {
      var opts = '<option value="">keep TTL</option>';
      APPROVAL_TTL_OPTIONS.forEach(function(s) { opts += '<option value="'+s+'">'+_fmtSecs(s)+'</option>'; });
      return '<select id="approve-ttl-'+name+'" style="font-size:0.72rem;background:var(--surface-2,#1e293b);border:1px solid var(--border,#334155);color:var(--text-muted,#94a3b8);border-radius:4px;padding:2px 6px;cursor:pointer;" title="TTL override (optional)">'+opts+'</select>';
    }

    function closeDetail() {
      if (_openDetail) {
        var existing = document.getElementById('detail-row-' + _openDetail);
        if (existing) existing.remove();
        var btn = document.getElementById('detail-btn-' + _openDetail);
        if (btn) {
          btn.classList.remove('open');
          var icon = btn.querySelector('i');
          if (icon) icon.style.transform = '';
        }
        _openDetail = null;
      }
    }

    function toggleDetail(name, cluster, clusterDisplay, requester, namespaces, phase, ttl, expiresAt, reason, approvedBy, btn) {
      // Close if already open
      if (_openDetail === name) { closeDetail(); return; }
      closeDetail();
      _openDetail = name;

      btn.classList.add('open');
      var icon = btn.querySelector('i');
      if (icon) icon.style.transform = 'rotate(180deg)';

      // Build actions HTML
      var actionsHtml = '';
      if (phase === 'Pending') {
        actionsHtml =
          '<div class="action-cell" id="actions-'+name+'">'
          +'<div class="extend-wrap" style="display:flex;align-items:center;gap:4px;">'
          +'<button class="action-btn approve-btn" onclick="inlineApprove(\''+cluster+'\',\''+name+'\',this)">'
          +'<i data-lucide="check" style="width:12px;height:12px;"></i> Approve</button>'
          +_buildTtlSelect(name)
          +'</div>'
          +'<button class="action-btn deny-btn" onclick="inlineDeny(\''+cluster+'\',\''+name+'\',this)">'
          +'<i data-lucide="x" style="width:12px;height:12px;"></i> Deny</button>'
          +'</div>';
      } else if (phase === 'Active' || phase === 'Approved') {
        actionsHtml = '<div class="action-cell" id="actions-'+name+'">';
        if (phase === 'Active') {
          // Show terminal link if this is admin's own request
          var currentUser = userEmail;
          if (requester.toLowerCase() === currentUser.toLowerCase()) {
            actionsHtml +=
              '<a href="/terminal/'+cluster+'/'+name+'" class="action-btn terminal-btn" '
              +'style="background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;text-decoration:none;">'
              +'<i data-lucide="terminal" style="width:12px;height:12px;"></i> Terminal</a>';
          }
          actionsHtml +=
            '<div class="extend-wrap" id="extend-wrap-'+name+'">'
            +'<button class="action-btn extend-btn" onclick="toggleExtend(\''+name+'\',\''+cluster+'\',event)">'
            +'<i data-lucide="clock-4" style="width:12px;height:12px;"></i> Extend</button>'
            +'<div class="extend-menu" id="extend-menu-'+name+'">'
            +'<button onclick="doExtend(\''+name+'\',\''+cluster+'\',3600,this)">+1h</button>'
            +'<button onclick="doExtend(\''+name+'\',\''+cluster+'\',7200,this)">+2h</button>'
            +'<button onclick="doExtend(\''+name+'\',\''+cluster+'\',14400,this)">+4h</button>'
            +'<button onclick="doExtend(\''+name+'\',\''+cluster+'\',28800,this)">+8h</button>'
            +'</div></div>';
        }
        actionsHtml +=
          '<button class="action-btn revoke-btn" onclick="inlineRevoke(\''+cluster+'\',\''+name+'\',\''+requester+'\')">'
          +'<i data-lucide="shield-off" style="width:12px;height:12px;"></i> Revoke</button>'
          +'</div>';
      }

      // Namespaces chips
      var nsHtml = namespaces.map(function(n) { return '<span class="ns-chip">'+n+'</span>'; }).join('');

      // TTL display — only show live countdown for Active phase
      var ttlStr = (phase === 'Active' && expiresAt)
        ? '<span class="ttl-remaining" data-expires="'+expiresAt+'" data-phase="Active">…</span>'
        : _fmtSecs(ttl);

      var panelHtml =
        '<div class="detail-panel">'
        +'<div class="detail-section"><span class="detail-label">Request ID</span>'
        +'<span class="detail-value"><a href="/status/'+cluster+'/'+name+'" style="color:var(--accent);font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;">'+name+'</a></span></div>'
        +'<div class="detail-section"><span class="detail-label">Requester</span><span class="detail-value" style="display:flex;align-items:center;gap:8px;"><div class="avatar" data-email="'+requester.toLowerCase()+'" style="width:22px;height:22px;font-size:0.55rem;flex-shrink:0;cursor:default;"></div><span>'+requester+'</span></span></div>'
        +'<div class="detail-section"><span class="detail-label">Cluster</span>'
        +'<span class="detail-value"><code style="color:#fb923c;background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.25);">'+clusterDisplay+'</code></span></div>'
        +'<div class="detail-section" style="grid-column:1/-1;"><span class="detail-label">Namespaces ('+namespaces.length+')</span>'
        +'<div style="margin-top:4px;">'+nsHtml+'</div></div>'
        +(reason ? '<div class="detail-section" style="grid-column:1/-1;"><span class="detail-label">Reason</span><span class="detail-value" style="font-style:italic;">'+reason+'</span></div>' : '')
        +'<div class="detail-section"><span class="detail-label">TTL / Remaining</span><span class="detail-value" id="detail-ttl-'+name+'">'+ttlStr+'</span></div>'
        +(approvedBy ? '<div class="detail-section"><span class="detail-label">Approved by</span><span class="detail-value" style="display:flex;align-items:center;gap:8px;"><div class="avatar" data-email="'+approvedBy.toLowerCase()+'" style="width:22px;height:22px;font-size:0.55rem;flex-shrink:0;cursor:default;"></div><span data-approver-email="'+approvedBy.toLowerCase()+'">'+approvedBy+'</span></span></div>' : '')
        +(actionsHtml ? '<div class="detail-actions">'+actionsHtml+'</div>' : '')
        +'</div>';

      // Insert after the row
      var row = document.querySelector('tr.req-row[data-name="'+name+'"]');
      var detailRow = document.createElement('tr');
      detailRow.id = 'detail-row-' + name;
      detailRow.className = 'detail-row';
      detailRow.innerHTML = '<td colspan="6">'+panelHtml+'</td>';
      row.insertAdjacentElement('afterend', detailRow);

      lucide.createIcons({ nodes: [detailRow] });
      updateTtlRemaining();
      // Load avatars + names for the newly injected detail panel avatars
      if (typeof _loadPeerAvatars === 'function') _loadPeerAvatars();
    }

    // ── Quick inline actions (from row buttons) ──
    async function quickApprove(cluster, name, btn) {
      btn.disabled = true; btn.textContent = '…';
      try {
        var resp = await fetch('/approve/' + cluster + '/' + name, {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}',
        });
        var data = await _jsonOrErr(resp);
        if (data.ok) {
          _setRowPhase(name, 'Approved');
          _removeQuickBtns(name);
        } else { _showBanner('Approve failed: ' + (data.error || 'unknown'), 'error'); btn.disabled = false; btn.textContent = 'Approve'; }
      } catch(e) { _showBanner('Approve failed: ' + e, 'error'); btn.disabled = false; btn.textContent = 'Approve'; }
    }

    async function quickDeny(cluster, name, btn) {
      var reason = prompt('Denial reason (optional):');
      if (reason === null) return;
      btn.disabled = true; btn.textContent = '…';
      try {
        var body = new FormData(); body.append('denial_reason', reason || '');
        var resp = await fetch('/deny/' + cluster + '/' + name, { method: 'POST', body: body });
        var data = await _jsonOrErr(resp);
        if (data.ok) { _setRowPhase(name, 'Denied'); _removeQuickBtns(name); }
        else { _showBanner('Deny failed: ' + (data.error || 'unknown'), 'error'); btn.disabled = false; btn.textContent = 'Deny'; }
      } catch(e) { _showBanner('Deny failed: ' + e, 'error'); btn.disabled = false; btn.textContent = 'Deny'; }
    }

    async function quickRevoke(cluster, name, requester, btn) {
      if (!confirm('Revoke access for ' + requester + '?')) return;
      btn.disabled = true; btn.textContent = '…';
      try {
        var resp = await fetch('/revoke/' + cluster + '/' + name, { method: 'POST', headers: {'Accept': 'application/json'} });
        var data = await _jsonOrErr(resp);
        if (data.ok) { _setRowPhase(name, 'Revoked'); _removeQuickBtns(name); }
        else { _showBanner('Revoke failed: ' + (data.error || 'unknown'), 'error'); btn.disabled = false; btn.textContent = 'Revoke'; }
      } catch(e) { _showBanner('Revoke failed: ' + e, 'error'); btn.disabled = false; btn.textContent = 'Revoke'; }
    }

    function _removeQuickBtns(name) {
      var row = document.querySelector('tr.req-row[data-name="'+name+'"]');
      if (!row) return;
      row.querySelectorAll('.approve-btn, .deny-btn, .revoke-btn').forEach(function(b) { b.remove(); });
    }

    // ── Initial render ──
    _allRows = _getAllRows();
    _filteredRows = _allRows.slice();
    renderPage();

    // ── Inline approve/deny ──
    function _setRowPhase(name, phase) {
      var row = document.querySelector('tr.req-row[data-name="'+name+'"]');
      if (!row) return;
      // Update badge
      var badge = row.querySelector('.badge');
      if (badge) {
        badge.className = 'badge badge-' + phase.toLowerCase();
        badge.innerHTML = '<span class="badge-dot"></span>' + phase;
      }
      row.dataset.phase = phase;
      // Update filter array
      _filteredRows = _getAllRows().filter(function(r) {
        var text    = document.getElementById('filter-text').value.toLowerCase().trim();
        var cluster = document.getElementById('filter-cluster').value;
        var ph      = document.getElementById('filter-phase').value;
        return (!text    || r.dataset.requester.includes(text) || r.dataset.namespace.includes(text) || r.dataset.name.toLowerCase().includes(text)) &&
               (!cluster || r.dataset.cluster === cluster) &&
               (!ph      || r.dataset.phase === ph);
      });
      _allRows = _getAllRows();
      // Close and reopen detail with updated phase
      var openName = _openDetail;
      closeDetail();
      if (openName === name) {
        var btn = document.getElementById('detail-btn-' + name);
        if (btn) setTimeout(function() { toggleDetailBtn(btn); }, 50);
      }
    }

    async function inlineRevoke(cluster, name, requester) {
      if (!confirm('Revoke access for ' + requester + '?')) return;
      var cell = document.getElementById('actions-' + name);
      if (cell) _lockActionCell(cell, 'Revoking…');
      try {
        var resp = await fetch('/revoke/' + cluster + '/' + name, {
          method: 'POST',
          headers: {'Accept': 'application/json'},
        });
        var data = await _jsonOrErr(resp);
        if (data.ok) {
          _setRowPhase(name, 'Revoked');
        } else {
          _showBanner('Revoke failed: ' + (data.error || 'unknown error'), 'error');
          closeDetail();
        }
      } catch(e) {
        _showBanner('Revoke failed: ' + e, 'error');
        closeDetail();
      }
    }

    function _lockActionCell(cell, label) {
      cell.innerHTML = `<span style="font-size:0.75rem;color:var(--text-dim);display:flex;align-items:center;gap:5px;">
        <i data-lucide="loader" style="width:12px;height:12px;animation:spin 0.8s linear infinite;"></i>${label}
      </span>`;
      lucide.createIcons();
    }

    async function _jsonOrErr(resp) {
      var ct = resp.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        var text = await resp.text();
        throw new Error('HTTP ' + resp.status + ' (non-JSON response)');
      }
      return resp.json();
    }

    async function inlineApprove(cluster, name, btn) {
      var ttlSel = document.getElementById('approve-ttl-' + name);
      var body = {};
      if (ttlSel && ttlSel.value) body.ttl_seconds = parseInt(ttlSel.value);
      var cell = document.getElementById('actions-' + name);
      _lockActionCell(cell, 'Approving…');
      try {
        var resp = await fetch('/approve/' + cluster + '/' + name, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(body),
        });
        var data = await _jsonOrErr(resp);
        if (data.ok) {
          // Update row data attributes so detail re-open shows correct TTL
          var row = document.querySelector('tr.req-row[data-name="'+name+'"]');
          if (row && data.ttlSeconds) row.dataset.ttl = data.ttlSeconds;
          if (row && data.expiresAt)  row.dataset.expires = data.expiresAt;
          _setRowPhase(name, 'Approved');
        } else {
          _showBanner('Approve failed: ' + (data.error || 'unknown error'), 'error');
          closeDetail();
        }
      } catch(e) {
        _showBanner('Approve failed: ' + e, 'error');
        closeDetail();
      }
    }

    async function inlineDeny(cluster, name, btn) {
      var reason = prompt('Denial reason (optional):');
      if (reason === null) return; // cancelled
      var cell = document.getElementById('actions-' + name);
      _lockActionCell(cell, 'Denying…');
      try {
        var body = new FormData();
        body.append('denial_reason', reason || '');
        var resp = await fetch('/deny/' + cluster + '/' + name, { method: 'POST', body: body });
        var data = await _jsonOrErr(resp);
        if (data.ok) {
          _setRowPhase(name, 'Denied');
        } else {
          _showBanner('Deny failed: ' + (data.error || 'unknown error'), 'error');
          closeDetail();
        }
      } catch(e) {
        _showBanner('Deny failed: ' + e, 'error');
        closeDetail();
      }
    }

    // ── TTL extend ──
    var _extendOpen = null;

    function toggleExtend(name, cluster, event) {
      event.stopPropagation();
      var menu = document.getElementById('extend-menu-' + name);
      if (_extendOpen && _extendOpen !== menu) {
        _extendOpen.classList.remove('open');
      }
      menu.classList.toggle('open');
      _extendOpen = menu.classList.contains('open') ? menu : null;
    }

    document.addEventListener('click', function() {
      if (_extendOpen) { _extendOpen.classList.remove('open'); _extendOpen = null; }
    });

    async function doExtend(name, cluster, seconds, btn) {
      if (_extendOpen) { _extendOpen.classList.remove('open'); _extendOpen = null; }
      btn.disabled = true;
      btn.textContent = '…';
      try {
        var resp = await fetch('/extend/' + cluster + '/' + name, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({seconds: seconds}),
        });
        var data = await resp.json();
        if (data.ok) {
          // Update the TTL display cell for this row
          var rows = document.querySelectorAll('tr.req-row');
          for (var r of rows) {
            var link = r.querySelector('a');
            if (link && link.textContent.trim() === name) {
              var ttlEl = r.querySelector('.ttl-remaining');
              if (ttlEl && data.expiresAt) { ttlEl.dataset.expires = data.expiresAt; }
              break;
            }
          }
          _showBanner('TTL extended for ' + name, 'success');
        } else {
          _showBanner('Extend failed: ' + (data.error || 'unknown'), 'error');
        }
      } catch(e) {
        _showBanner('Extend failed: ' + e, 'error');
      }
    }

    function _showBanner(msg, type) {
      var el = document.createElement('div');
      el.style.cssText = 'position:fixed;top:90px;right:24px;z-index:999;padding:10px 16px;border-radius:8px;font-size:0.82rem;font-weight:500;' +
        (type === 'success'
          ? 'background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.4);color:#34d399;'
          : 'background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.4);color:#f87171;');
      el.textContent = msg;
      document.body.appendChild(el);
      setTimeout(function() { el.remove(); }, 3500);
    }

    // ── Audit log ──
    var _EVENT_CLASS = {
      'request.created': 'created',
      'request.approved': 'approved',
      'access.granted': 'granted',
      'request.denied': 'denied',
      'access.revoked': 'revoked',
      'access.expired': 'expired',
      'access.extended': 'approved',
      'crd.deleted': 'deleted',
    };

    function _fmtTs(iso) {
      if (!iso) return '—';
      try {
        return new Date(iso).toLocaleString(undefined, {
          year: 'numeric', month: '2-digit', day: '2-digit',
          hour: '2-digit', minute: '2-digit', second: '2-digit',
        });
      } catch(e) { return iso.slice(0, 19).replace('T', ' '); }
    }

    var _auditRows = [];

    function _auditRowHtml(r) {
      var cls = _EVENT_CLASS[r.event] || '';
      return '<tr>' +
        '<td style="white-space:nowrap;font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;">' + _fmtTs(r.timestamp) + '</td>' +
        '<td><span class="audit-event ' + cls + '">' + (r.event || '—') + '</span></td>' +
        '<td style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:#a5b4fc;">' + (r.request_name || '—') + '</td>' +
        '<td style="font-size:0.8rem;">' + (r.actor || '—') + '</td>' +
        '<td style="font-size:0.8rem;color:var(--text-dim);">' + (r.detail || '') + '</td>' +
        '</tr>';
    }

    async function loadAuditLog() {
      var statusEl = document.getElementById('audit-status');
      var tbody = document.getElementById('audit-tbody');
      try {
        var resp = await fetch('/api/audit');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        _auditRows = await resp.json();
        if (!_auditRows.length) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:24px;">No audit entries yet (DB not enabled or no events recorded)</td></tr>';
          statusEl.textContent = '';
          return;
        }
        var preview = _auditRows.slice(0, 5);
        tbody.innerHTML = preview.map(_auditRowHtml).join('');
        statusEl.textContent = '5 of ' + _auditRows.length;
        if (_auditRows.length > 5) {
          document.getElementById('audit-more-count').textContent = _auditRows.length;
          document.getElementById('audit-more-row').style.display = '';
        }
      } catch(e) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:24px;">Could not load audit log</td></tr>';
        statusEl.textContent = '';
      }
    }

    function openAuditModal() {
      document.getElementById('audit-modal-tbody').innerHTML = _auditRows.map(_auditRowHtml).join('');
      document.getElementById('audit-modal-count').textContent = _auditRows.length + ' entries';
      document.getElementById('audit-modal-backdrop').classList.add('open');
      lucide.createIcons({ nodes: [document.getElementById('audit-modal')] });
    }

    function closeAuditModal() {
      document.getElementById('audit-modal-backdrop').classList.remove('open');
    }

    // Requests table is now inline — modal functions are no-ops
    function openRequestsModal() {}
    function closeRequestsModal() {}

    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') { closeAuditModal(); }
    });

    loadAuditLog();

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

    // ── Session expiry warning ──
    if (oidcEnabled) {
      (function() {
        const SESSION_MS = 24 * 60 * 60 * 1000;
        const WARN_MS    = 60 * 60 * 1000;
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

    // ── Auto-refresh: inject new rows ──
    (function() {
      function _insertRow(r) {
        var tbody = document.getElementById('requests-tbody');
        var tr = document.createElement('tr');
        tr.className = 'req-row';
        tr.dataset.name           = r.name;
        tr.dataset.requester      = r.requester.toLowerCase();
        tr.dataset.namespace      = (r.namespaces || []).join(' ').toLowerCase();
        tr.dataset.cluster        = r.cluster;
        tr.dataset.clusterDisplay = r.clusterDisplay;
        tr.dataset.phase          = r.phase;
        tr.dataset.ttl            = r.ttlSeconds;
        tr.dataset.expires        = r.expiresAt || '';
        tr.dataset.approvedBy     = r.approvedBy || '';
        tr.dataset.ts             = r.createdAt;
        var ttlStr = _fmtSecs(r.ttlSeconds);
        var clust = '<code style="color:#fb923c;font-weight:600;background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.25);">'+r.clusterDisplay+'</code>';
        var badge = '<span class="badge badge-'+r.phase.toLowerCase()+'"><span class="badge-dot"></span>'+r.phase+'</span>';
        var nsArr = r.namespaces || [];
        tr.innerHTML =
          '<td style="max-width:0;overflow:hidden;">'
          +'<div style="display:flex;flex-direction:column;gap:1px;overflow:hidden;">'
          +'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">'+r.name+'</span>'
          +'<span style="font-size:0.78rem;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">'+r.requester+'</span>'
          +'</div></td>'
          +'<td style="white-space:nowrap;">'+clust+'</td>'
          +'<td style="white-space:nowrap;">'+ttlStr+'</td>'
          +'<td>'+badge+'</td>'
          +'<td style="white-space:nowrap;font-size:0.78rem;">'+r.createdAt+'</td>'
          +'<td></td>';
        // Build detail button via DOM API to avoid any quoting issues with namespaces/reason
        var detailBtn = document.createElement('button');
        detailBtn.className = 'detail-btn';
        detailBtn.id = 'detail-btn-' + r.name;
        // Store ns/reason directly on button dataset (toggleDetailBtn falls back to these)
        detailBtn.dataset.namespaces = JSON.stringify(nsArr);
        detailBtn.dataset.reason = r.reason || '';
        detailBtn.setAttribute('onclick', 'toggleDetailBtn(this)');
        detailBtn.innerHTML = '<i data-lucide="chevron-down" style="width:11px;height:11px;transition:transform 0.2s;"></i> Details';
        tr.lastElementChild.appendChild(detailBtn);
        tbody.insertBefore(tr, tbody.firstChild);
        lucide.createIcons({ nodes: [tr] });
        _allRows = _getAllRows();
        _filteredRows = _allRows.filter(function(row) {
          var text    = document.getElementById('filter-text').value.toLowerCase().trim();
          var cluster = document.getElementById('filter-cluster').value;
          var phase   = document.getElementById('filter-phase').value;
          return (!text    || row.dataset.requester.includes(text) || row.dataset.namespace.includes(text) || row.dataset.name.toLowerCase().includes(text)) &&
                 (!cluster || row.dataset.cluster === cluster) &&
                 (!phase   || row.dataset.phase === phase);
        });
        renderPage();
      }

      function pollRequests() {
        fetch('/api/requests')
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (!d.requests) return;
            var existingMap = {};
            document.querySelectorAll('#requests-tbody tr.req-row').forEach(function(tr) {
              existingMap[tr.dataset.name] = tr;
            });
            d.requests.forEach(function(r) {
              var tr = existingMap[r.name];
              if (!tr) {
                // New request — insert row
                _insertRow(r);
              } else if (tr.dataset.phase !== r.phase) {
                // Phase changed — update badge and dataset without closing detail
                tr.dataset.phase = r.phase;
                var badge = tr.querySelector('.badge');
                if (badge) {
                  badge.className = 'badge badge-' + r.phase.toLowerCase();
                  badge.innerHTML = '<span class="badge-dot"></span>' + r.phase;
                }
                // If detail panel is open for this row, refresh it
                if (_openDetail === r.name) {
                  var btn = document.getElementById('detail-btn-' + r.name);
                  if (btn) { closeDetail(); setTimeout(function() { toggleDetailBtn(btn); }, 50); }
                }
                // Re-apply filters
                _allRows = _getAllRows();
                var text    = document.getElementById('filter-text').value.toLowerCase().trim();
                var cluster = document.getElementById('filter-cluster').value;
                var phase   = document.getElementById('filter-phase').value;
                _filteredRows = _allRows.filter(function(row) {
                  return (!text    || row.dataset.requester.includes(text) || row.dataset.namespace.includes(text) || row.dataset.name.toLowerCase().includes(text)) &&
                         (!cluster || row.dataset.cluster === cluster) &&
                         (!phase   || row.dataset.phase === phase);
                });
                renderPage();
              }
            });
          })
          .catch(function() {})
          .finally(function() { setTimeout(pollRequests, 6000); });
      }
      setTimeout(pollRequests, 6000);
    })();
