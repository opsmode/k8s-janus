lucide.createIcons();

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let _sessionId     = null;
let _kubeconfig    = null;
let _ws            = null;
let _setupHadError = false;

// ---------------------------------------------------------------------------
// Panel management
// ---------------------------------------------------------------------------
const PANELS = ['upload', 'select', 'progress', 'complete'];

function showPanel(name) {
  PANELS.forEach(p => {
    document.getElementById(`panel-${p}`).classList.toggle('hidden', p !== name);
  });
  const stepIdx = PANELS.indexOf(name);
  document.querySelectorAll('.wizard-step').forEach((el, i) => {
    el.classList.toggle('active', i === stepIdx);
    el.classList.toggle('done',   i < stepIdx);
  });
  lucide.createIcons();
}

// ---------------------------------------------------------------------------
// No-kubectl collapsible section
// ---------------------------------------------------------------------------
function toggleNoKubectl() {
  const body    = document.getElementById('no-kubectl-body');
  const chevron = document.getElementById('kubectl-chevron');
  const hidden  = body.classList.toggle('hidden');
  chevron.classList.toggle('open', !hidden);
}

let _activeOs = 'linux';
function showOs(os) {
  ['linux', 'win', 'cloud'].forEach(id => {
    document.getElementById(`os-${id}`).classList.toggle('hidden', id !== os);
  });
  document.querySelectorAll('.os-tab').forEach((btn, i) => {
    btn.classList.toggle('active', ['linux','win','cloud'][i] === os);
  });
  _activeOs = os;
}

function copyCmd(id) {
  const el = document.getElementById(id);
  if (!el) return;
  // Clone and strip comment spans so only commands are copied
  const clone = el.cloneNode(true);
  clone.querySelectorAll('.cmt').forEach(n => n.remove());
  const text = clone.innerText.trim();
  const btn = el.closest('.cmd-block')?.querySelector('.copy-btn');

  const done = () => {
    if (btn) { btn.textContent = 'copied!'; setTimeout(() => btn.textContent = 'copy', 1500); }
  };

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}

function fallbackCopy(text, cb) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); cb(); } catch {}
  document.body.removeChild(ta);
}

// ---------------------------------------------------------------------------
// Panel 1 — Upload
// ---------------------------------------------------------------------------
const dropZone  = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) handleFile(fileInput.files[0]); });

async function handleFile(file) {
  if (file.size > 1024 * 1024) {
    showError('upload', 'File too large (max 1 MB). Is this really a kubeconfig?');
    return;
  }
  dropZone.innerHTML = `<div class="spinner"></div><p style="margin-top:12px;color:var(--text-muted)">Parsing ${escHtml(file.name)}…</p>`;

  const formData = new FormData();
  formData.append('kubeconfig', file);

  try {
    const resp = await fetch('/setup/upload', { method: 'POST', body: formData });
    const data = await resp.json();
    if (data.error) { resetDropZone(); showError('upload', data.error); return; }
    _sessionId  = data.session_id;
    _kubeconfig = data.contexts;
    populateContextSelectors(data.contexts);
    showPanel('select');
  } catch (err) {
    resetDropZone();
    showError('upload', `Upload failed: ${err.message}`);
  }
}

function resetDropZone() {
  dropZone.innerHTML = `
    <i data-lucide="file-key" width="44" height="44"></i>
    <p>Drop your kubeconfig here</p>
    <span class="dz-sub">~/.kube/config · .yaml · .yml · any filename</span>
    <div class="drop-zone-hint">
      🍎 <strong>macOS:</strong> press <kbd style="background:var(--surface-3);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:0.7rem">⇧⌘.</kbd> in the file picker to show hidden folders like <code>.kube</code><br><br>
      ⚠️ <strong>GKE / EKS / AKS?</strong> Use the upload helper — starts port-forward, resolves auth &amp; uploads automatically:
      <div class="cmd-block" style="margin-top:6px;white-space:normal">
        <button class="copy-btn" data-cmd-id="cmd-upload-helper-r">copy</button>
        <span id="cmd-upload-helper-r">curl -fsSL https://raw.githubusercontent.com/infroware/k8s-janus/main/webui/setup-upload.sh | bash</span>
      </div>
    </div>
  `;
  lucide.createIcons();
}

// ---------------------------------------------------------------------------
// Panel 2 — Select contexts
// ---------------------------------------------------------------------------
function populateContextSelectors(contexts) {
  const centralList = document.getElementById('central-list');
  const remoteList  = document.getElementById('remote-list');
  centralList.innerHTML = '';
  remoteList.innerHTML  = '';

  contexts.forEach(ctx => {
    const cItem = document.createElement('label');
    cItem.className = 'context-item';
    cItem.className = 'context-item central-sel';
    cItem.innerHTML = `
      <input type="radio" name="central" value="${escHtml(ctx.name)}">
      <div style="flex:1;min-width:0">
        <div class="context-name">${escHtml(ctx.name)}</div>
        <div class="context-cluster">${escHtml(ctx.cluster)}</div>
      </div>
    `;
    cItem.querySelector('input').addEventListener('change', onCentralChange);
    centralList.appendChild(cItem);
  });

  onCentralChange();
}

function onCentralChange() {
  const central   = document.querySelector('input[name="central"]:checked')?.value;
  const remoteList = document.getElementById('remote-list');
  const noRemotes  = document.getElementById('no-remotes');
  const btnStart   = document.getElementById('btn-start');
  const centralNameRow = document.getElementById('central-name-row');

  document.querySelectorAll('#central-list .context-item').forEach(item => {
    item.classList.toggle('selected', item.querySelector('input').checked);
  });
  btnStart.disabled = false;
  if (centralNameRow) {
    centralNameRow.style.display = central ? 'flex' : 'none';
    if (central) {
      const slugInput    = document.getElementById('central-cluster-name');
      const displayInput = document.getElementById('central-display-name');
      const defaultSlug  = central.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 52);
      if (slugInput && !slugInput._userEdited)    { slugInput.value    = defaultSlug; slugInput.style.borderColor = 'var(--accent)'; }
      if (displayInput && !displayInput._userEdited) { displayInput.value = central; }
    }
  }

  remoteList.innerHTML = '';
  const others = (_kubeconfig || []).filter(c => c.name !== central);

  if (others.length === 0) {
    noRemotes.classList.remove('hidden');
    remoteList.classList.add('hidden');
  } else {
    noRemotes.classList.add('hidden');
    remoteList.classList.remove('hidden');
    others.forEach((ctx) => {
      const defaultSlug = ctx.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 52);
      const rItem = document.createElement('div');
      rItem.className = 'context-item remote-sel';

      rItem.innerHTML = `
        <input type="checkbox" name="remote" value="${escHtml(ctx.name)}">
        <div style="flex:1;min-width:0">
          <div class="context-name">${escHtml(ctx.name)}</div>
          <div class="context-cluster">${escHtml(ctx.cluster)}</div>
          <div class="cluster-name-field" style="display:none;margin-top:10px;display:none;flex-direction:column;gap:7px">
            <div>
              <div style="font-size:0.72rem;color:var(--text-muted);font-weight:500;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.05em">Internal ID <span style="color:var(--text-dim);font-weight:400;text-transform:none">&nbsp;·&nbsp;used as secret name prefix</span></div>
              <input type="text" name="remote-cluster-name" data-context="${escHtml(ctx.name)}"
                value="${escHtml(defaultSlug)}"
                style="width:100%;background:var(--surface);border:1px solid var(--border-light);
                       color:var(--text);border-radius:6px;padding:6px 10px;font-size:0.82rem;
                       font-family:'JetBrains Mono',monospace;outline:none;box-sizing:border-box;
                       border-color:var(--accent)"
                >
            </div>
            <div>
              <div style="font-size:0.72rem;color:var(--text-muted);font-weight:500;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.05em">Display name <span style="color:var(--text-dim);font-weight:400;text-transform:none">&nbsp;·&nbsp;shown in the UI</span></div>
              <input type="text" name="remote-display-name" data-context="${escHtml(ctx.name)}"
                value="${escHtml(ctx.name)}"
                placeholder="${escHtml(ctx.name)}"
                style="width:100%;background:var(--surface);border:1px solid var(--border-light);
                       color:var(--text);border-radius:6px;padding:6px 10px;font-size:0.82rem;
                       font-family:'Inter',sans-serif;outline:none;box-sizing:border-box"
                >
            </div>
          </div>
        </div>
      `;

      const cb           = rItem.querySelector('input[type="checkbox"]');
      const nameField    = rItem.querySelector('.cluster-name-field');
      const nameInput    = rItem.querySelector('input[name="remote-cluster-name"]');
      const displayInput = rItem.querySelector('input[name="remote-display-name"]');
      nameInput.addEventListener('input', function() {
        this.style.borderColor = this.value.trim() ? 'var(--accent)' : 'var(--border-light)';
      });
      displayInput.addEventListener('input', function() {
        this.style.borderColor = this.value.trim() ? 'var(--accent)' : 'var(--border-light)';
      });
      cb.addEventListener('change', e => {
        rItem.classList.toggle('selected', e.target.checked);
        nameField.style.display = e.target.checked ? 'flex' : 'none';
        if (e.target.checked) nameInput.focus();
      });
      remoteList.appendChild(rItem);
    });
  }
  lucide.createIcons();
}

// ---------------------------------------------------------------------------
// Panel 3 — Run setup
// ---------------------------------------------------------------------------
async function startSetup() {
  const central = document.querySelector('input[name="central"]:checked')?.value || '';

  const centralNameRaw    = document.getElementById('central-cluster-name')?.value.trim() || '';
  const central_name      = centralNameRaw.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '') || 'cluster1';
  const centralDisplayRaw = document.getElementById('central-display-name')?.value.trim() || '';
  const central_display   = centralDisplayRaw || central || 'cluster1';

  const remotes = [];
  for (const cb of document.querySelectorAll('input[name="remote"]:checked')) {
    const ctx          = cb.value;
    const item         = cb.closest('.context-item');
    const nameInput    = item?.querySelector('input[name="remote-cluster-name"]');
    const displayInput = item?.querySelector('input[name="remote-display-name"]');
    const cluster_name = nameInput?.value.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '') || ctx.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 52);
    const display_name = displayInput?.value.trim() || ctx;
    remotes.push({ context: ctx, cluster_name, display_name });
  }

  _setupHadError = false;
  document.getElementById('progress-actions').style.display = 'none';
  showPanel('progress');

  try {
    const resp = await fetch('/setup/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: _sessionId, central, central_name, central_display, remotes }),
    });
    if (!resp.ok) {
      showError('progress', `Failed to start setup: ${await resp.text()}`);
      return;
    }
  } catch (err) {
    showError('progress', `Network error: ${err.message}`);
    return;
  }

  connectWebSocket(_sessionId);
}

function connectWebSocket(sessionId) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  _ws = new WebSocket(`${proto}//${location.host}/ws/setup/${sessionId}`);
  document.getElementById('log-output').innerHTML = '';

  _ws.onmessage = ev => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'line') {
        appendLog(msg.text);
        if (msg.text.startsWith('[ERROR]') || msg.text.startsWith('[FATAL]')) {
          _setupHadError = true;
        }
        if (msg.text.includes('No janus deployments found')) {
          document.getElementById('btn-restart-deployments')?.classList.remove('hidden');
          lucide.createIcons();
        }
        if (msg.text.startsWith('[DONE]')) {
          const hint = document.getElementById('progress-actions-hint');
          if (_setupHadError) {
            hint.textContent = 'Some clusters had errors — review above.';
          } else {
            hint.textContent = 'Setup complete!';
          }
          const el = document.getElementById('progress-actions');
          el.style.display = 'flex';
          lucide.createIcons();
        } else if (msg.text.startsWith('[FATAL]')) {
          showError('progress', msg.text.replace('[FATAL] ', ''));
        }
      } else if (msg.type === 'done') {
        // no-op — user clicks "Go to Dashboard" manually
      } else if (msg.type === 'error') {
        appendLog(`[ERROR] ${msg.text}`, 'error');
      }
    } catch {}
  };
  _ws.onerror = () => appendLog('[ERROR] WebSocket connection lost', 'error');
  _ws.onclose = () => { document.querySelector('.log-cursor')?.remove(); };
}

function appendLog(text, forceClass) {
  const log = document.getElementById('log-output');
  log.querySelector('.log-cursor')?.remove();

  const line = document.createElement('div');
  line.className = 'log-line';
  if      (forceClass)                               line.classList.add(forceClass);
  else if (text.startsWith('[OK]') || text.startsWith('[READY]'))   line.classList.add('ok');
  else if (text.startsWith('[ERROR]') || text.startsWith('[FATAL]')) line.classList.add('error');
  else if (text.startsWith('[WARN]'))                line.classList.add('warn');
  else if (text.startsWith('[DONE]'))                line.classList.add('done');
  else if (text.startsWith('[RESTART]'))             line.classList.add('warn');
  else                                               line.classList.add('info');

  line.textContent = text;
  log.appendChild(line);

  const cur = document.createElement('span');
  cur.className = 'log-cursor';
  log.appendChild(cur);
  log.scrollTop = log.scrollHeight;
}

// ---------------------------------------------------------------------------
// Panel 4 — Complete
// ---------------------------------------------------------------------------
function startCountdown(_secs) {
  // No auto-redirect — setup stays on this page
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function showError(panel, msg) {
  const el = document.getElementById(`error-${panel}`);
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Manage / Remove clusters
// ---------------------------------------------------------------------------
let _manageVisible = false;

function showManagePanel(show) {
  _manageVisible = show;
  document.getElementById('panel-manage').classList.toggle('hidden', !show);
}

async function loadManagePanel() {
  // Hide all wizard panels, show manage panel
  PANELS.forEach(p => document.getElementById(`panel-${p}`).classList.add('hidden'));
  document.querySelectorAll('.wizard-step').forEach(el => {
    el.classList.remove('active', 'done');
  });
  showManagePanel(true);

  const listEl = document.getElementById('manage-cluster-list');
  listEl.innerHTML = '<div style="color:var(--text-dim);font-size:0.82rem">Loading…</div>';

  try {
    const resp = await fetch('/api/clusters');
    const clusters = await resp.json();
    listEl.innerHTML = '';
    if (clusters.length === 0) {
      listEl.innerHTML = '<div style="color:var(--text-dim);font-size:0.82rem">No clusters found.</div>';
      return;
    }
    clusters.forEach((c, idx) => {
      const isCentral = idx === 0;
      const row = document.createElement('div');
      row.dataset.clusterName = c.name;
      row.style.cssText = 'display:flex;flex-direction:column;gap:8px;padding:12px 14px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px';
      row.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px">
          <div style="min-width:0">
            <div style="font-size:0.72rem;color:var(--text-dim);margin-bottom:3px;font-family:'JetBrains Mono',monospace">
              ${isCentral
                ? `<span style="color:var(--accent);font-weight:600">central</span> &nbsp;·&nbsp; management cluster`
                : `${escHtml(c.name)}-kubeconfig`}
            </div>
            <div style="display:flex;align-items:center;gap:8px">
              <input type="text" class="rename-input" value="${escHtml(c.displayName || c.name)}"
                data-cluster="${escHtml(c.name)}"
                style="background:var(--surface);border:1px solid var(--border-light);color:var(--text);
                       border-radius:6px;padding:5px 9px;font-size:0.85rem;font-family:'Inter',sans-serif;
                       outline:none;width:220px"
                >
              <button class="btn btn-rename" data-action="rename" data-cluster="${escHtml(c.name)}" style="padding:5px 12px;font-size:0.78rem;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);color:var(--accent);border-radius:6px;cursor:pointer;white-space:nowrap">
                <i data-lucide="check" width="13" height="13"></i> Save
              </button>
            </div>
          </div>
          ${isCentral ? '' : `
          <button class="btn" data-action="remove" data-cluster="${escHtml(c.name)}" style="padding:6px 14px;font-size:0.78rem;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--danger);border-radius:6px;cursor:pointer;white-space:nowrap;flex-shrink:0">
            <i data-lucide="trash-2" width="13" height="13"></i> Remove
          </button>`}
        </div>
      `;
      const renameInput = row.querySelector('.rename-input');
      const renameBtn   = row.querySelector('[data-action="rename"]');
      const removeBtn   = row.querySelector('[data-action="remove"]');
      if (renameInput) {
        renameInput.addEventListener('input', function() { this.style.borderColor = 'var(--accent)'; });
        renameInput.addEventListener('keydown', function(e) {
          if (e.key === 'Enter' && renameBtn) renameBtn.click();
        });
      }
      if (renameBtn) renameBtn.addEventListener('click', function() { renameCluster(c.name, this); });
      if (removeBtn) removeBtn.addEventListener('click', function() { removeCluster(c.name, this); });
      listEl.appendChild(row);
    });
    lucide.createIcons();
  } catch (e) {
    listEl.innerHTML = `<div style="color:var(--danger);font-size:0.82rem">Failed to load clusters: ${escHtml(String(e))}</div>`;
  }
}

async function restartDeployments() {
  const btn = document.getElementById('btn-restart-deployments');
  const hint = document.getElementById('progress-actions-hint');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Restarting…';
  try {
    const res = await fetch('/api/setup/restart-deployments', { method: 'POST' });
    const data = await res.json();
    if (data.ok) {
      appendLog('[OK]   Deployments restarted — pods will be ready shortly.');
      btn.classList.add('hidden');
      hint.textContent = 'Setup complete!';
    } else {
      appendLog(`[WARN]  Restart failed: ${data.message}`);
      btn.disabled = false;
      btn.innerHTML = '<i data-lucide="refresh-cw" width="14" height="14"></i> Restart Deployments';
      lucide.createIcons();
    }
  } catch (e) {
    appendLog(`[WARN]  Restart failed: ${e}`);
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="refresh-cw" width="14" height="14"></i> Restart Deployments';
    lucide.createIcons();
  }
}

async function renameCluster(clusterName, btn) {
  const row        = btn.closest('[data-cluster-name]');
  const input      = row.querySelector('.rename-input');
  const newName    = input.value.trim();
  if (!newName) { input.focus(); return; }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  try {
    const resp = await fetch('/setup/rename-cluster', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cluster_name: clusterName, display_name: newName }),
    });
    const data = await resp.json();
    if (data.ok) {
      input.style.borderColor = 'var(--ok, #34d399)';
      btn.innerHTML = '<i data-lucide="check" width="13" height="13"></i> Saved';
      setTimeout(() => {
        input.style.borderColor = 'var(--border-light)';
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="check" width="13" height="13"></i> Save';
        lucide.createIcons();
      }, 2000);
    } else {
      input.style.borderColor = 'var(--danger)';
      btn.disabled = false;
      btn.innerHTML = '<i data-lucide="check" width="13" height="13"></i> Save';
    }
  } catch(e) {
    input.style.borderColor = 'var(--danger)';
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="check" width="13" height="13"></i> Save';
  }
  lucide.createIcons();
}

async function removeCluster(clusterName, btn) {
  if (!confirm(`Remove cluster "${clusterName}"?\n\nThis will delete the kubeconfig secret and clean up RBAC on the remote cluster (if accessible).`)) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="border-top-color:var(--danger)"></span>';

  const manageLog = document.getElementById('manage-log');
  const logOut    = document.getElementById('manage-log-output');
  manageLog.style.display = 'block';
  logOut.innerHTML = '';

  try {
    const resp = await fetch('/setup/remove-cluster', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        cluster_name: clusterName,
        session_id: _sessionId || '',
        context: '',
      }),
    });
    const data = await resp.json();
    (data.lines || []).forEach(line => {
      const div = document.createElement('div');
      div.className = 'log-line';
      if (line.startsWith('[OK]'))    div.classList.add('ok');
      else if (line.startsWith('[ERROR]')) div.classList.add('error');
      else if (line.startsWith('[WARN]'))  div.classList.add('warn');
      else                                 div.classList.add('info');
      div.textContent = line;
      logOut.appendChild(div);
      logOut.scrollTop = logOut.scrollHeight;
    });
    if (data.ok) {
      btn.closest('div[style]').remove();
      if (document.getElementById('manage-cluster-list').children.length === 0) {
        document.getElementById('manage-cluster-list').innerHTML =
          '<div style="color:var(--text-dim);font-size:0.82rem">No remote clusters configured.</div>';
      }
    } else {
      btn.disabled = false;
      btn.innerHTML = '<i data-lucide="trash-2" width="13" height="13"></i> Retry';
      lucide.createIcons();
    }
  } catch(e) {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="trash-2" width="13" height="13"></i> Retry';
    lucide.createIcons();
    const div = document.createElement('div');
    div.className = 'log-line error';
    div.textContent = `[ERROR] ${e}`;
    logOut.appendChild(div);
  }
}

// ---------------------------------------------------------------------------
// Auto-restore session from ?session= query param (set by setup-upload.sh)
// ---------------------------------------------------------------------------
(async function restoreSession() {
  const params = new URLSearchParams(location.search);

  // Auto-open manage panel when ?manage=1
  if (params.get('manage') === '1') {
    history.replaceState(null, '', location.pathname);
    loadManagePanel();
    return;
  }

  const sid = params.get('session');
  if (!sid) return;

  // ?autorun=1 — setup/run was already POSTed by setup-upload.sh, skip straight to progress
  if (params.get('autorun') === '1') {
    history.replaceState(null, '', location.pathname);
    _sessionId = sid;
    showPanel('progress');
    connectWebSocket(sid);
    return;
  }

  try {
    const resp = await fetch(`/setup/contexts/${sid}`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.error || !data.contexts?.length) return;
    _sessionId  = data.session_id;
    _kubeconfig = data.contexts;
    populateContextSelectors(data.contexts);
    showPanel('select');
    history.replaceState(null, '', location.pathname);
  } catch (_) { /* ignore — stay on upload panel */ }
})();
