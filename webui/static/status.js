// status.js — extracted from status.html
// Jinja2 variables are passed via window.PAGE_DATA (set inline in the template)
const { canWithdraw, cluster, name, phase } = window.PAGE_DATA;

lucide.createIcons();

// ── Withdraw / Cancel own request ──
if (canWithdraw) {
  window.doWithdraw = async function doWithdraw() {
    var label = phase === 'Active' ? 'Cancel your active session?' : 'Withdraw this pending request?';
    if (!confirm(label)) return;
    var btn = document.getElementById('withdraw-btn');
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader" style="width:14px;height:14px;animation:spin 0.8s linear infinite;"></i> ' + (phase === 'Active' ? 'Cancelling\u2026' : 'Withdrawing\u2026');
    lucide.createIcons({ nodes: [btn] });
    try {
      var resp = await fetch('/cancel/' + cluster + '/' + name, { method: 'POST', headers: {'Accept': 'application/json'} });
      var data = await resp.json();
      if (data.ok) {
        window.location.href = '/';
      } else {
        alert('Failed: ' + (data.error || 'unknown error'));
        btn.disabled = false;
        lucide.createIcons({ nodes: [btn] });
      }
    } catch(e) {
      alert('Failed: ' + e);
      btn.disabled = false;
      lucide.createIcons({ nodes: [btn] });
    }
  };
}

// ── Expiry countdown ──
(function() {
  var el = document.getElementById('ttl-countdown');
  if (!el) return;
  var expires = new Date(el.dataset.expires);
  function tick() {
    var diff = Math.floor((expires - Date.now()) / 1000);
    if (diff <= 0) {
      el.textContent = 'Expired';
      el.style.color = 'var(--danger)';
      return;
    }
    var h = Math.floor(diff / 3600);
    var m = Math.floor((diff % 3600) / 60);
    var s = diff % 60;
    el.textContent = h > 0
      ? h + 'h ' + m + 'm ' + s + 's remaining'
      : m > 0 ? m + 'm ' + s + 's remaining'
      : s + 's remaining';
    el.style.color = diff < 300 ? 'var(--danger)' : diff < 900 ? 'var(--warning)' : 'var(--success)';
    setTimeout(tick, 1000);
  }
  tick();
})();

function copyCmd(id, btn) {
  const text = document.getElementById(id).innerText;
  function onSuccess() {
    btn.innerHTML = '<i data-lucide="check" style="width:13px;height:13px;"></i> Copied!';
    btn.style.borderColor = 'rgba(16,185,129,0.5)';
    btn.style.color = '#34d399';
    lucide.createIcons();
    setTimeout(() => {
      btn.innerHTML = '<i data-lucide="clipboard" style="width:13px;height:13px;"></i> Copy';
      btn.style.borderColor = '';
      btn.style.color = '';
      lucide.createIcons();
    }, 2000);
  }
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onSuccess);
  } else {
    // Fallback for HTTP (non-secure) origins
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    onSuccess();
  }
}
