// ── State ──
let lastResults = null;
let currentFinding = null;
let currentTab = 'gdpr';
let settingsOpen = false;

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  document.getElementById('req-email').addEventListener('input', renderTemplate);
  document.getElementById('req-name').addEventListener('input', renderTemplate);
});

// ── Settings ──
function toggleSettings() {
  settingsOpen = !settingsOpen;
  document.getElementById('settings-drawer').classList.toggle('open', settingsOpen);
}

const KEY_IDS = ['hibp', 'serp', 'github', 'gitlab', 'bd'];

function saveSettings() {
  KEY_IDS.forEach(k => {
    const el = document.getElementById(`key-${k}`);
    if (!el) return;
    const val = el.value.trim();
    if (val) localStorage.setItem(`lr_key_${k}`, val);
    else localStorage.removeItem(`lr_key_${k}`);
  });
  toggleSettings();
  showToast('API keys saved');
}

function clearSettings() {
  KEY_IDS.forEach(k => {
    localStorage.removeItem(`lr_key_${k}`);
    const el = document.getElementById(`key-${k}`);
    if (el) el.value = '';
  });
}

function loadSettings() {
  KEY_IDS.forEach(k => {
    const val = localStorage.getItem(`lr_key_${k}`);
    const el = document.getElementById(`key-${k}`);
    if (val && el) el.value = val;
  });
}

function getKeys() {
  return {
    hibp_key:     localStorage.getItem('lr_key_hibp')   || '',
    serp_key:     localStorage.getItem('lr_key_serp')   || '',
    github_token: localStorage.getItem('lr_key_github') || '',
    gitlab_token: localStorage.getItem('lr_key_gitlab') || '',
    bd_key:       localStorage.getItem('lr_key_bd')     || '',
  };
}

// ── Search ──
async function startSearch() {
  const raw = document.getElementById('search-input').value.trim();
  if (!raw) return;

  setLoading(true);
  hideError();
  hideResults();

  const params = new URLSearchParams({ domain: raw, ...getKeys() });
  // Remove empty keys
  for (const [k, v] of [...params]) { if (!v) params.delete(k); }

  try {
    const resp = await fetch(`/api/search?${params}`);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    lastResults = await resp.json();
    renderResults(lastResults);
  } catch (e) {
    showError(`Search failed: ${e.message}`);
  } finally {
    setLoading(false);
  }
}

function setLoading(on) {
  document.getElementById('scan-btn').disabled = on;
  document.getElementById('scan-label').classList.toggle('hidden', on);
  document.getElementById('scan-spinner').classList.toggle('hidden', !on);
}

// ── Render Results ──
function renderResults(data) {
  const results = document.getElementById('results');
  results.classList.remove('hidden');

  renderSummary(data);
  renderCards(data.findings, 'all');
  renderDorks(data.dork_queries || []);

  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderSummary(data) {
  const keylessBadge = data.keyless
    ? `<span style="background:#14532d;color:#86efac;border:1px solid #166534;font-size:11px;padding:2px 8px;border-radius:4px;margin-left:10px">✓ keyless</span>`
    : `<span style="background:#1a2744;color:#93c5fd;border:1px solid #1e3a5f;font-size:11px;padding:2px 8px;border-radius:4px;margin-left:10px">🔑 keys active</span>`;

  document.getElementById('summary-domain').innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    ${escHtml(data.domain)}
    <span style="font-size:13px;color:#64748b;font-weight:400;margin-left:8px">${data.total_findings} finding${data.total_findings !== 1 ? 's' : ''}</span>
    ${keylessBadge}
  `;

  const sv = data.severity_summary || {};
  const accts = data.total_affected_accounts || 0;
  document.getElementById('summary-stats').innerHTML = `
    ${sv.critical ? `<span class="stat-chip c-critical">● ${sv.critical} Critical</span>` : ''}
    ${sv.high     ? `<span class="stat-chip c-high">● ${sv.high} High</span>` : ''}
    ${sv.medium   ? `<span class="stat-chip c-medium">● ${sv.medium} Medium</span>` : ''}
    ${sv.low      ? `<span class="stat-chip c-low">● ${sv.low} Low</span>` : ''}
    ${accts > 0   ? `<span class="stat-chip c-accounts">~${fmtNum(accts)} accounts exposed</span>` : ''}
  `;

  const types = data.data_types_found || [];
  const sensitiveWords = ['password', 'credit', 'bank', 'ssn', 'financial', 'passport', 'health'];
  document.getElementById('summary-types').innerHTML = types.map(t =>
    `<span class="type-tag">${escHtml(t)}</span>`
  ).join('');
}

function renderCards(findings, sevFilter) {
  const grid = document.getElementById('cards-grid');
  const visible = sevFilter === 'all' ? findings : findings.filter(f => f.severity === sevFilter);

  if (!visible.length) {
    grid.innerHTML = `<div style="text-align:center;padding:60px;color:#64748b">No findings at this severity level.</div>`;
    return;
  }

  grid.innerHTML = visible.map(f => cardHTML(f)).join('');
}

function cardHTML(f) {
  const sev = f.severity || 'low';
  const src = f.source_type || 'dork';

  // Source badge label
  const srcLabels = { hibp: 'HIBP', git: 'GitHub', paste: 'Paste', dork: 'Dork', forum: 'Forum', breach_db: 'BreachDB', exposed_service: 'LeakIX' };
  const srcBadge = `<span class="source-badge ${src}">${srcLabels[src] || src.toUpperCase()}</span>`;

  // Logo / icon
  const logoEl = f.logo
    ? `<img class="card-logo" src="${escHtml(f.logo)}" alt="" onerror="this.style.display='none'" />`
    : `<div class="card-logo-placeholder">${srcIcon(src)}</div>`;

  // Date + accounts
  const dateStr = f.date ? `<span><span class="card-info-label">Date: </span><span class="card-info-value">${escHtml(f.date)}</span></span>` : '';
  const acctStr = f.affected_accounts ? `<span><span class="card-info-label">Accounts: </span><span class="card-info-value">${fmtNum(f.affected_accounts)}</span></span>` : '';

  // Data types
  const sensitiveWords = ['password', 'credit', 'bank', 'ssn', 'financial', 'passport'];
  const typesHTML = (f.data_types || []).map(t => {
    const isSensitive = sensitiveWords.some(w => t.toLowerCase().includes(w));
    return `<span class="data-type-tag${isSensitive ? ' sensitive' : ''}">${escHtml(t)}</span>`;
  }).join('');

  // Emails
  const emailsHTML = (f.sample_emails || []).length
    ? `<div style="margin-top:8px;margin-bottom:4px;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px">Exposed emails (masked)</div>
       <div class="card-emails">${f.sample_emails.map(e => `<span class="email-chip">${escHtml(e)}</span>`).join('')}</div>`
    : '';

  // Dork sub-results
  let dorkResultsHTML = '';
  if (f.dork_results && f.dork_results.length) {
    dorkResultsHTML = `<div class="dork-results-list">` +
      f.dork_results.map(r => `
        <div class="dork-result-item">
          <div class="dork-result-title"><a href="${escHtml(r.url)}" target="_blank" rel="noopener">${escHtml(r.title || 'Untitled')}</a></div>
          <div class="dork-result-url">${escHtml(r.display_url || r.url || '')}</div>
          ${r.snippet ? `<div class="dork-result-snippet">${escHtml(r.snippet.slice(0, 180))}</div>` : ''}
        </div>
      `).join('') + `</div>`;
  }

  // Exposed values (passwords, API keys, tokens — masked)
  let exposedHTML = '';
  if (f.exposed_values && f.exposed_values.length) {
    exposedHTML = `<div style="margin-top:10px;margin-bottom:4px;font-size:11px;color:#fca5a5;text-transform:uppercase;letter-spacing:.5px">Exposed values (masked)</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px">` +
      f.exposed_values.map(v => `<span style="background:#2d1515;border:1px solid #7f1d1d;color:#fca5a5;padding:3px 10px;border-radius:4px;font-size:12px;font-family:'JetBrains Mono',monospace">${escHtml(v)}</span>`).join('') +
      `</div>`;
  }

  // File hits (repo + path links)
  let fileHitsHTML = '';
  if (f.file_hits && f.file_hits.length) {
    fileHitsHTML = `<div style="margin-top:10px;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Affected files</div>` +
      `<div style="display:flex;flex-direction:column;gap:4px">` +
      f.file_hits.map(h => `
        <div style="display:flex;align-items:center;gap:8px;font-size:12px">
          <span style="color:#7dd3fc;font-family:'JetBrains Mono',monospace">🐙</span>
          <a href="${escHtml(h.url)}" target="_blank" rel="noopener" style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#93c5fd">${escHtml(h.repo)}/<span style="color:#e2e8f0">${escHtml(h.path)}</span></a>
        </div>`).join('') +
      `</div>`;
  }

  // Snippet preview for GitHub/GitLab
  let snippetsHTML = '';
  if (f.snippets && f.snippets.length) {
    snippetsHTML = `<div style="margin-top:10px;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px">Code snippets</div>` +
      f.snippets.map(s => `<div style="background:#0a0e1a;border:1px solid #1e2d4a;border-radius:5px;padding:8px 10px;margin-top:4px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#94a3b8;word-break:break-all">${escHtml(s)}</div>`).join('');
  }

  // Paste URLs
  let pasteLinksHTML = '';
  if (f.paste_urls && f.paste_urls.length) {
    pasteLinksHTML = `<div style="margin-top:10px;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Paste links</div>` +
      f.paste_urls.map(u => `<div><a href="${escHtml(u)}" target="_blank" rel="noopener" style="font-family:'JetBrains Mono',monospace;font-size:12px">${escHtml(u)}</a></div>`).join('');
  }

  const viewBtn = f.source_url
    ? `<a href="${escHtml(f.source_url)}" target="_blank" rel="noopener" class="btn-view">View ↗</a>`
    : '';

  // "needs token" notice for GitHub unauthenticated
  let needsTokenHTML = '';
  if (f.needs_token) {
    needsTokenHTML = `
      <div style="background:#1a2744;border:1px solid #1e3a5f;border-radius:6px;padding:10px 14px;margin-top:10px;font-size:13px;color:#93c5fd;display:flex;align-items:center;gap:10px">
        <span style="font-size:16px">🔑</span>
        <span>Add a free <a href="https://github.com/settings/tokens/new?scopes=&description=LeakRadar" target="_blank">GitHub token</a> in Settings to unlock full code search — finds leaked passwords, API keys, .env files, and secrets across millions of public repos.</span>
        <button onclick="toggleSettings()" style="background:var(--accent);color:#fff;border:none;padding:5px 12px;border-radius:5px;font-size:12px;cursor:pointer;white-space:nowrap;font-family:inherit">Add Key</button>
      </div>`;
  }

  const findingJson = encodeURIComponent(JSON.stringify({
    name: f.breach_name,
    source: f.source,
    source_url: f.source_url,
    date: f.date,
    data_types: f.data_types,
  }));

  return `
  <div class="card" data-sev="${sev}">
    <div class="card-header">
      ${logoEl}
      <div class="card-meta">
        <div class="card-title">
          ${escHtml(f.breach_name || f.source)}
          <span class="sev-badge sev-${sev}">${sev}</span>
        </div>
        <div class="card-source">
          ${srcBadge}
          ${f.source !== f.breach_name ? `<span>${escHtml(f.source)}</span>` : ''}
        </div>
      </div>
      <div class="card-actions">
        <button class="btn-delete" onclick='openDeleteModal(decodeURIComponent("${findingJson}"))'>Request Deletion</button>
        ${viewBtn}
      </div>
    </div>
    ${(dateStr || acctStr) ? `<div class="card-info-row">${dateStr}${acctStr}</div>` : ''}
    ${typesHTML ? `<div class="card-data-types">${typesHTML}</div>` : ''}
    ${f.description ? `<div class="card-body">${escHtml(f.description)}</div>` : ''}
    ${emailsHTML}
    ${exposedHTML}
    ${fileHitsHTML}
    ${snippetsHTML}
    ${pasteLinksHTML}
    ${needsTokenHTML}
    ${dorkResultsHTML}
  </div>`;
}

function srcIcon(type) {
  const icons = { hibp: '🔓', git: '🐙', paste: '📋', dork: '🔍', forum: '⚠️', breach_db: '🗄️' };
  return icons[type] || '🔍';
}

// ── Filter ──
function filterSeverity(sev, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (lastResults) renderCards(lastResults.findings, sev);
}

// ── Dork Queries ──
function renderDorks(queries) {
  const list = document.getElementById('dork-list');
  list.innerHTML = queries.map((q, i) => `
    <div class="dork-item">
      <span class="dork-query">${escHtml(q)}</span>
      <button class="dork-copy" onclick="copyText(${i})">Copy</button>
      <a class="dork-open" href="https://duckduckgo.com/?q=${encodeURIComponent(q)}" target="_blank" rel="noopener">DDG ↗</a>
      <a class="dork-open" href="https://www.google.com/search?q=${encodeURIComponent(q)}" target="_blank" rel="noopener">Google ↗</a>
    </div>
  `).join('');
  // Store for copy
  window._dorkQueries = queries;
}

function copyText(idx) {
  navigator.clipboard.writeText(window._dorkQueries[idx]).then(() => showToast('Copied'));
}

// ── Delete Request Modal ──
function openDeleteModal(jsonStr) {
  try { currentFinding = JSON.parse(jsonStr); } catch { return; }
  document.getElementById('modal-overlay').classList.remove('hidden');
  renderTemplate();
}

function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
  currentFinding = null;
}

function switchTab(tab, btn) {
  currentTab = tab;
  document.querySelectorAll('.modal-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTemplate();
}

function renderTemplate() {
  if (!currentFinding) return;
  const email = document.getElementById('req-email').value || '[YOUR EMAIL]';
  const name  = document.getElementById('req-name').value  || '[YOUR NAME]';
  const f = currentFinding;
  const today = new Date().toISOString().split('T')[0];
  const breach = f.name || 'Unknown Breach';
  const site   = (f.source_url ? new URL(f.source_url).hostname : (f.source || '[site]'));

  let tpl = '';
  if (currentTab === 'gdpr') {
    tpl = `Subject: GDPR Article 17 — Right to Erasure Request

To: Privacy / Data Protection Officer
From: ${name} <${email}>
Date: ${today}

Dear Data Controller,

I am writing to exercise my right to erasure under Article 17 of the General Data Protection Regulation (GDPR).

I have been informed that my personal data — specifically my email address and associated credentials — was exposed in the following incident:

  Breach / Source: ${breach}
  Reported by: ${f.source || 'LeakRadar OSINT scan'}
  ${f.date ? `Date of incident: ${f.date}` : ''}
  ${f.data_types ? `Data categories exposed: ${f.data_types.join(', ')}` : ''}

I hereby request that you:
1. Confirm whether my personal data is being processed
2. Permanently delete all personal data you hold relating to ${email}
3. Confirm in writing once the deletion has been completed
4. Notify any third parties to whom my data was disclosed

Under GDPR, you must fulfil this request without undue delay and at the latest within 30 days of receipt.

Please respond to: ${email}

Regards,
${name}`;

  } else if (currentTab === 'ccpa') {
    tpl = `Subject: CCPA — Request to Delete Personal Information

To: Privacy Contact
From: ${name} <${email}>
Date: ${today}

Dear Privacy Team,

Pursuant to the California Consumer Privacy Act (CCPA), Cal. Civ. Code § 1798.105, I am requesting the deletion of my personal information.

My information was found in the following data exposure:

  Breach: ${breach}
  Source: ${f.source || 'LeakRadar OSINT scan'}
  ${f.data_types ? `Exposed data: ${f.data_types.join(', ')}` : ''}

I request that you:
1. Delete all personal information collected about me
2. Direct any service providers to delete my personal information
3. Confirm completion of this request

Please process this request within 45 days as required by CCPA.

Contact me at: ${email}

Sincerely,
${name}`;

  } else {
    tpl = `Subject: Data Deletion Request — ${email}

To: Security / Privacy Team
From: ${name} <${email}>
Date: ${today}

Hello,

I am writing to request the deletion of my personal data that was exposed in the following incident:

  Incident: ${breach}
  Source: ${f.source || 'LeakRadar scan'}
  ${f.date ? `Date: ${f.date}` : ''}
  ${f.data_types ? `Exposed data: ${f.data_types.join(', ')}` : ''}

I kindly ask that you:
• Remove all records associated with ${email} from your systems
• Confirm the deletion in a reply to this email

I appreciate your prompt attention to this matter.

Best regards,
${name}
${email}`;
  }

  document.getElementById('template-content').textContent = tpl;
}

function copyTemplate() {
  const tpl = document.getElementById('template-content').textContent;
  navigator.clipboard.writeText(tpl).then(() => showToast('Template copied to clipboard'));
}

// ── Export ──
function exportJSON() {
  if (!lastResults) return;
  const blob = new Blob([JSON.stringify(lastResults, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `leakradar-${lastResults.domain}-${Date.now()}.json`;
  a.click();
}

// ── Helpers ──
function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function fmtNum(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return (n / 1_000).toFixed(0) + 'K';
  return String(n);
}

function hideResults() { document.getElementById('results').classList.add('hidden'); }
function showError(msg) {
  const el = document.getElementById('error-banner');
  el.textContent = msg;
  el.classList.remove('hidden');
}
function hideError() { document.getElementById('error-banner').classList.add('hidden'); }

function showToast(msg) {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#1e3a5f;color:#93c5fd;border:1px solid #1e4a7f;padding:10px 18px;border-radius:8px;font-size:13px;z-index:999;transition:opacity .3s';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.opacity = '1';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; }, 2000);
}
