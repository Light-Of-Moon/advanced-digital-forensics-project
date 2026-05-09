/* ═══════════════════════════════════════════════════════
   CipherChain Forensics — Main Application Script
   ═══════════════════════════════════════════════════════ */

const API = '/api';
let token = localStorage.getItem('cf_token');
let guestToken = sessionStorage.getItem('cf_guest_token');
let currentUser = null;
let allCases = [];
let allEvidence = [];
let chartInstance = null;

// ── API Helper ──────────────────────────────────────────
async function api(method, path, body = null, isForm = false, useGuestToken = false) {
  const headers = {};
  const activeToken = useGuestToken ? guestToken : token;
  if (activeToken) headers['Authorization'] = `Bearer ${activeToken}`;
  if (!isForm && body) headers['Content-Type'] = 'application/json';

  const opts = {
    method,
    headers,
    body: isForm ? body : (body ? JSON.stringify(body) : null)
  };

  try {
    const res = await fetch(`${API}${path}`, opts);
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && path !== '/auth/login' && path !== '/auth/guest' && !useGuestToken) { 
      logout(); 
      return null; 
    }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, data: { error: 'Network error: ' + e.message } };
  }
}

// ── Toast ────────────────────────────────────────────────
function toast(msg, type = 'info', duration = 4000) {
  const tc = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  tc.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(20px)'; el.style.transition = '0.3s'; setTimeout(() => el.remove(), 300); }, duration);
}

// ── Auth ─────────────────────────────────────────────────
function togglePw(id, btn) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '\u25CE' : '\u25C9';
}

function fillCreds(u, p) {
  document.getElementById('login-username').value = u;
  document.getElementById('login-password').value = p;
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('login-btn');
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  btn.querySelector('.btn-text').textContent = 'AUTHENTICATING...';
  btn.querySelector('.btn-loader').classList.remove('hidden');

  const res = await api('POST', '/auth/login', {
    username: document.getElementById('login-username').value,
    password: document.getElementById('login-password').value
  });

  btn.querySelector('.btn-text').textContent = 'ACCESS SYSTEM';
  btn.querySelector('.btn-loader').classList.add('hidden');

  if (res?.ok) {
    token = res.data.token;
    currentUser = res.data.user;
    localStorage.setItem('cf_token', token);
    localStorage.setItem('cf_user', JSON.stringify(currentUser));
    enterApp();
  } else {
    errEl.textContent = res?.data?.error || 'Authentication failed';
    errEl.classList.remove('hidden');
  }
});

function logout() {
  token = null; currentUser = null;
  localStorage.removeItem('cf_token');
  localStorage.removeItem('cf_user');
  document.getElementById('app-screen').classList.add('hidden');
  document.getElementById('auth-screen').classList.remove('hidden');
  document.getElementById('auth-screen').classList.add('active');
  document.getElementById('login-form').reset();
  document.getElementById('login-error').classList.add('hidden');
  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
  toast('Signed out successfully', 'info', 2000);
}

// ── App Initialization ──────────────────────────────────
function enterApp() {
  document.getElementById('auth-screen').classList.remove('active');
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app-screen').classList.remove('hidden');

  // Set sidebar user info
  const u = currentUser;
  document.getElementById('sidebar-name').textContent = u.full_name || u.username;
  document.getElementById('sidebar-avatar').textContent = (u.full_name || u.username)[0].toUpperCase();
  const roleEl = document.getElementById('sidebar-role');
  roleEl.textContent = u.role.charAt(0).toUpperCase() + u.role.slice(1);
  roleEl.className = `user-role-badge role-${u.role}`;

  // Apply role-based visibility
  applyRoleVisibility(u.role);

  // Start clock
  updateClock();
  setInterval(updateClock, 1000);

  // Navigate to dashboard
  navigate('dashboard');
}

function applyRoleVisibility(role) {
  // Toggle the 'hidden' class based on permissions
  document.querySelectorAll('.admin-only').forEach(el => {
    el.classList.toggle('hidden', role !== 'admin');
  });
  document.querySelectorAll('.investigator-only').forEach(el => {
    el.classList.toggle('hidden', role !== 'investigator');
  });
  document.querySelectorAll('.analyst-only').forEach(el => {
    el.classList.toggle('hidden', role !== 'analyst');
  });
}

function updateClock() {
  const now = new Date();
  document.getElementById('top-time').textContent = now.toLocaleTimeString('en-US', { hour12: false });
}

// ── Navigation ───────────────────────────────────────────
const sectionTitles = {
  dashboard: 'Dashboard',
  cases: 'Cases',
  evidence: 'Upload Evidence',
  'evidence-list': 'Evidence Library',
  analyst: 'Analysis Lab',
  users: 'User Management',
  audit: 'Audit Trail',
  blockchain: 'Blockchain Explorer'
};

function navigate(section) {
  document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const sec = document.getElementById(`section-${section}`);
  if (sec) sec.classList.add('active');
  const navItem = document.querySelector(`.nav-item[data-section="${section}"]`);
  if (navItem) navItem.classList.add('active');
  document.getElementById('page-title').textContent = sectionTitles[section] || section;

  // Load section data
  const loaders = {
    dashboard: loadDashboard,
    cases: loadCases,
    'evidence-list': loadEvidenceList,
    analyst: loadAnalystSection,
    users: loadUsers,
    audit: loadAuditLogs,
    blockchain: loadBlockchainStatus,
    evidence: loadEvidenceCaseSelect
  };
  if (loaders[section]) loaders[section]();
}

// ── Dashboard ────────────────────────────────────────────
async function loadDashboard() {
  const [statsRes, recentRes] = await Promise.all([
    api('GET', '/dashboard/stats'),
    api('GET', '/dashboard/recent')
  ]);

  if (statsRes?.ok) {
    const s = statsRes.data;
    animateCounter('stat-cases', s.total_cases);
    animateCounter('stat-evidence', s.total_evidence);
    animateCounter('stat-verified', s.verified_evidence);
    animateCounter('stat-tampered', s.tampered_evidence);
    animateCounter('stat-users', s.total_users);
    document.getElementById('stat-blocks').textContent = s.blockchain?.block_number?.toLocaleString() || '—';

    // Chain status badge
    const dot = document.querySelector('.status-dot');
    if (s.blockchain?.connected) { dot.classList.remove('offline'); }
    else { dot.classList.add('offline'); }

    // Chart
    renderEvidenceChart(s.evidence_by_type || {});
  }

  if (recentRes?.ok) {
    renderActivityFeed(recentRes.data.recent_activity || []);
    renderRecentEvidence(recentRes.data.recent_evidence || []);
  }
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = 0;
  const duration = 800;
  const startTime = Date.now();
  const tick = () => {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    el.textContent = Math.floor(start + (target - start) * easeOut(progress));
    if (progress < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}
const easeOut = t => 1 - Math.pow(1 - t, 3);

function renderEvidenceChart(data) {
  const ctx = document.getElementById('evidenceTypeChart');
  if (!ctx) return;
  if (chartInstance) chartInstance.destroy();

  const labels = Object.keys(data);
  const values = Object.values(data);
  const colors = ['#00d4ff', '#00e676', '#ff9100', '#aa00ff', '#ff1744', '#ffd740', '#00bcd4', '#4caf50'];

  chartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels.map(l => l.toUpperCase()),
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + '55'),
        borderColor: colors,
        borderWidth: 2,
        hoverBorderWidth: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: '#7ba0c4', font: { size: 11 }, padding: 12 } }
      },
      cutout: '65%'
    }
  });
}

function renderActivityFeed(activity) {
  const feed = document.getElementById('activity-feed');
  if (!activity.length) { feed.innerHTML = '<div class="loading-pulse">No recent activity</div>'; return; }
  feed.innerHTML = activity.map(a => {
    let text = escHtml(a.action.replace(/_/g, ' '));
    let color = 'var(--accent)';
    if (a.action === 'EVIDENCE_UPLOADED') { text = 'Uploaded Evidence'; color = 'var(--green)'; }
    else if (a.action.startsWith('CASE_')) { text = a.action === 'CASE_CREATED' ? 'Created Case' : 'Updated Case'; color = 'var(--yellow)'; }
    else if (a.action === 'ASSIGNMENT_ADDED') { text = 'Assigned to Case'; color = 'var(--blue)'; }
    else if (a.action.startsWith('VERIFICATION_')) {
      text = a.action === 'VERIFICATION_VERIFIED' ? 'Verified Clue/Evidence (Match)' : 'Verified Clue/Evidence (Mismatch)';
      color = a.action === 'VERIFICATION_VERIFIED' ? 'var(--green)' : 'var(--red)';
    }
    
    return `
      <div class="activity-item" style="display:flex; justify-content:space-between; align-items:center; padding:0.6rem 0; border-bottom:1px solid rgba(255,255,255,0.05);">
        <div>
          <div style="font-weight:600; color:${color}; font-size:0.85rem;">${text}</div>
          <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.2rem;">By: <span style="color:var(--text);">${escHtml(a.user || 'System')}</span></div>
        </div>
        <span class="activity-time" style="font-size:0.7rem; color:var(--text-dim);">${timeAgo(a.timestamp)}</span>
      </div>
    `;
  }).join('');
}

function renderRecentEvidence(evList) {
  const el = document.getElementById('recent-evidence-list');
  if (!evList.length) { el.innerHTML = '<div class="loading-pulse">No evidence uploaded yet</div>'; return; }
  el.innerHTML = evList.map(e => `
    <div class="recent-ev-item" onclick="openEvidenceDetail(${e.id})" style="display:flex;align-items:center;gap:0.6rem;padding:0.5rem 0.3rem;cursor:pointer;border-bottom:1px solid rgba(255,255,255,0.04);">
      <span style="font-size:1.2rem">${typeIcon(e.evidence_type)}</span>
      <div style="flex:1;min-width:0">
        <div style="font-size:0.82rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(e.original_filename)}</div>
        <div style="font-size:0.72rem;color:var(--text-muted)">${e.evidence_number} · ${timeAgo(e.created_at)}</div>
      </div>
      <span class="tag tag-${e.status}">${e.status}</span>
    </div>
  `).join('');
}

// ── Cases ────────────────────────────────────────────────
async function loadCases() {
  document.getElementById('cases-grid').innerHTML = '<div class="loading-pulse">Loading cases...</div>';
  const res = await api('GET', '/cases');
  if (!res?.ok) { document.getElementById('cases-grid').innerHTML = '<div class="alert-error">Failed to load cases</div>'; return; }
  allCases = res.data.cases || [];
  renderCases(allCases);
}

function renderCases(cases) {
  const grid = document.getElementById('cases-grid');
  if (!cases.length) { grid.innerHTML = '<div class="loading-pulse">No cases found. Create your first case.</div>'; return; }
  grid.innerHTML = cases.map(c => `
    <div class="case-card glass-card" onclick="openCaseDetail(${c.id})">
      <div class="case-card-header">
        <span class="case-number">${escHtml(c.case_number)}</span>
        <span class="tag tag-${c.priority}">${c.priority}</span>
      </div>
      <div class="case-title">${escHtml(c.title)}</div>
      <div class="case-desc">${escHtml(c.description || 'No description provided.')}</div>
      <div class="case-meta">
        <span class="tag tag-${c.status}">${c.status}</span>
        <span style="font-size:0.75rem;color:var(--text-muted)">◈ ${c.evidence_count} evidence</span>
        <span style="font-size:0.75rem;color:var(--text-muted)"> ${fmtDate(c.created_at)}</span>
      </div>
    </div>
  `).join('');
}

function filterCases() {
  const q = document.getElementById('case-search').value.toLowerCase();
  const s = document.getElementById('case-status-filter').value;
  renderCases(allCases.filter(c =>
    (!q || c.title.toLowerCase().includes(q) || c.case_number.toLowerCase().includes(q)) &&
    (!s || c.status === s)
  ));
}

function openCreateCase() {
  document.getElementById('create-case-form').reset();
  document.getElementById('create-case-error').classList.add('hidden');
  document.getElementById('create-case-modal').classList.remove('hidden');
}

document.getElementById('create-case-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('create-case-error');
  errEl.classList.add('hidden');
  const body = {
    title: document.getElementById('case-title').value,
    description: document.getElementById('case-description').value,
    priority: document.getElementById('case-priority').value,
    location: document.getElementById('case-location').value,
    incident_date: document.getElementById('case-date').value || null
  };
  const res = await api('POST', '/cases', body);
  if (res?.ok) {
    closeModal('create-case-modal');
    toast('Case created successfully', 'success');
    loadCases();
  } else {
    errEl.textContent = res?.data?.error || 'Failed to create case';
    errEl.classList.remove('hidden');
  }
});

async function openCaseDetail(caseId) {
  const res = await api('GET', `/cases/${caseId}`);
  if (!res?.ok) { toast('Failed to load case', 'error'); return; }
  const c = res.data.case;

  document.getElementById('case-detail-title').textContent = `${c.case_number} — ${c.title}`;

  const canAssign = currentUser.role === 'investigator';
  const allUsersRes = canAssign ? await api('GET', '/users') : null;
  const allUsers = allUsersRes?.ok ? allUsersRes.data.users : [];

  document.getElementById('case-detail-body').innerHTML = `
    <div class="detail-grid" style="margin-bottom:1rem">
      <div class="detail-item"><label>Status</label><span class="tag tag-${c.status}">${c.status}</span></div>
      <div class="detail-item"><label>Priority</label><span class="tag tag-${c.priority}">${c.priority}</span></div>
      <div class="detail-item"><label>Location</label><div class="val">${escHtml(c.location || '—')}</div></div>
      <div class="detail-item"><label>Incident Date</label><div class="val">${fmtDate(c.incident_date)}</div></div>
      <div class="detail-item"><label>Created By</label><div class="val">${escHtml(c.creator_name)}</div></div>
      <div class="detail-item"><label>Created At</label><div class="val">${c.created_at ? c.created_at.replace('T', ' ').split('.')[0] : '—'}</div></div>
    </div>
    <div style="margin-bottom:1rem"><label>Description</label><p style="font-size:0.88rem;color:var(--text)">${escHtml(c.description || 'No description.')}</p></div>

    <div style="margin-bottom:1rem">
      <div class="card-header"><h3> Assigned Personnel (${(c.assignments||[]).length})</h3>
      ${canAssign ? `
        <div style="display:flex;gap:0.5rem;align-items:center">
          <select id="assign-user-sel" style="max-width:180px">
            ${allUsers.filter(u => !(c.assignments||[]).find(a=>a.user_id===u.id)).map(u=>`<option value="${u.id}">${escHtml(u.full_name||u.username)} (${u.role})</option>`).join('')}
          </select>
          <button class="btn btn-xs btn-primary" onclick="assignUserToCase(${c.id})">Assign</button>
        </div>` : ''}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-top:0.5rem">
        ${(c.assignments||[]).map(a=>`<div class="tag tag-active">${escHtml(a.full_name||a.username)} · ${escHtml(a.role_in_case)}</div>`).join('')}
      </div>
    </div>

    <div>
      <div class="card-header"><h3>◈ Evidence (${(c.evidence||[]).length})</h3></div>
      ${(c.evidence||[]).length ? `
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Number</th><th>Filename</th><th>Type</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              ${c.evidence.map(ev=>`
                <tr>
                  <td class="mono" style="font-size:0.75rem;color:var(--accent)">${ev.evidence_number}</td>
                  <td class="ev-filename">${escHtml(ev.original_filename)}</td>
                  <td class="ev-type">${ev.evidence_type}</td>
                  <td><span class="tag tag-${ev.status}">${ev.status}</span></td>
                  <td><div class="actions-col">
                    <button class="btn btn-xs btn-outline" onclick="closeModal('case-detail-modal');openEvidenceDetail(${ev.id})">View</button>
                  </div></td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>` : '<div class="loading-pulse">No evidence uploaded for this case.</div>'}
    </div>`;

  document.getElementById('case-detail-modal').classList.remove('hidden');
}

async function assignUserToCase(caseId) {
  const userId = document.getElementById('assign-user-sel').value;
  if (!userId) return;
  const res = await api('POST', `/cases/${caseId}/assign`, { user_id: parseInt(userId), role_in_case: 'Team Member' });
  if (res?.ok) { toast(res.data.message, 'success'); openCaseDetail(caseId); }
  else toast(res?.data?.error || 'Failed to assign', 'error');
}

// ── Evidence Upload ──────────────────────────────────────
async function loadEvidenceCaseSelect() {
  const res = await api('GET', '/cases');
  const sel = document.getElementById('ev-case-id');
  if (res?.ok) {
    const cases = res.data.cases || [];
    sel.innerHTML = '<option value="">Select a Case</option>' + cases.map(c=>`<option value="${c.id}">${escHtml(c.case_number)} — ${escHtml(c.title)}</option>`).join('');
  }
}

setupDropZone('ev-drop-zone', 'ev-file', async (file) => {
  const infoEl = document.getElementById('ev-file-info');
  infoEl.innerHTML = `
    <div><strong>Selected:</strong> ${escHtml(file.name)}</div>
    <div style="color:var(--text-muted);font-size:0.82rem">Size: ${humanSize(file.size)}</div>
    <div class="file-hash" style="margin-top:0.3rem">Computing SHA-256...</div>
  `;
  infoEl.classList.remove('hidden');
  computeHashClient(file).then(hash => {
    document.querySelector('#ev-file-info .file-hash').textContent = `SHA-256: ${hash}`;
  });

  // Extract metadata from backend
  const metaPanel = document.getElementById('ev-metadata-panel');
  metaPanel.classList.remove('hidden');
  document.getElementById('ev-meta-status').textContent = 'Analyzing file...';

  const fd = new FormData();
  fd.append('file', file);
  const res = await api('POST', '/evidence/preview-metadata', fd, true);

  if (!res?.ok) {
    document.getElementById('ev-meta-status').textContent = 'Extraction failed';
    document.getElementById('meta-file-info').innerHTML = `<div style="color:var(--red);font-size:0.82rem">${res?.data?.error || 'Could not extract metadata'}</div>`;
    return;
  }

  const m = res.data.metadata;
  document.getElementById('ev-meta-status').textContent = 'Analysis complete';
  renderMetadataPreview(m);
});

function renderMetadataPreview(m) {
  // File Info
  const fileItems = [];
  if (m.filename) fileItems.push(metaItem('Filename', m.filename));
  if (m.mime_type) fileItems.push(metaItem('MIME Type', m.mime_type));
  if (m.size_human) fileItems.push(metaItem('File Size', m.size_human));
  if (m.resolution) fileItems.push(metaItem('Resolution', m.resolution));
  if (m.megapixels) fileItems.push(metaItem('Megapixels', m.megapixels + ' MP'));
  if (m.format) fileItems.push(metaItem('Format', m.format));
  if (m.mode) fileItems.push(metaItem('Color Mode', m.mode));
  if (m.bit_depth !== undefined) fileItems.push(metaItem('Bit Depth', m.bit_depth));
  if (m.color_type) fileItems.push(metaItem('Color Type', m.color_type));
  if (m.compression) fileItems.push(metaItem('Compression', m.compression));
  if (m.filter) fileItems.push(metaItem('Filter', m.filter));
  if (m.interlace) fileItems.push(metaItem('Interlace', m.interlace));
  
  if (m.file_type) fileItems.push(metaItem('File Type', m.file_type));
  if (m.line_count) fileItems.push(metaItem('Lines', m.line_count));
  if (m.word_count) fileItems.push(metaItem('Words', m.word_count));
  if (m.page_count) fileItems.push(metaItem('Pages', m.page_count));
  
  if (m.raw_header) {
    fileItems.push(`<div class="meta-item" style="grid-column: 1 / -1;"><div class="meta-label">Raw Header</div><div class="meta-val" style="word-break: break-all; white-space: normal; font-family: monospace;">${escHtml(m.raw_header)}</div></div>`);
  }
  
  document.getElementById('meta-file-info').innerHTML = `<div class="meta-section-title">File Information</div><div class="meta-grid">${fileItems.join('')}</div>`;

  // C2PA / JUMBF Info
  if (m.jumd_label || m.c2pa_present || m.actions_software_agent_name) {
    const swEl = document.getElementById('meta-software');
    swEl.classList.remove('hidden'); // we'll re-use the software section for this
    let c2paHtml = `<div class="meta-section-title" style="color:#aa00ff; margin-top:0.8rem;">C2PA / Content Credentials</div><div class="meta-grid">`;
    if (m.jumd_label) c2paHtml += metaItem('JUMBF Label', m.jumd_label);
    if (m.actions_software_agent_name) c2paHtml += metaItem('AI / Software Agent', m.actions_software_agent_name);
    if (m.claim__generator__info_name) c2paHtml += metaItem('Generator API', m.claim__generator__info_name);
    if (m.c2pa_created) c2paHtml += metaItem('Action', 'c2pa.created');
    if (m.c2pa_converted) c2paHtml += metaItem('Action', 'c2pa.converted');
    if (m.actions_digital_source_type) c2paHtml += metaItem('Digital Source Type', m.actions_digital_source_type);
    if (m.claim__generator__info_spec_version) c2paHtml += metaItem('C2PA Spec Version', m.claim__generator__info_spec_version);
    c2paHtml += `</div>`;
    
    const existing = document.getElementById('meta-software-data').innerHTML;
    document.getElementById('meta-software-data').innerHTML = existing + c2paHtml;
  }

  // Camera
  const cam = m.camera;
  if (cam && Object.keys(cam).length) {
    const camEl = document.getElementById('meta-camera');
    camEl.classList.remove('hidden');
    let items = '';
    if (cam.make) items += metaItem('Make', cam.make);
    if (cam.model) items += metaItem('Model', cam.model);
    if (cam.lens_model) items += metaItem('Lens', cam.lens_model);
    if (cam.lens_make) items += metaItem('Lens Make', cam.lens_make);
    if (cam.focal_length) items += metaItem('Focal Length', cam.focal_length);
    if (cam.focal_length_35mm) items += metaItem('35mm Equiv.', cam.focal_length_35mm);
    if (cam.aperture) items += metaItem('Aperture', cam.aperture);
    if (cam.exposure_time) items += metaItem('Exposure', cam.exposure_time);
    if (cam.iso) items += metaItem('ISO', cam.iso);
    if (cam.flash) items += metaItem('Flash', cam.flash);
    if (cam.white_balance) items += metaItem('White Bal.', cam.white_balance);
    if (cam.metering_mode) items += metaItem('Metering', cam.metering_mode);
    document.getElementById('meta-camera-data').innerHTML = items;
  }

  // GPS
  const gps = m.gps;
  if (gps && Object.keys(gps).length && !gps.gps_error) {
    const gpsEl = document.getElementById('meta-gps');
    gpsEl.classList.remove('hidden');
    let items = '';
    if (gps.latitude !== undefined) items += metaItem('Latitude', gps.latitude);
    if (gps.longitude !== undefined) items += metaItem('Longitude', gps.longitude);
    if (gps.altitude_m !== undefined) items += metaItem('Altitude', gps.altitude_m + ' m');
    if (gps.altitude_ref) items += metaItem('Alt. Ref', gps.altitude_ref);
    if (gps.speed) items += metaItem('Speed', gps.speed + ' ' + (gps.speed_ref || 'km/h'));
    if (gps.gps_date) items += metaItem('GPS Date', gps.gps_date);
    if (gps.gps_time) items += metaItem('GPS Time', gps.gps_time);
    if (gps.maps_url) items += `<div class="meta-item" style="grid-column:1/-1"><a href="${escHtml(gps.maps_url)}" target="_blank" class="meta-link">Open in Google Maps</a></div>`;
    document.getElementById('meta-gps-data').innerHTML = items;
  }

  // Software
  const sw = m.software;
  const detected = m.detected_software;
  if ((sw && Object.keys(sw).length) || (detected && detected.length)) {
    const swEl = document.getElementById('meta-software');
    swEl.classList.remove('hidden');
    let items = '';
    if (sw) {
      if (sw.software) items += metaItem('Software', sw.software);
      if (sw.processing_software) items += metaItem('Processing', sw.processing_software);
      if (sw.host_computer) items += metaItem('Device', sw.host_computer);
      if (sw.artist) items += metaItem('Artist', sw.artist);
      if (sw.copyright) items += metaItem('Copyright', sw.copyright);
    }
    if (detected && detected.length) {
      items += metaItem('Detected', detected.join(', '));
    }
    // PDF / Office metadata
    if (m.pdf_producer) items += metaItem('PDF Producer', m.pdf_producer);
    if (m.pdf_creator) items += metaItem('PDF Creator', m.pdf_creator);
    if (m.doc_application) items += metaItem('Application', m.doc_application);
    if (m.doc_creator) items += metaItem('Author', m.doc_creator);
    if (m.doc_lastmodifiedby) items += metaItem('Last Modified By', m.doc_lastmodifiedby);
    if (m.doc_company) items += metaItem('Company', m.doc_company);
    document.getElementById('meta-software-data').innerHTML = items;
  }

  // Editing Analysis
  const ea = m.editing_analysis;
  if (ea) {
    const edEl = document.getElementById('meta-editing');
    edEl.classList.remove('hidden');
    const conf = ea.confidence || 'low';
    const badgeClass = ea.likely_edited ? (conf === 'high' ? 'meta-badge-red' : 'meta-badge-yellow') : 'meta-badge-green';
    const statusText = ea.likely_edited ? `LIKELY EDITED (${conf} confidence)` : 'APPEARS ORIGINAL';
    let html = `<div style="margin-bottom:0.5rem"><span class="meta-badge ${badgeClass}">${statusText}</span></div>`;
    if (ea.indicators && ea.indicators.length) {
      html += '<ul style="margin:0;padding-left:1.2rem;font-size:0.78rem;color:var(--text-dim)">';
      ea.indicators.forEach(ind => { html += `<li style="margin:0.15rem 0">${escHtml(ind)}</li>`; });
      html += '</ul>';
    }
    document.getElementById('meta-editing-data').innerHTML = html;
  }

  // Timestamps
  const ts = m.timestamps;
  if (ts && Object.keys(ts).length) {
    const tsEl = document.getElementById('meta-timestamps');
    tsEl.classList.remove('hidden');
    let items = '';
    if (ts.date_original) items += metaItem('Original', ts.date_original);
    if (ts.date_digitized) items += metaItem('Digitized', ts.date_digitized);
    if (ts.date_time) items += metaItem('Modified', ts.date_time);
    document.getElementById('meta-timestamps-data').innerHTML = items;
  }

  // Raw JSON
  document.getElementById('meta-raw-json').textContent = JSON.stringify(m, null, 2);
}

function metaItem(label, value) {
  return `<div class="meta-item"><div class="meta-label">${escHtml(label)}</div><div class="meta-val">${escHtml(String(value))}</div></div>`;
}

function resetMetadataPanel() {
  document.getElementById('ev-metadata-panel').classList.add('hidden');
  ['meta-camera','meta-gps','meta-software','meta-editing','meta-timestamps'].forEach(id => {
    document.getElementById(id).classList.add('hidden');
  });
  ['meta-camera-override','meta-gps-override','meta-software-override','meta-editing-override','meta-general-notes'].forEach(id => {
    document.getElementById(id).value = '';
  });
}

document.getElementById('evidence-upload-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('ev-file');
  const errEl = document.getElementById('upload-error');
  errEl.classList.add('hidden');

  if (!fileInput.files.length) { errEl.textContent = 'Please select a file'; errEl.classList.remove('hidden'); return; }
  if (!document.getElementById('ev-case-id').value) { errEl.textContent = 'Please select a case'; errEl.classList.remove('hidden'); return; }

  const btn = document.getElementById('upload-btn');
  btn.disabled = true;
  btn.textContent = 'Uploading & Hashing...';

  document.getElementById('upload-progress').classList.remove('hidden');
  animateProgressBar();

  // Collect user metadata overrides
  const overrides = {
    camera_override: document.getElementById('meta-camera-override')?.value || '',
    gps_override: document.getElementById('meta-gps-override')?.value || '',
    software_override: document.getElementById('meta-software-override')?.value || '',
    editing_override: document.getElementById('meta-editing-override')?.value || '',
    notes: document.getElementById('meta-general-notes')?.value || ''
  };

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('case_id', document.getElementById('ev-case-id').value);
  fd.append('evidence_type', document.getElementById('ev-type').value);
  fd.append('description', document.getElementById('ev-description').value);
  fd.append('location_found', document.getElementById('ev-location').value);
  fd.append('tags', document.getElementById('ev-tags').value);
  fd.append('metadata_overrides', JSON.stringify(overrides));

  const res = await api('POST', '/evidence/upload', fd, true);

  btn.disabled = false;
  btn.textContent = 'Register Evidence on Blockchain';
  document.getElementById('upload-progress').classList.add('hidden');

  const resultEl = document.getElementById('upload-result');
  if (res?.ok) {
    const ev = res.data.evidence;
    const bc = res.data.blockchain;
    resultEl.className = 'upload-result success';
    resultEl.innerHTML = `
      <h3 style="color:var(--green);margin-bottom:0.8rem">[+] Evidence Registered Successfully</h3>
      <div><strong>Evidence Number:</strong> ${ev.evidence_number}</div>
      <div><strong>File:</strong> ${escHtml(ev.original_filename)} (${ev.file_size_human})</div>
      <div class="hash-display">SHA-256: ${ev.sha256_hash}</div>
      <div class="hash-display">Blockchain TX: ${bc.tx_hash || 'N/A'}</div>
      <div class="hash-display">Block #${bc.block_number || 'N/A'} - Mode: ${bc.mode}</div>
      <div style="margin-top:0.7rem;display:flex;gap:0.7rem;flex-wrap:wrap">
        <button class="btn btn-outline" onclick="openEvidenceDetail(${ev.id})">View Detail</button>
        <button class="btn btn-primary" onclick="downloadCertificate(${ev.id})">Download Certificate</button>
      </div>`;
    resultEl.classList.remove('hidden');
    document.getElementById('evidence-upload-form').reset();
    document.getElementById('ev-file-info').classList.add('hidden');
    resetMetadataPanel();
    toast('Evidence registered on blockchain!', 'success');
  } else {
    resultEl.className = 'upload-result error';
    resultEl.innerHTML = `<h3 style="color:var(--red)">[-] Upload Failed</h3><p>${res?.data?.error || 'Unknown error'}</p>`;
    resultEl.classList.remove('hidden');
    toast(res?.data?.error || 'Upload failed', 'error');
  }
});

function animateProgressBar() {
  let w = 0;
  const bar = document.getElementById('upload-prog-bar');
  const msgs = ['Computing SHA-256...', 'Validating file...', 'Registering on blockchain...', 'Finalizing...'];
  let msgIdx = 0;
  const t = setInterval(() => {
    w = Math.min(w + Math.random() * 8, 90);
    bar.style.width = w + '%';
    if (w > 30 * (msgIdx+1) && msgIdx < msgs.length - 1) {
      document.getElementById('upload-prog-text').textContent = msgs[++msgIdx];
    }
  }, 200);
  setTimeout(() => { clearInterval(t); bar.style.width = '100%'; }, 8000);
}

// ── Evidence Library ─────────────────────────────────────
async function loadEvidenceList() {
  document.getElementById('evidence-table-wrap').innerHTML = '<div class="loading-pulse">Loading...</div>';
  const res = await api('GET', '/dashboard/recent');
  const casesRes = await api('GET', '/cases');
  const allCasesMap = {};
  (casesRes?.data?.cases || []).forEach(c => allCasesMap[c.id] = c.case_number);

  if (!res?.ok) { document.getElementById('evidence-table-wrap').innerHTML = '<div class="alert-error">Failed to load evidence</div>'; return; }
  allEvidence = res.data.recent_evidence || [];

  // Also fetch all cases and their evidence
  const evAll = [];
  for (const c of (casesRes?.data?.cases || [])) {
    const cr = await api('GET', `/cases/${c.id}`);
    if (cr?.ok) (cr.data.case.evidence || []).forEach(e => { e._case_number = c.case_number; evAll.push(e); });
  }
  allEvidence = evAll;
  renderEvidenceTable(allEvidence, allCasesMap);

  // Search/filter
  ['ev-search', 'ev-status-filter', 'ev-type-filter'].forEach(id => {
    document.getElementById(id).oninput = () => filterEvidence(allCasesMap);
    document.getElementById(id).onchange = () => filterEvidence(allCasesMap);
  });
}

function filterEvidence(casesMap) {
  const q = document.getElementById('ev-search').value.toLowerCase();
  const s = document.getElementById('ev-status-filter').value;
  const t = document.getElementById('ev-type-filter').value;
  renderEvidenceTable(allEvidence.filter(e =>
    (!q || e.original_filename.toLowerCase().includes(q) || e.evidence_number.toLowerCase().includes(q) || (e.sha256_hash||'').includes(q)) &&
    (!s || e.status === s) && (!t || e.evidence_type === t)
  ), casesMap);
}

function renderEvidenceTable(evList, casesMap = {}) {
  const wrap = document.getElementById('evidence-table-wrap');
  if (!evList.length) { wrap.innerHTML = '<div class="loading-pulse">No evidence found.</div>'; return; }

  const canTransfer = currentUser.role === 'investigator';

  wrap.innerHTML = `
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Number</th><th>Filename</th><th>Type</th><th>SHA-256</th><th>Case</th><th>Status</th><th>Uploaded</th><th>Actions</th></tr></thead>
        <tbody>
          ${evList.map(e => `<tr>
            <td style="font-family:var(--mono);font-size:0.73rem;color:var(--accent)">${e.evidence_number}</td>
            <td><div class="ev-filename">${escHtml(e.original_filename)}</div><div style="font-size:0.72rem;color:var(--text-muted)">${e.file_size_human||''}</div></td>
            <td><span class="tag tag-${e.evidence_type==='malware'?'tampered':e.evidence_type==='pcap'?'active':'pending'}">${typeIcon(e.evidence_type)} ${e.evidence_type}</span></td>
            <td><div class="ev-hash" onclick="copyText('${e.sha256_hash}', this)" title="${e.sha256_hash}">${e.sha256_hash?.substring(0,16)}...</div></td>
            <td style="font-size:0.78rem;color:var(--text-dim)">${escHtml(e._case_number || casesMap[e.case_id] || '—')}</td>
            <td><span class="tag tag-${e.status}">${e.status}</span></td>
            <td style="font-size:0.75rem;color:var(--text-muted)">${timeAgo(e.created_at)}</td>
            <td><div class="actions-col">
              <button class="btn btn-xs btn-outline" onclick="openEvidenceDetail(${e.id})">View</button>
              ${canTransfer ? `<button class="btn btn-xs btn-outline" onclick="openTransferModal(${e.id}, '${escHtml(e.evidence_number)}')">Transfer</button>` : ''}
              <button class="btn btn-xs btn-ghost" onclick="downloadCertificate(${e.id})"> Cert</button>
            </div></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

async function openEvidenceDetail(evId) {
  const res = await api('GET', `/evidence/${evId}`);
  if (!res?.ok) { toast('Failed to load evidence', 'error'); return; }
  const e = res.data.evidence;
  const meta = res.data.evidence.metadata || {};
  const custody = res.data.evidence.custody_logs || [];

  document.getElementById('ev-detail-title').textContent = `${e.evidence_number} — ${e.original_filename}`;

  const verifyBtn = `<button class="btn btn-xs btn-outline" onclick="verifyEvidenceIntegrity(${e.id})"> Verify Integrity</button>`;
  const certBtn = `<button class="btn btn-xs btn-primary" onclick="downloadCertificate(${e.id})"> Certificate</button>`;
  const downloadBtn = `<button class="btn btn-xs btn-ghost" onclick="downloadEvidence(${e.id})">⬇ Download</button>`;
  const noteBtn = (currentUser.role === 'analyst') ?
    `<button class="btn btn-xs btn-success" onclick="openNoteModal(${e.id})"> Add Note</button>` : '';

  document.getElementById('ev-detail-body').innerHTML = `
    <div style="display:flex;gap:0.7rem;flex-wrap:wrap;margin-bottom:1.2rem">${verifyBtn}${certBtn}${downloadBtn}${noteBtn}</div>
    <div class="detail-grid">
      <div class="detail-item"><label>Evidence Number</label><div class="val mono">${e.evidence_number}</div></div>
      <div class="detail-item"><label>Status</label><span class="tag tag-${e.status}">${e.status}</span></div>
      <div class="detail-item"><label>Original Filename</label><div class="val">${escHtml(e.original_filename)}</div></div>
      <div class="detail-item"><label>File Size</label><div class="val">${e.file_size_human || '—'}</div></div>
      <div class="detail-item"><label>MIME Type</label><div class="val">${e.mime_type || '—'}</div></div>
      <div class="detail-item"><label>Evidence Type</label><div class="val">${e.evidence_type}</div></div>
      <div class="detail-item"><label>Uploaded By</label><div class="val">${escHtml(e.uploader_name)}</div></div>
      <div class="detail-item"><label>Upload Date</label><div class="val">${e.created_at ? e.created_at.replace('T', ' ').split('.')[0] : '—'}</div></div>
    </div>
    <div style="margin-bottom:1rem">
      <label>SHA-256 Hash</label>
      <div class="hash-display" style="cursor:pointer" onclick="copyText('${e.sha256_hash}', this)">${e.sha256_hash}<br><small style="color:var(--text-muted)">(click to copy)</small></div>
    </div>
    <div style="margin-bottom:1rem">
      <label>Blockchain TX</label>
      <div class="hash-display">${e.blockchain_tx || '—'}</div>
    </div>
    ${e.description ? `<div style="margin-bottom:1rem"><label>Description</label><p style="font-size:0.88rem;color:var(--text)">${escHtml(e.description)}</p></div>` : ''}
    <div style="margin-bottom:1rem">
      <label>Chain of Custody (${custody.length} events)</label>
      <div class="custody-timeline">
        ${custody.map(cl=>`<div class="custody-item"><div class="custody-dot"></div><div class="custody-text"><strong>${cl.action}</strong> · ${cl.timestamp.replace('T', ' ').split('.')[0]} (IP: ${escHtml(cl.ip_address)})<br>${escHtml(cl.details||'')}</div></div>`).join('') || '<div class="loading-pulse">No custody events</div>'}
      </div>
    </div>
    <div id="ev-verify-result-${e.id}"></div>`;

  document.getElementById('evidence-detail-modal').classList.remove('hidden');
}

async function verifyEvidenceIntegrity(evId) {
  const resultEl = document.getElementById(`ev-verify-result-${evId}`);
  if (resultEl) { resultEl.innerHTML = '<div class="loading-pulse">Verifying...</div>'; }
  const res = await api('GET', `/evidence/${evId}/verify`);
  if (!res?.ok) { toast('Verification failed', 'error'); return; }
  const r = res.data;
  const cls = r.verified ? 'verified' : 'tampered';
  if (resultEl) {
    resultEl.innerHTML = `
      <div class="verify-result ${cls}">
        <div class="result-title">${r.verified ? '[+] VERIFIED — Evidence Untampered' : '[-] TAMPERED — Hash Mismatch Detected'}</div>
        <div class="result-hash">Stored: ${r.stored_hash}</div>
        <div class="result-hash">Current: ${r.current_hash}</div>
        <div class="result-hash">Block #: ${r.blockchain_record?.index !== undefined ? r.blockchain_record.index : (r.blockchain_record?.block || 'N/A')}</div>
      </div>`;
  }
  toast(r.verified ? 'Evidence verified!' : 'Evidence tampered!', r.verified ? 'success' : 'error');
}

async function downloadEvidence(evId) {
  window.open(`/api/evidence/${evId}/download?token=${token}`, '_blank');
}

async function downloadCertificate(evId) {
  toast('Generating PDF certificate...', 'info');
  const res = await fetch(`/api/certificate/${evId}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) { toast('Certificate generation failed', 'error'); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `certificate_${evId}.pdf`; a.click();
  URL.revokeObjectURL(url);
  toast('Certificate downloaded!', 'success');
}

// ── Transfer Modal ───────────────────────────────────────
async function openTransferModal(evId, evNum) {
  const usersRes = await api('GET', '/users');
  const users = usersRes?.data?.users?.filter(u => u.is_active && u.id !== currentUser.id) || [];
  const html = `
    <div class="modal hidden" id="transfer-modal-dyn">
      <div class="modal-backdrop" onclick="document.getElementById('transfer-modal-dyn').remove()"></div>
      <div class="modal-box glass-card">
        <div class="modal-header"><h3> Transfer Evidence ${escHtml(evNum)}</h3><button class="modal-close" onclick="document.getElementById('transfer-modal-dyn').remove()">x</button></div>
        <div class="form-group"><label>Transfer To</label>
          <select id="transfer-to-select">${users.map(u=>`<option value="${u.id}">${escHtml(u.full_name||u.username)} (${u.role})</option>`).join('')}</select>
        </div>
        <div class="form-group"><label>Reason *</label><textarea id="transfer-reason" rows="3" placeholder="State reason for custody transfer..."></textarea></div>
        <div class="modal-actions">
          <button class="btn btn-ghost" onclick="document.getElementById('transfer-modal-dyn').remove()">Cancel</button>
          <button class="btn btn-primary" onclick="submitTransfer(${evId})">Transfer Custody</button>
        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML('beforeend', html);
  document.getElementById('transfer-modal-dyn').classList.remove('hidden');
}

async function submitTransfer(evId) {
  const toUser = document.getElementById('transfer-to-select').value;
  const reason = document.getElementById('transfer-reason').value;
  if (!reason.trim()) { toast('Reason is required', 'error'); return; }
  const res = await api('POST', `/evidence/${evId}/transfer`, { to_user_id: parseInt(toUser), reason });
  document.getElementById('transfer-modal-dyn')?.remove();
  if (res?.ok) { toast('Evidence transferred!', 'success'); loadEvidenceList(); }
  else toast(res?.data?.error || 'Transfer failed', 'error');
}

// ── Analyst Section ──────────────────────────────────────
async function loadAnalystSection() {
  const evEl = document.getElementById('analyst-evidence-list');
  evEl.innerHTML = '<div class="loading-pulse">Loading assigned evidence...</div>';
  const casesRes = await api('GET', '/cases');
  const cases = casesRes?.data?.cases || [];
  const evAll = [];
  for (const c of cases) {
    const cr = await api('GET', `/cases/${c.id}`);
    if (cr?.ok) (cr.data.case.evidence || []).forEach(e => { e._case_number = c.case_number; evAll.push(e); });
  }

  if (!evAll.length) { evEl.innerHTML = '<div class="loading-pulse">No evidence assigned to your cases.</div>'; return; }
  evEl.innerHTML = evAll.map(e => `
    <div class="glass-card" style="padding:1rem;margin-bottom:0.8rem;display:flex;align-items:center;gap:1rem">
      <div style="font-size:1.5rem">${typeIcon(e.evidence_type)}</div>
      <div style="flex:1">
        <div style="font-weight:600">${escHtml(e.original_filename)}</div>
        <div style="font-size:0.78rem;color:var(--text-muted)">${e.evidence_number} · ${escHtml(e._case_number||'')}</div>
        <div style="font-size:0.78rem;color:var(--text-muted)">SHA-256: <span style="font-family:var(--mono)">${e.sha256_hash?.substring(0,32)}...</span></div>
      </div>
      <div style="display:flex;flex-direction:column;gap:0.4rem">
        <span class="tag tag-${e.status}">${e.status}</span>
        <button class="btn btn-xs btn-outline" onclick="openEvidenceDetail(${e.id})">View</button>
        <button class="btn btn-xs btn-success" onclick="openNoteModal(${e.id})"> Add Note</button>
      </div>
    </div>`).join('');
}

function openNoteModal(evId) {
  document.getElementById('note-evidence-id').value = evId;
  document.getElementById('note-content').value = '';
  document.getElementById('note-error').classList.add('hidden');
  document.getElementById('note-modal').classList.remove('hidden');
}

async function submitNote() {
  const evId = document.getElementById('note-evidence-id').value;
  const content = document.getElementById('note-content').value;
  const classification = document.getElementById('note-classification').value;
  const errEl = document.getElementById('note-error');
  if (!content.trim()) { errEl.textContent = 'Note content required'; errEl.classList.remove('hidden'); return; }
  const res = await api('POST', `/evidence/${evId}/notes`, { content, classification });
  if (res?.ok) { closeModal('note-modal'); toast('Analysis note saved!', 'success'); }
  else { errEl.textContent = res?.data?.error || 'Failed to save note'; errEl.classList.remove('hidden'); }
}

// ── User Management ──────────────────────────────────────
async function loadUsers() {
  document.getElementById('users-table-wrap').innerHTML = '<div class="loading-pulse">Loading...</div>';
  const res = await api('GET', '/users');
  if (!res?.ok) return;
  const users = res.data.users || [];
  document.getElementById('users-table-wrap').innerHTML = `
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Department</th><th>Badge</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
        <tbody>
          ${users.map(u => `<tr class="${u.is_active ? '' : 'user-row-inactive'}">
            <td><strong>${escHtml(u.full_name||'—')}</strong></td>
            <td style="font-family:var(--mono);font-size:0.82rem">${escHtml(u.username)}</td>
            <td style="font-size:0.8rem;color:var(--text-muted)">${escHtml(u.email)}</td>
            <td><span class="user-role-badge role-${u.role}">${u.role}</span></td>
            <td style="font-size:0.8rem">${escHtml(u.department||'—')}</td>
            <td style="font-family:var(--mono);font-size:0.8rem">${escHtml(u.badge_number||'—')}</td>
            <td><span class="tag ${u.is_active ? 'tag-verified' : 'tag-tampered'}">${u.is_active ? 'Active' : 'Inactive'}</span></td>
            <td style="font-size:0.75rem;color:var(--text-muted)">${u.last_login ? timeAgo(u.last_login) : 'Never'}</td>
            <td><div class="actions-col">
              <button class="btn btn-xs btn-outline" onclick="editUser(${JSON.stringify(u).replace(/"/g,'&quot;')})">Edit</button>
              <button class="btn btn-xs btn-${u.is_active ? 'danger' : 'success'}" onclick="toggleUserActive(${u.id}, ${u.is_active})">${u.is_active ? 'Disable' : 'Enable'}</button>
              ${u.id !== currentUser.id ? `<button class="btn btn-xs btn-danger" onclick="deleteUser(${u.id}, '${escHtml(u.username)}')">Delete</button>` : ''}
            </div></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

function openCreateUser() {
  document.getElementById('user-modal-title').textContent = 'Add New User';
  document.getElementById('user-form').reset();
  document.getElementById('user-id-edit').value = '';
  document.getElementById('user-pw-label').textContent = 'Password *';
  document.getElementById('user-password').required = true;
  document.getElementById('user-error').classList.add('hidden');
  document.getElementById('user-modal').classList.remove('hidden');
}

function editUser(u) {
  document.getElementById('user-modal-title').textContent = 'Edit User';
  document.getElementById('user-id-edit').value = u.id;
  document.getElementById('user-username').value = u.username;
  document.getElementById('user-email').value = u.email;
  document.getElementById('user-fullname').value = u.full_name || '';
  document.getElementById('user-role').value = u.role;
  document.getElementById('user-dept').value = u.department || '';
  document.getElementById('user-badge').value = u.badge_number || '';
  document.getElementById('user-password').value = '';
  document.getElementById('user-pw-label').textContent = 'New Password (leave blank to keep)';
  document.getElementById('user-password').required = false;
  document.getElementById('user-error').classList.add('hidden');
  document.getElementById('user-modal').classList.remove('hidden');
}

document.getElementById('user-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('user-error');
  errEl.classList.add('hidden');
  const uid = document.getElementById('user-id-edit').value;
  const body = {
    username: document.getElementById('user-username').value,
    email: document.getElementById('user-email').value,
    role: document.getElementById('user-role').value,
    full_name: document.getElementById('user-fullname').value,
    department: document.getElementById('user-dept').value,
    badge_number: document.getElementById('user-badge').value,
  };
  const pw = document.getElementById('user-password').value;
  if (pw) body.password = pw;
  if (!uid) body.password = pw;

  const res = uid ? await api('PUT', `/users/${uid}`, body) : await api('POST', '/users', body);
  if (res?.ok) {
    closeModal('user-modal');
    toast(uid ? 'User updated' : 'User created', 'success');
    loadUsers();
  } else {
    errEl.textContent = res?.data?.error || 'Failed';
    errEl.classList.remove('hidden');
  }
});

async function toggleUserActive(uid, isActive) {
  const res = await api('PUT', `/users/${uid}`, { is_active: !isActive });
  if (res?.ok) { toast(isActive ? 'User disabled' : 'User enabled', 'success'); loadUsers(); }
}

async function deleteUser(uid, uname) {
  if (!confirm(`Delete user "${uname}"? This is permanent.`)) return;
  const res = await api('DELETE', `/users/${uid}`);
  if (res?.ok) { toast('User deleted', 'success'); loadUsers(); }
  else toast(res?.data?.error || 'Failed', 'error');
}

// ── Audit Logs ───────────────────────────────────────────
async function loadAuditLogs() {
  document.getElementById('audit-table-wrap').innerHTML = '<div class="loading-pulse">Loading...</div>';
  const sev = document.getElementById('audit-severity')?.value || '';
  const res = await api('GET', `/audit/logs?per_page=100&severity=${sev}`);
  if (!res?.ok) return;
  const logs = res.data.logs || [];
  document.getElementById('audit-table-wrap').innerHTML = logs.length ? `
    <div style="display:flex;justify-content:flex-end;margin-bottom:0.8rem">
      <button class="btn btn-danger-ghost btn-xs" onclick="clearAllAuditLogs()"> Clear All Logs</button>
    </div>
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>IP</th><th>Severity</th><th>Details</th><th>Action</th></tr></thead>
        <tbody>
          ${logs.map(l => `<tr>
            <td style="font-family:var(--mono);font-size:0.73rem;white-space:nowrap">${fmtDate(l.timestamp)}</td>
            <td style="font-size:0.82rem">${escHtml(l.username || 'System')}</td>
            <td style="font-size:0.8rem;font-weight:600">${escHtml(l.action.replace(/_/g,' '))}</td>
            <td style="font-size:0.78rem;color:var(--text-muted)">${escHtml(l.resource_type || '')} ${l.resource_id ? '#'+l.resource_id : ''}</td>
            <td style="font-family:var(--mono);font-size:0.75rem;color:var(--text-muted)">${l.ip_address || '—'}</td>
            <td><span class="severity-${l.severity}" style="font-size:0.78rem;font-weight:700;text-transform:uppercase">${l.severity}</span></td>
            <td style="font-size:0.78rem;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis">${escHtml(l.details || '—')}</td>
            <td><button class="btn btn-xs btn-danger-ghost" onclick="deleteAuditLog(${l.id})" title="Delete Log">x</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>` : '<div class="loading-pulse">No logs found</div>';
}

async function deleteAuditLog(id) {
  if (!confirm('Permanently delete this specific system log?')) return;
  const res = await api('DELETE', `/audit/logs/${id}`);
  if (res?.ok) { toast('Log deleted', 'success'); loadAuditLogs(); }
}

async function clearAllAuditLogs() {
  if (!confirm('WARNING: Are you sure you want to completely clear ALL system logs? This action is irreversible!')) return;
  const res = await api('DELETE', `/audit/logs/clear`);
  if (res?.ok) { toast('All logs cleared', 'success'); loadAuditLogs(); }
}

// ── Blockchain Status ────────────────────────────────────
async function loadBlockchainStatus() {
  const res = await api('GET', '/blockchain/status');
  if (!res?.ok) return;
  const d = res.data;
  document.getElementById('bc-status-val').textContent = d.connected ? '[ON] Online' : '[OFF] Offline';
  document.getElementById('bc-block-val').textContent = (d.block_number || '—').toLocaleString?.() || d.block_number || '—';
  document.getElementById('bc-records-val').textContent = d.record_count || 0;
  document.getElementById('bc-mode-val').textContent = (d.mode || '—').toUpperCase();
  document.getElementById('bc-mode-desc').textContent = d.connected
    ? `Connected to Ganache at ${d.rpc_url}` : `Simulation Mode — ${d.note || ''}`;
}

async function verifyHashInline() {
  const hash = document.getElementById('bc-hash-input').value.trim();
  const resultEl = document.getElementById('bc-verify-result');
  if (hash.length !== 64) { toast('Invalid hash length (must be 64 hex chars)', 'error'); return; }
  const res = await api('POST', '/public/verify-hash', { hash });
  if (!res?.ok) { toast('Verification failed', 'error'); return; }
  const r = res.data;
  const cls = r.result === 'verified' ? 'verified' : 'not-found';
  resultEl.className = `verify-result ${cls}`;
  resultEl.innerHTML = `<div class="result-title">${r.status_text}</div>
    ${r.evidence_number ? `<div class="result-hash">Evidence: ${escHtml(r.evidence_number)}</div>` : ''}
    <div class="result-hash">Hash: ${escHtml(hash)}</div>`;
  resultEl.classList.remove('hidden');
}

async function verifyByHash() {
  const hash = document.getElementById('pv-hash-input').value.trim().toLowerCase();
  if (!hash) return;
  if (!guestToken) { toast('Guest session expired. Please sign in again.', 'error'); endGuestSession(); return; }
  const resultEl = document.getElementById('public-result');
  resultEl.className = 'verify-result pending';
  resultEl.innerHTML = '<div class="result-title">Verifying...</div>';
  resultEl.classList.remove('hidden');
  const res = await api('POST', '/public/verify-hash', { hash }, false, true);
  if (!res?.ok) {
    if (res?.status === 401) {
      resultEl.className = 'verify-result tampered';
      resultEl.innerHTML = '<div class="result-title">[EXPIRED] Session Expired</div><p>Please sign in as guest again.</p>';
      endGuestSession();
      return;
    }
    resultEl.className = 'verify-result tampered';
    resultEl.innerHTML = '<div class="result-title">[ERROR] Verification Error</div>';
    return;
  }
  const r = res.data;
  const cls = r.result === 'verified' ? 'verified' : 'not-found';
  resultEl.className = `verify-result ${cls}`;
  resultEl.innerHTML = `<div class="result-title">${r.status_text}</div><div class="result-hash">Hash: ${escHtml(hash)}</div>${r.evidence_number ? `<div class="result-hash">Evidence #: ${escHtml(r.evidence_number)}</div>` : ''}`;
}

// ── Guest Login ──────────────────────────────────────────
document.getElementById('guest-login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('guest-login-btn');
  const errEl = document.getElementById('guest-login-error');
  errEl.classList.add('hidden');
  btn.querySelector('.btn-text').textContent = 'AUTHENTICATING...';
  btn.querySelector('.btn-loader').classList.remove('hidden');

  const username = document.getElementById('guest-username').value.trim();
  const password = document.getElementById('guest-password').value;

  const res = await api('POST', '/auth/login', { username, password });

  btn.querySelector('.btn-text').textContent = 'SIGN IN AS GUEST';
  btn.querySelector('.btn-loader').classList.add('hidden');

  if (res?.ok) {
    const user = res.data.user;
    if (user.role !== 'guest') {
      // Non-guest user tried to use guest tab - redirect to staff login
      token = res.data.token;
      currentUser = user;
      localStorage.setItem('cf_token', token);
      localStorage.setItem('cf_user', JSON.stringify(currentUser));
      enterApp();
      return;
    }
    guestToken = res.data.token;
    sessionStorage.setItem('cf_guest_token', guestToken);
    sessionStorage.setItem('cf_guest_name', user.full_name || username);
    showGuestVerifyStep(user.full_name || username);
  } else {
    errEl.textContent = res?.data?.error || 'Invalid credentials. Contact admin for guest access.';
    errEl.classList.remove('hidden');
  }
});

function showGuestVerifyStep(name) {
  document.getElementById('guest-login-step').classList.add('hidden');
  document.getElementById('guest-verify-step').classList.remove('hidden');
  document.getElementById('guest-session-name').textContent = name || 'Guest';
  // Re-initialize drop zone for the now-visible elements
  setupDropZone('pv-drop-zone', 'pv-file', (file) => {
    const fn = document.getElementById('pv-file-name');
    fn.textContent = `Selected: ${file.name} (${humanSize(file.size)})`;
    fn.classList.remove('hidden');
  });
}

function endGuestSession() {
  guestToken = null;
  sessionStorage.removeItem('cf_guest_token');
  sessionStorage.removeItem('cf_guest_name');
  document.getElementById('guest-verify-step').classList.add('hidden');
  document.getElementById('guest-login-step').classList.remove('hidden');
  document.getElementById('guest-login-form').reset();
  document.getElementById('public-result').classList.add('hidden');
  document.getElementById('pv-file-name').classList.add('hidden');
}

// ── Public Verification ──────────────────────────────────
setupDropZone('pv-drop-zone', 'pv-file', (file) => {
  const fn = document.getElementById('pv-file-name');
  fn.textContent = `Selected: ${file.name} (${humanSize(file.size)})`;
  fn.classList.remove('hidden');
});

document.getElementById('public-verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('pv-file');
  const resultEl = document.getElementById('public-result');
  if (!fileInput.files.length) { toast('Please select a file', 'error'); return; }
  if (!guestToken) { toast('Guest session expired. Please sign in again.', 'error'); endGuestSession(); return; }

  resultEl.className = 'verify-result pending';
  resultEl.innerHTML = '<div class="result-title">Computing hash and verifying...</div>';
  resultEl.classList.remove('hidden');

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('verifier_name', sessionStorage.getItem('cf_guest_name') || 'Guest');
  fd.append('verifier_org', '');

  const res = await api('POST', '/public/verify', fd, true, true);
  if (!res?.ok) {
    if (res?.status === 401) {
      resultEl.className = 'verify-result tampered';
      resultEl.innerHTML = '<div class="result-title">[EXPIRED] Session Expired</div><p>Please sign in as guest again.</p>';
      endGuestSession();
      return;
    }
    resultEl.className = 'verify-result tampered';
    resultEl.innerHTML = `<div class="result-title">[ERROR] ${res?.data?.error || 'Verification failed'}</div>`;
    return;
  }
  const r = res.data;
  const cls = r.result === 'verified' ? 'verified' : r.result === 'verified_db_only' ? 'pending' : 'not-found';
  resultEl.className = `verify-result ${cls}`;
  resultEl.innerHTML = `
    <div class="result-title">${r.status_text}</div>
    <div class="result-hash" style="margin-top:0.5rem">SHA-256: ${r.hash}</div>
    ${r.evidence_number ? `<div class="result-hash">Evidence #: ${r.evidence_number}</div>` : ''}
    ${r.upload_date ? `<div class="result-hash">Registered: ${fmtDate(r.upload_date)}</div>` : ''}
    <div class="result-hash">Blockchain: ${r.found_on_blockchain ? '[+] Found' : '[-] Not Found'}</div>
    ${r.blockchain_record && r.found_on_blockchain ? `<div class="result-hash">Block #: ${r.blockchain_record.index !== undefined ? r.blockchain_record.index : (r.blockchain_record.block || 'N/A')}</div><div class="result-hash">Block TS: ${fmtDate(r.blockchain_record.timestamp || r.blockchain_record.ts)}</div>` : ''}`;
});

// ── Utilities ────────────────────────────────────────────
function closeModal(id) { document.getElementById(id)?.classList.add('hidden'); }

function copyText(text, el) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = el.textContent;
    el.textContent = 'Copied!';
    setTimeout(() => el.textContent = orig, 1200);
  });
}

function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function humanSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(1) + ' GB';
}

function typeIcon(type) {
  const icons = { pcap: '\u25C8', image: '\u25A3', log: '\u25AB', document: '\u25A4', video: '\u25B6', malware: '\u2620', database: '\u25A6', email: '\u25C7', other: '\u25A1' };
  return icons[type] || '\u25A1';
}

function setupDropZone(zoneId, inputId, callback) {
  const zone = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  if (!zone || !input) return;

  zone.addEventListener('click', (e) => { if (e.target !== input) input.click(); });
  input.addEventListener('change', () => { if (input.files[0]) callback(input.files[0]); });
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) {
      const dt = new DataTransfer(); dt.items.add(file); input.files = dt.files;
      callback(file);
    }
  });
}

async function computeHashClient(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Init ─────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  // Try auto-login from stored token
  const storedUser = localStorage.getItem('cf_user');
  if (token && storedUser) {
    currentUser = JSON.parse(storedUser);
    enterApp();
  }
  // Restore guest session if exists
  const storedGuestToken = sessionStorage.getItem('cf_guest_token');
  const storedGuestName = sessionStorage.getItem('cf_guest_name');
  if (storedGuestToken && storedGuestName) {
    guestToken = storedGuestToken;
    showGuestVerifyStep(storedGuestName);
  }
});
