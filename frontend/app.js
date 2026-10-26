/* CIRA dashboard. All dynamic text goes through textContent (the h() helper), never innerHTML,
   because file names on a computer can contain anything. */
(function () {
  'use strict';
  const TOKEN = document.querySelector('meta[name="cira-token"]').content;
  const $ = (id) => document.getElementById(id);

  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') el.className = v;
      else if (k === 'data') Object.assign(el.dataset, v);
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  // replaceChildren() would turn an array into the text "[object HTMLDivElement]", so flatten first.
  function fill(el, ...kids) {
    el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
  }

  async function api(path, opts) {
    opts = opts || {};
    const r = await fetch(path, {
      method: opts.method || 'GET',
      headers: { 'X-CIRA-Token': TOKEN, 'Content-Type': 'application/json' },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = null;
    try { data = await r.json(); } catch (e) { /* not JSON */ }
    if (!r.ok) throw new Error((data && data.detail) || 'Request failed (' + r.status + ')');
    return data;
  }

  const state = {
    info: null, result: null, history: [], items: [],
    picked: new Set(), open: new Set(), folders: new Set(), includeSystem: true, scanning: false,
  };
  let projEl = null;

  function notice(text, isError) {
    const n = $('notice');
    n.textContent = text;
    n.className = 'notice' + (isError ? ' err' : '');
    n.hidden = !text;
  }

  function applyWidths(root) {
    root.querySelectorAll('[data-w]').forEach((e) => { e.style.width = e.dataset.w + '%'; });
  }

  const when = (iso) => new Date(iso).toLocaleString();
  const size = (b) => b > 1e6 ? (b / 1e6).toFixed(1) + ' MB' : Math.max(1, Math.round(b / 1e3)) + ' KB';

  // ---- consent and scan -----------------------------------------------------------------------
  function renderConsent() {
    const box = $('consent');
    fill(box, 
      h('h2', { id: 'consent-h' }, 'Choose what to scan'),
      h('p', { class: 'mute' },
        'CIRA only reads files to score them. A scan changes nothing. Files move to quarantine only when you click ' +
        'the button, and you can restore them. CIRA can only look inside your user folder (' + state.info.home + ').'),
      ...state.info.folders.map((f) => h('label', { class: 'check' },
        h('input', { type: 'checkbox', checked: state.folders.has(f.path), onchange: (e) => {
          e.target.checked ? state.folders.add(f.path) : state.folders.delete(f.path);
          $('start').disabled = state.folders.size === 0 || state.scanning;
        } }),
        h('span', {}, f.name, ' ', h('span', { class: 'path' }, f.path)))),
      h('label', { class: 'check' },
        h('input', { type: 'checkbox', checked: state.includeSystem, onchange: (e) => { state.includeSystem = e.target.checked; } }),
        h('span', {}, 'Also check open ports, running programs and security settings')),
      h('div', { class: 'actions' },
        h('button', { id: 'start', disabled: state.folders.size === 0 || state.scanning, onclick: startScan },
          state.result ? 'Scan again' : 'Start scan (read-only)')));
  }

  async function startScan() {
    notice('');
    state.scanning = true;
    renderConsent();
    try {
      await api('/api/scan', { method: 'POST', body: { folders: [...state.folders], include_system: state.includeSystem } });
    } catch (e) {
      state.scanning = false;
      renderConsent();
      return notice(e.message, true);
    }
    pollScan();
  }

  const PHASES = { listing: 'Listing files…', reading: 'Reading files', scoring: 'Scoring files…',
    system: 'Checking ports, running programs and security settings…', done: 'Finishing…' };

  async function pollScan() {
    const box = $('progress');
    box.hidden = false;
    for (;;) {
      let s;
      try { s = await api('/api/scan/status'); } catch (e) { notice(e.message, true); break; }
      const label = (PHASES[s.phase] || 'Working…') + (s.phase === 'reading' && s.total ? ' ' + s.done + ' of ' + s.total : '');
      fill(box, h('p', {}, label), h('progress', { max: s.total || 1, value: s.phase === 'reading' ? s.done : 0 }));
      if (s.state === 'done') break;
      if (s.state === 'error') { notice('The scan failed. ' + s.error, true); break; }
      await new Promise((r) => setTimeout(r, 600));
    }
    box.hidden = true;
    state.scanning = false;
    await loadResult();
    renderConsent();
  }

  // ---- results --------------------------------------------------------------------------------
  async function loadResult() {
    const d = await api('/api/scan/result');
    state.result = d.result;
    state.history = d.history || [];
    renderResults();
  }

  function renderResults() {
    const r = state.result;
    $('results').hidden = !r;
    if (!r) return;
    renderHealth(r);
    renderWhatIf(r);
    renderFindings(r);
    renderSystem(r);
  }

  function renderHealth(r) {
    const hl = r.health;
    const hist = state.history.slice(-12);
    fill($('health'), 
      h('h2', { id: 'health-h' }, 'Device health'),
      h('div', { class: 'scoreline' },
        h('span', { class: 'big' }, hl.score),
        h('span', { class: 'level ' + hl.level }, hl.level)),
      h('p', { class: 'mute' },
        r.files_scanned + ' files checked' + (r.truncated ? ' (stopped at the limit)' : '') + '. ' +
        r.level_counts.High + ' high-risk and ' + r.level_counts.Medium + ' medium-risk items open. Scanned ' + when(r.finished_at) + '.'),
      hist.length > 1 ? h('div', {},
        h('div', { class: 'mute' }, 'Score over your last ' + hist.length + ' scans'),
        h('div', { class: 'spark', role: 'img', 'aria-label': 'Scores: ' + hist.map((x) => x.score).join(', ') },
          hist.map((x) => h('div', { class: 'col', title: x.score + ' on ' + when(x.at), data: { h: x.score } })))) : null,
      h('div', { class: 'actions' }, h('button', { class: 'ghost', onclick: downloadReport }, 'Download report')));
    $('health').querySelectorAll('.col').forEach((c) => { c.style.height = Math.max(3, c.dataset.h * 0.36) + 'px'; });
  }

  function renderWhatIf(r) {
    const recs = r.health.recommendations;
    state.picked = new Set([...state.picked].filter((id) => recs.some((x) => x.id === id)));
    projEl = h('div', { class: 'proj' });
    fill($('whatif'), 
      h('h2', { id: 'whatif-h' }, 'What would improve the score'),
      h('p', { class: 'mute' }, 'Best value first (points gained for the effort). Tick fixes to see the projected score. Nothing changes on your computer.'),
      recs.length ? recs.map((x) => h('div', { class: 'rec' },
        h('label', { class: 'check' },
          h('input', { type: 'checkbox', checked: state.picked.has(x.id), onchange: (e) => togglePick(x.id, e.target.checked) }),
          h('span', {}, h('strong', {}, x.title), ' ', h('span', { class: 'mute' }, '+' + x.gain + ' points, effort ' + x.effort + '/5'))),
        h('details', {}, h('summary', {}, 'How'), h('ul', {}, x.steps.map((s) => h('li', {}, s))))))
        : h('p', { class: 'empty' }, 'Nothing to fix. Run a scan again after you install or download new files.'),
      projEl);
    updateProjection();
  }

  async function togglePick(id, on) {
    on ? state.picked.add(id) : state.picked.delete(id);
    updateProjection();
  }

  async function updateProjection() {
    if (!projEl) return;
    const cur = state.result.health.score;
    if (!state.picked.size) { projEl.textContent = 'Current score: ' + cur; return; }
    try {
      const w = await api('/api/whatif', { method: 'POST', body: { ids: [...state.picked] } });
      projEl.textContent = 'Score ' + w.current + ' becomes ' + w.projected + ' (' + w.level + ') if you do the ticked fixes.';
    } catch (e) { notice(e.message, true); }
  }

  function factorBars(factors) {
    const max = Math.max(0.01, ...factors.map((f) => Math.abs(f.effect || 0)));
    return factors.map((f) => f.effect == null
      ? h('div', {}, f.label)
      : h('div', { class: 'bar' },
          h('span', {}, f.label),
          h('span', { class: 'track' }, h('i', { class: 'fill ' + (f.effect > 0 ? 'pos' : 'neg'), data: { w: Math.round(Math.abs(f.effect) / max * 100) } })),
          h('span', { class: 'mute' }, (f.effect > 0 ? '+' : '') + f.effect)));
  }

  function renderFindings(r) {
    const rows = [];
    r.findings.forEach((f) => {
      rows.push(h('tr', {},
        h('td', {}, h('span', { class: 'pill ' + f.level }, f.score)),
        h('td', {}, h('strong', {}, f.name), f.running ? h('span', { class: 'chip High' }, ' running') : null,
          f.quarantined ? h('span', { class: 'chip ok' }, ' quarantined') : null,
          h('div', { class: 'path' }, f.path)),
        h('td', {}, f.kind === 'process' ? 'Running program' : 'File', h('div', { class: 'mute' }, size(f.size))),
        h('td', {}, h('button', { class: 'ghost small', 'aria-expanded': String(state.open.has(f.id)), onclick: () => {
          state.open.has(f.id) ? state.open.delete(f.id) : state.open.add(f.id);
          renderFindings(state.result);
        } }, state.open.has(f.id) ? 'Hide' : 'Why?'))));
      if (state.open.has(f.id)) {
        rows.push(h('tr', { class: 'detail' }, h('td', { colspan: 4 },
          h('h3', {}, 'Why this score'),
          f.factors.length ? factorBars(f.factors) : h('p', { class: 'mute' }, 'No single trait stands out.'),
          h('p', { class: 'mute' }, 'Red bars raise the score, green bars lower it. Values are SHAP contributions in log-odds.'),
          h('h3', {}, 'What to do'),
          h('p', {}, f.advice),
          f.quarantinable && !f.quarantined
            ? h('button', { onclick: () => quarantine(f) }, 'Move to quarantine')
            : null)));
      }
    });
    fill($('findings'), 
      h('h2', { id: 'findings-h' }, 'Findings'),
      r.findings.length
        ? h('div', { class: 'tablewrap' }, h('table', {},
            h('thead', {}, h('tr', {}, ['Risk', 'Item', 'Type', ''].map((t) => h('th', {}, t)))),
            h('tbody', {}, rows)))
        : h('p', { class: 'empty' }, 'No medium or high risk items found in the folders you scanned.'));
    applyWidths($('findings'));
  }

  async function quarantine(f) {
    try {
      const d = await api('/api/quarantine', { method: 'POST', body: { finding_id: f.id } });
      state.result = d.result;
      notice('Moved ' + f.name + ' to quarantine. You can restore it from the quarantine list below.');
      renderResults();
      loadQuarantine();
    } catch (e) { notice(e.message, true); }
  }

  function renderSystem(r) {
    if (!r.include_system) {
      fill($('system'), h('h2', { id: 'system-h' }, 'This computer'),
        h('p', { class: 'empty' }, 'System checks were skipped for this scan.'));
      return;
    }
    fill($('system'), 
      h('h2', { id: 'system-h' }, 'This computer'),
      h('h3', {}, 'Security settings'),
      r.config.map((c) => h('div', { class: 'rec' },
        h('strong', {}, c.label), ' ',
        h('span', { class: 'chip ' + c.status }, c.status === 'ok' ? 'OK' : c.status === 'risk' ? 'Needs attention' : 'Unknown'),
        h('div', { class: 'mute' }, c.detail))),
      h('div', { class: 'mute' }, 'Disk: ' + r.disk.free_gb + ' GB free of ' + r.disk.total_gb + ' GB. Temporary files: about ' + r.junk.gb + ' GB' + (r.junk.partial ? ' (partial count)' : '') + '.'),
      h('h3', {}, 'Ports open to the network'),
      r.ports.length
        ? h('div', { class: 'tablewrap' }, h('table', {},
            h('thead', {}, h('tr', {}, ['Port', 'Program', 'Level', 'Note'].map((t) => h('th', {}, t)))),
            h('tbody', {}, r.ports.map((p) => h('tr', {},
              h('td', {}, p.port), h('td', {}, p.process),
              h('td', {}, h('span', { class: 'level ' + p.level }, p.level)), h('td', {}, p.note))))))
        : h('p', { class: 'empty' }, 'No ports are open to the network, or CIRA could not read them. Run as administrator for a full list.'));
  }

  async function downloadReport() {
    try {
      const r = await fetch('/api/report', { headers: { 'X-CIRA-Token': TOKEN } });
      if (!r.ok) throw new Error('Could not create the report.');
      const url = URL.createObjectURL(await r.blob());
      const a = h('a', { href: url, download: 'cira-report.html' });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) { notice(e.message, true); }
  }

  // ---- quarantine list and model card ---------------------------------------------------------
  async function loadQuarantine() {
    state.items = (await api('/api/quarantine')).items;
    renderQuarantine();
  }

  function renderQuarantine() {
    fill($('quarantine'), 
      h('h2', { id: 'quarantine-h' }, 'Quarantine'),
      state.items.length
        ? [h('p', { class: 'mute' }, 'Quarantined files are kept, not deleted. Restore puts a file back where it was.'),
           h('div', { class: 'tablewrap' }, h('table', {},
             h('thead', {}, h('tr', {}, ['File', 'Why', 'When', ''].map((t) => h('th', {}, t)))),
             h('tbody', {}, state.items.map((i) => h('tr', {},
               h('td', {}, h('strong', {}, i.name), h('div', { class: 'path' }, i.original_path)),
               h('td', {}, i.reason), h('td', {}, when(i.quarantined_at)),
               h('td', {}, h('button', { class: 'ghost small', onclick: () => restore(i) }, 'Restore')))))))]
        : h('p', { class: 'empty' }, 'Nothing is quarantined.'));
  }

  async function restore(i) {
    try {
      const d = await api('/api/restore', { method: 'POST', body: { item_id: i.id } });
      if (d.result) state.result = d.result;
      notice('Restored ' + i.name + ' to ' + d.item.restored_to + '.');
      renderResults();
      loadQuarantine();
    } catch (e) { notice(e.message, true); }
  }

  function renderModel() {
    const m = state.info.metrics;
    fill($('model'), 
      h('h2', { id: 'model-h' }, 'About the risk model'),
      h('div', { class: 'warn' }, h('strong', {}, 'Read this: '), m.warning),
      h('p', { class: 'mute' }, 'A high score means a file has traits common in malware. It is not proof, and a low score is not a guarantee. CIRA is a decision aid, not a replacement for Windows Security.'),
      h('div', { class: 'tablewrap' }, h('table', {}, h('tbody', {},
        [['Algorithm', m.algorithm], ['Training data', m.data_source],
         ['Model AUC on held-out synthetic data', m.model_auc], ['Equal-weight checklist AUC (baseline)', m.checklist_auc],
         ['Model Brier score (lower is better)', m.model_brier + ' (always guessing the average: ' + m.constant_brier + ')'],
         ['Known malicious hashes loaded', state.info.known_bad_count]]
          .map((row) => h('tr', {}, h('td', {}, row[0]), h('td', {}, String(row[1]))))))));
  }

  // ---- start ----------------------------------------------------------------------------------
  async function init() {
    try {
      state.info = await api('/api/info');
      state.info.folders.forEach((f) => state.folders.add(f.path));
      renderConsent();
      renderModel();
      await loadResult();
      await loadQuarantine();
      renderConsent();
    } catch (e) {
      notice('Could not reach the CIRA agent. ' + e.message, true);
    }
  }
  init();
})();
