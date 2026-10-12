(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const token = new URLSearchParams(window.location.hash.slice(1)).get('token');
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }

  const state = {
    summary: null,
    epoch: 0,
    listRequest: 0,
    detailRequest: 0,
    previewRequest: 0,
    refreshRequest: 0,
    offset: 0,
    limit: 50,
    total: 0,
    selected: null,
    tab: 'memories'
  };

  function textNode(tag, value, className = '') {
    const node = document.createElement(tag);
    node.textContent = value == null ? '' : String(value);
    node.className = className;
    return node;
  }

  function clear(node) { node.replaceChildren(); }
  function setStatus(message) { $('status').textContent = message; }
  function readable(value) { return value == null || value === '' ? '-' : String(value); }
  function label(value) { return String(value).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()); }
  function showTime(value) {
    if (!value) return '-';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  async function api(path, options = {}) {
    if (!token) throw new Error('The launch link is missing its access token. Reopen the full URL printed in the terminal.');
    const headers = { Authorization: `Bearer ${token}`, ...(options.body ? { 'Content-Type': 'application/json' } : {}) };
    let response;
    try {
      response = await fetch(path, { ...options, headers, cache: 'no-store' });
    } catch (_) {
      throw new Error('The local explorer could not be reached. Check that its terminal is still running.');
    }
    let payload;
    try { payload = await response.json(); } catch (_) {
      throw new Error('The local explorer returned an unreadable response.');
    }
    if (!response.ok) {
      const message = payload && typeof payload.error === 'string' ? payload.error : `Request failed (${response.status}).`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function addNotice(message, level = 'warning') {
    const node = textNode('p', message, `notice ${level}`);
    $('notice-region').append(node);
  }

  function renderNotices(extra = '') {
    clear($('notice-region'));
    if (extra) addNotice(extra, 'error');
    const summary = state.summary;
    if (!summary) return;
    if (summary.state === 'missing') addNotice('The selected store is missing. There are no source records to inspect. Launch demo mode separately to explore fictitious memories.');
    if (summary.state === 'empty') addNotice('The selected store is empty. Refresh after memories have been added to this store.');
    if (summary.state === 'unreadable') addNotice('At least one source file could not be read or parsed. This snapshot is incomplete; recall preview is unavailable.', 'error');
    if (summary.verification?.state === 'missing') addNotice('No verification file was selected. Signature verification is unavailable for this snapshot.');
    if (summary.verification?.state === 'invalid') addNotice('The verification file is invalid or unreadable. Signature verification is unavailable for this snapshot.', 'error');
    const files = summary.files || {};
    for (const [name, info] of Object.entries(files)) {
      if (info && info.state && !['readable', 'present', 'available', 'missing', 'empty'].includes(info.state)) addNotice(`${name}: ${info.state}.`, 'error');
    }
    for (const notice of summary.notices || []) addNotice(notice);
  }

  function renderSummary(summary) {
    state.summary = summary;
    $('store-label').textContent = summary.mode === 'demo' ? `Synthetic demo · ${readable(summary.store)}` : readable(summary.store);
    const counts = summary.counts || {};
    const factCount = Number(counts.facts) || 0;
    const insightCount = Number(counts.insights) || 0;
    $('store-state').textContent = `${label(summary.state || 'unknown')} · ${factCount} ${factCount === 1 ? 'fact' : 'facts'}, ${insightCount} ${insightCount === 1 ? 'insight' : 'insights'}`;
    $('capture-time').textContent = showTime(summary.captured_at);
    const verification = summary.verification || {};
    const verificationCounts = verification.counts || {};
    const countText = Object.entries(verificationCounts).map(([key, value]) => `${label(key)} ${value}`).join(' · ');
    $('verification-state').textContent = `${label(verification.state || 'unknown')}${countText ? ` · ${countText}` : ''}`;
    clear($('kind'));
    $('kind').append(new Option('All kinds', ''));
    for (const kind of summary.kinds || []) $('kind').append(new Option(kind, kind));
    const unreadable = summary.state === 'unreadable';
    $('preview-form').querySelector('button[type="submit"]').disabled = unreadable;
    if (unreadable) {
      clear($('preview-result'));
      $('preview-result').append(textNode('p', 'Recall preview is unavailable because this snapshot contains unreadable source data. Review the notices and refresh after fixing the source.', 'notice error'));
    }
    renderNotices();
  }

  function renderListState(message) {
    clear($('record-list'));
    $('record-list').append(textNode('p', message, 'empty-state'));
    $('record-count').textContent = '-';
    $('page-label').textContent = '-';
    $('page-position').textContent = '-';
    $('previous-page').disabled = true;
    $('next-page').disabled = true;
  }

  function clearDetail(message = 'Select a memory to read its full content, source references, and verification state.') {
    state.detailRequest += 1;
    state.selected = null;
    clear($('record-detail'));
    $('record-detail').append(textNode('p', message, 'empty-state'));
  }

  function badge(value, type = '') {
    const word = readable(value);
    const normalized = word.toLowerCase().replace(/\s+/g, '_');
    const className = ['superseded', 'inactive', 'unsigned', 'unavailable', 'missing'].includes(normalized) ? 'warn' : ['revoked', 'invalid', 'tampered', 'parent_suspect'].includes(normalized) ? 'error' : '';
    return textNode('span', word, `badge ${type || className}`.trim());
  }

  function renderRecords(result) {
    state.total = Number(result.total) || 0;
    state.offset = Number(result.offset) || 0;
    state.limit = Number(result.limit) || 50;
    clear($('record-list'));
    const items = Array.isArray(result.items) ? result.items : [];
    if (!items.length) {
      const message = state.summary?.state === 'missing' ? 'The source store is missing.' : state.summary?.state === 'empty' ? 'This store has no memories yet.' : state.summary?.state === 'unreadable' ? 'Records could not be read from this snapshot.' : 'No memories match these filters. Try a broader search or choose "All states."';
      $('record-list').append(textNode('p', message, 'empty-state'));
    }
    for (const record of items) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'record-row';
      button.dataset.handle = record.handle;
      if (record.handle === state.selected) button.setAttribute('aria-current', 'true');
      const meta = textNode('span', `${label(record.collection)} · ${label(record.kind)} · ${label(record.lifecycle)}`, 'record-meta');
      button.append(meta, textNode('span', record.content, 'record-content'), textNode('span', `${readable(record.source_date)} · ${readable(record.id)}`, 'record-id'));
      button.addEventListener('click', () => selectRecord(record.handle));
      $('record-list').append(button);
    }
    const start = state.total ? state.offset + 1 : 0;
    const end = Math.min(state.offset + items.length, state.total);
    $('record-count').textContent = `${state.total} ${state.total === 1 ? 'record' : 'records'} in this view`;
    $('page-label').textContent = state.total ? `${start}-${end} of ${state.total}` : 'No results';
    $('page-position').textContent = state.total ? `Page ${Math.floor(state.offset / state.limit) + 1} of ${Math.ceil(state.total / state.limit)}` : '-';
    $('previous-page').disabled = state.offset <= 0;
    $('next-page').disabled = state.offset + state.limit >= state.total;
  }

  function queryParams() {
    return new URLSearchParams({ query: $('search').value.trim(), kind: $('kind').value, lifecycle: $('lifecycle').value, collection: $('collection').value, offset: String(state.offset), limit: String(state.limit) });
  }

  async function loadRecords() {
    if (!state.summary) return;
    const epoch = state.epoch;
    const request = ++state.listRequest;
    const snapshot = state.summary.snapshot_id;
    renderListState('Loading memories…');
    try {
      const result = await api(`/api/records?${queryParams()}`);
      if (request !== state.listRequest || epoch !== state.epoch) return;
      if (result.snapshot_id !== snapshot) { await loadSummary('The snapshot changed while browsing. Loading its latest contents.'); return; }
      renderRecords(result);
      setStatus(`Showing snapshot captured ${showTime(state.summary.captured_at)}.`);
    } catch (error) {
      if (request !== state.listRequest || epoch !== state.epoch) return;
      renderListState(error.message);
      setStatus('Memories could not be loaded.');
      renderNotices(error.message);
    }
  }

  function detailSection(title, entries) {
    if (!entries.length) return null;
    const section = document.createElement('section');
    section.className = 'detail-section';
    section.append(textNode('h4', title));
    const list = document.createElement('dl');
    for (const [key, value] of entries) {
      if (value == null || value === '') continue;
      list.append(textNode('dt', label(key)));
      const rendered = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
      list.append(textNode('dd', rendered));
    }
    section.append(list);
    return section;
  }

  function renderDetail(record) {
    const container = $('record-detail');
    clear(container);
    const tags = document.createElement('div');
    tags.className = 'detail-tags';
    tags.append(badge(label(record.collection)), badge(label(record.kind)), badge(label(record.lifecycle)), badge(record.verification));
    container.append(tags, textNode('p', record.content, 'detail-content'), textNode('p', `ID · ${readable(record.id)}`, 'detail-id'));
    const basic = [['Source date', readable(record.source_date)], ['Confidence (stored score)', record.confidence == null ? 'Unavailable' : record.confidence], ['Verification', record.verification], ['Lifecycle', record.lifecycle], ['Status', record.status]];
    const facts = detailSection('Record state', basic);
    if (facts) container.append(facts);
    const details = record.details || {};
    const sourceKeys = new Set(['evidence', 'source', 'source_file', 'source_path', 'session_anchor', 'source_anchor', 'source_event_ids']);
    const evidence = [];
    const metadata = [];
    for (const [key, value] of Object.entries(details)) (sourceKeys.has(key) ? evidence : metadata).push([key, value]);
    const sourceSection = detailSection('Evidence references · text only', evidence);
    const metadataSection = detailSection('Stored metadata', metadata);
    if (sourceSection) container.append(sourceSection);
    if (metadataSection) container.append(metadataSection);
    if (Array.isArray(record.links) && record.links.length) {
      const section = document.createElement('section');
      section.className = 'detail-section';
      section.append(textNode('h4', 'Related memories'));
      for (const link of record.links) {
        if (!link || typeof link.handle !== 'string') continue;
        const button = textNode('button', `${label(link.relation || 'Related')} · ${readable(link.id)}`, 'detail-link');
        button.type = 'button';
        button.addEventListener('click', () => selectRecord(link.handle));
        section.append(button);
      }
      container.append(section);
    }
  }

  async function selectRecord(handle) {
    if (!state.summary || typeof handle !== 'string') return;
    state.selected = handle;
    for (const button of $('record-list').querySelectorAll('.record-row')) {
      if (button.dataset.handle === handle) button.setAttribute('aria-current', 'true');
      else button.removeAttribute('aria-current');
    }
    const epoch = state.epoch;
    const request = ++state.detailRequest;
    const snapshot = state.summary.snapshot_id;
    clear($('record-detail'));
    $('record-detail').append(textNode('p', 'Loading record…', 'empty-state'));
    try {
      const params = new URLSearchParams({ handle, snapshot_id: snapshot });
      const record = await api(`/api/record?${params}`);
      if (epoch !== state.epoch || request !== state.detailRequest || state.selected !== handle) return;
      renderDetail(record);
    } catch (error) {
      if (epoch !== state.epoch || request !== state.detailRequest) return;
      clearDetail(error.status === 409 ? 'This detail belongs to an older snapshot. Refresh to inspect the current record.' : error.message);
      if (error.status === 409) await loadSummary('The snapshot changed. Loading its latest contents.');
    }
  }

  async function loadSummary(message = '') {
    const epoch = ++state.epoch;
    state.listRequest++;
    state.previewRequest++;
    clearDetail();
    renderListState('Loading memories…');
    clear($('preview-result'));
    $('preview-result').append(textNode('p', 'Run a new preview for this snapshot.', 'empty-state'));
    setStatus('Loading snapshot…');
    try {
      const summary = await api('/api/summary');
      if (epoch !== state.epoch) return;
      renderSummary(summary);
      if (message) addNotice(message);
      state.offset = 0;
      await loadRecords();
    } catch (error) {
      if (epoch !== state.epoch) return;
      renderListState(error.message);
      setStatus('Snapshot could not be loaded.');
      renderNotices(error.message);
    }
  }

  async function refresh() {
    if (!token) { renderNotices('Reopen the full launch URL printed in the terminal to reconnect.'); return; }
    const epoch = ++state.epoch;
    const request = ++state.refreshRequest;
    state.listRequest++;
    state.previewRequest++;
    clearDetail('Refreshing the snapshot…');
    renderListState('Refreshing the snapshot…');
    clear($('preview-result'));
    $('preview-result').append(textNode('p', 'Run a new preview after refresh.', 'empty-state'));
    $('refresh').disabled = true;
    setStatus('Refreshing source files…');
    try {
      const summary = await api('/api/refresh', { method: 'POST', body: '{}' });
      if (epoch !== state.epoch || request !== state.refreshRequest) return;
      state.offset = 0;
      renderSummary(summary);
      clearDetail();
      await loadRecords();
    } catch (error) {
      if (epoch !== state.epoch || request !== state.refreshRequest) return;
      if (state.summary) await loadRecords();
      else renderListState('Refresh failed. Try again.');
      if (epoch !== state.epoch || request !== state.refreshRequest) return;
      clearDetail('Refresh failed. Select a memory from the previous snapshot to inspect its detail.');
      renderNotices(`Refresh failed: ${error.message}`);
      setStatus('Refresh failed; the displayed capture time has not advanced.');
    } finally {
      if (request === state.refreshRequest) $('refresh').disabled = false;
    }
  }

  function renderPreview(result) {
    const container = $('preview-result');
    clear(container);
    for (const notice of result.notices || []) container.append(textNode('p', notice, 'notice warning'));
    const classifier = result.classifier || {};
    const settings = result.settings || {};
    const summary = document.createElement('div');
    summary.className = 'preview-summary';
    summary.append(textNode('span', `Classifier: ${classifier.eligible ? 'Eligible for automatic recall' : 'Would be skipped by the automatic hook'}`));
    if (classifier.reason) summary.append(textNode('span', `Reason: ${classifier.reason}`));
    if (Array.isArray(classifier.categories) && classifier.categories.length) summary.append(textNode('span', `Categories: ${classifier.categories.join(', ')}`));
    summary.append(textNode('span', `Approx. ${readable(result.tokens_used)} tokens`));
    summary.append(textNode('span', `${readable(result.matches)} matches · ${Array.isArray(result.items) ? result.items.length : 0} included`));
    if (result.truncated) summary.append(textNode('span', 'Truncated to budget'));
    container.append(summary);
    container.append(textNode('p', `BM25 · semantic ${settings.semantic ? 'on' : 'off'} · graph ${settings.graph ? 'on' : 'off'} · budget ${readable(settings.budget)} · date-diversity cap ${readable(settings.max_per_date)} (overflow deferred) · strict verification ${settings.strict_verify ? 'on' : 'off'} · agent scope ${settings.agent_scope == null ? 'none' : settings.agent_scope}. Preview, not injection history.`, 'preview-settings'));
    const selected = document.createElement('section');
    selected.className = 'preview-block';
    selected.append(textNode('h3', 'Selected memories'));
    if (!Array.isArray(result.items) || !result.items.length) selected.append(textNode('p', 'No memories were selected for this prompt under these settings.', 'empty-state'));
    for (const item of result.items || []) {
      const row = document.createElement('div');
      row.className = 'preview-item';
      row.append(textNode('span', `${label(item.kind)} · ${readable(item.source_date)} · ${readable(item.id)}`, 'record-meta'), textNode('p', item.content));
      selected.append(row);
    }
    container.append(selected);
    const rendered = document.createElement('section');
    rendered.className = 'preview-block';
    rendered.append(textNode('h3', 'Rendered recall text'), textNode('pre', result.rendered || '(No text rendered.)', 'rendered-text'));
    container.append(rendered);
  }

  async function preview(event) {
    event.preventDefault();
    const query = $('prompt').value.trim();
    const budget = Number($('budget').value);
    if (!query || query.length > 2000 || !Number.isInteger(budget) || budget < 1 || budget > 1500) {
      clear($('preview-result'));
      $('preview-result').append(textNode('p', 'Enter a prompt of up to 2,000 characters and a whole-number budget from 1 to 1,500.', 'notice error'));
      return;
    }
    if (!state.summary) {
      clear($('preview-result'));
      $('preview-result').append(textNode('p', 'Load a snapshot before previewing recall.', 'notice error'));
      return;
    }
    if (state.summary.state === 'unreadable') {
      clear($('preview-result'));
      $('preview-result').append(textNode('p', 'Recall preview is unavailable because this snapshot contains unreadable source data.', 'notice error'));
      return;
    }
    const epoch = state.epoch;
    const request = ++state.previewRequest;
    const snapshot = state.summary.snapshot_id;
    clear($('preview-result'));
    $('preview-result').append(textNode('p', 'Running BM25 preview…', 'empty-state'));
    try {
      const result = await api('/api/preview', { method: 'POST', body: JSON.stringify({ query, budget, snapshot_id: snapshot }) });
      if (epoch !== state.epoch || request !== state.previewRequest) return;
      renderPreview(result);
    } catch (error) {
      if (epoch !== state.epoch || request !== state.previewRequest) return;
      clear($('preview-result'));
      $('preview-result').append(textNode('p', error.status === 409 ? 'The snapshot changed during preview. Refresh and run the preview again.' : error.message, 'notice error'));
    }
  }

  function invalidatePreview() {
    state.previewRequest += 1;
    clear($('preview-result'));
    if (state.summary?.state === 'unreadable') {
      $('preview-result').append(textNode('p', 'Recall preview is unavailable because this snapshot contains unreadable source data. Review the notices and refresh after fixing the source.', 'notice error'));
    } else {
      $('preview-result').append(textNode('p', 'Prompt or budget changed. Run a new BM25 preview for these settings.', 'empty-state'));
    }
  }

  function activateTab(which, focus = false) {
    state.tab = which;
    for (const name of ['memories', 'preview']) {
      const active = name === which;
      const tab = $(`${name}-tab`);
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
      $(`${name}-panel`).hidden = !active;
    }
    if (focus) $(`${which}-tab`).focus();
  }

  for (const name of ['memories', 'preview']) $(`${name}-tab`).addEventListener('click', () => activateTab(name));
  $('memories-tab').parentElement.addEventListener('keydown', (event) => {
    const names = ['memories', 'preview'];
    const index = names.indexOf(state.tab);
    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft' || event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      activateTab(event.key === 'Home' ? names[0] : event.key === 'End' ? names[1] : names[(index + (event.key === 'ArrowRight' ? 1 : -1) + names.length) % names.length], true);
    }
  });
  $('filters').addEventListener('submit', (event) => { event.preventDefault(); state.offset = 0; clearDetail(); loadRecords(); });
  for (const id of ['kind', 'lifecycle', 'collection']) $(id).addEventListener('change', () => { state.offset = 0; clearDetail(); loadRecords(); });
  let searchTimer;
  $('search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { state.offset = 0; clearDetail(); loadRecords(); }, 250); });
  $('previous-page').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); clearDetail(); loadRecords(); });
  $('next-page').addEventListener('click', () => { if (state.offset + state.limit < state.total) { state.offset += state.limit; clearDetail(); loadRecords(); } });
  $('refresh').addEventListener('click', refresh);
  $('preview-form').addEventListener('submit', preview);
  $('prompt').addEventListener('input', invalidatePreview);
  $('budget').addEventListener('input', invalidatePreview);

  if (token) loadSummary();
  else {
    renderListState('The access token is unavailable. Reopen the full launch URL printed in the terminal.');
    setStatus('The explorer needs its launch link to connect.');
    addNotice("The access token is held only in this tab's memory. Reopen the full launch URL printed in the terminal after a reload or new tab.", 'error');
  }
})();
