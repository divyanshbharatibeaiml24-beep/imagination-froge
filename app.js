const state = {
  mode: 'upload', files: [], studies: [], policies: [], selectedStudyId: null,
  running: false, viewMode: 'original', slice: 1
};
const $ = (id) => document.getElementById(id);
const elements = {
  uploadTab: $('uploadTab'), demoTab: $('demoTab'), uploadPanel: $('uploadPanel'), demoPanel: $('demoPanel'),
  fileInput: $('fileInput'), dropZone: $('dropZone'), fileSelection: $('fileSelection'), fileName: $('fileName'), fileMeta: $('fileMeta'),
  removeFile: $('removeFile'), demoSelect: $('demoSelect'), policySelect: $('policySelect'), reviewMode: $('reviewMode'),
  selectionSummary: $('selectionSummary'), runButton: $('runButton'), progressCard: $('progressCard'), progressTitle: $('progressTitle'),
  progressPercent: $('progressPercent'), progressBar: $('progressBar'), pipelineSteps: $('pipelineSteps'), results: $('resultsSection'),
  toast: $('toast'), worklist: $('worklist'), sliceRange: $('sliceRange'), sliceValue: $('sliceValue'), reviewPanel: $('reviewPanel')
};

async function api(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).detail || message; } catch (_) { /* non-JSON response */ }
    throw new Error(message);
  }
  return response.json();
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.className = `toast show${isError ? ' error' : ''}`;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { elements.toast.className = 'toast'; }, 3600);
}

function setMode(mode) {
  if (state.running) return;
  state.mode = mode;
  const upload = mode === 'upload';
  elements.uploadTab.classList.toggle('active', upload);
  elements.demoTab.classList.toggle('active', !upload);
  elements.uploadTab.setAttribute('aria-selected', String(upload));
  elements.demoTab.setAttribute('aria-selected', String(!upload));
  elements.uploadPanel.classList.toggle('hidden', !upload);
  elements.demoPanel.classList.toggle('hidden', upload);
  updateSelection();
}

function updateSelection() {
  const dot = document.querySelector('.summary-dot');
  const study = state.studies.find((item) => item.id === elements.demoSelect.value);
  const ready = state.mode === 'upload' ? state.files.length > 0 : Boolean(study);
  if (state.mode === 'upload') {
    elements.selectionSummary.textContent = ready
      ? `${state.files.length} DICOM ${state.files.length === 1 ? 'file' : 'files'} ready for intake`
      : 'Select one or more DICOM files to continue';
  } else {
    elements.selectionSummary.textContent = study ? `${study.modality} · ${study.studyDesc}` : 'Choose a demo study';
  }
  elements.runButton.disabled = !ready || state.running;
  dot.classList.toggle('ready', ready);
}

function chooseFiles(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  if (files.length > 10) return showToast('Select no more than 10 DICOM files at a time.', true);
  if (files.some((file) => file.size > 50 * 1024 * 1024)) return showToast('Each file must be 50 MB or smaller.', true);
  state.files = files;
  elements.fileName.textContent = files.length === 1 ? files[0].name : `${files[0].name} and ${files.length - 1} more`;
  elements.fileMeta.textContent = `${files.length} DICOM file${files.length === 1 ? '' : 's'} · ${(files.reduce((sum, file) => sum + file.size, 0) / 1024 / 1024).toFixed(2)} MB total`;
  elements.fileSelection.classList.remove('hidden');
  updateSelection();
}

async function loadStudies() {
  try {
    const [health, studies, policies, metrics] = await Promise.all([
      api('/api/health'), api('/api/studies'), api('/api/policies'), api('/api/dashboard/metrics')
    ]);
    $('systemLabel').textContent = 'All systems operational';
    $('policyLabel').textContent = health.activePolicy.replaceAll('_', ' ');
    state.studies = studies;
    state.policies = policies;
    const demos = studies.filter((study) => study.id.startsWith('ST-'));
    elements.demoSelect.innerHTML = demos.map((study) => `<option value="${escapeHtml(study.id)}">${escapeHtml(study.modality)} — ${escapeHtml(study.studyDesc)}</option>`).join('');
    elements.policySelect.innerHTML = policies.map((policy) => `<option value="${escapeHtml(policy.id)}">${escapeHtml(policy.label)}</option>`).join('');
    elements.policySelect.value = health.activePolicy;
    renderOperations(metrics);
    renderWorklist();
    updateSelection();
  } catch (error) {
    $('systemLabel').textContent = 'Backend unavailable';
    $('policyLabel').textContent = 'Start backend.py to connect';
    showToast(error.message, true);
  }
}

function renderOperations(metrics) {
  const cards = [
    ['Studies', metrics.studies], ['Approved', metrics.approved], ['In review', metrics.inReview],
    ['Quarantined', metrics.quarantined], ['PHI findings', metrics.phiFindings], ['Attack leaks', metrics.attackLeaks]
  ];
  $('operationsMetrics').innerHTML = cards.map(([label, value]) => `<div class="metric"><span>${label}</span><strong class="${label === 'Attack leaks' && value === 0 ? 'good' : ''}">${value}</strong></div>`).join('');
}

function filteredStudies() {
  const needle = $('worklistSearch').value.trim().toLowerCase();
  const releaseState = $('worklistState').value;
  const priority = $('worklistPriority').value;
  return state.studies.filter((study) => {
    const caseData = study.case || {};
    const fields = [study.id, study.modality, study.studyDesc, caseData.owner, ...(caseData.tags || [])].join(' ').toLowerCase();
    return (!needle || fields.includes(needle)) && (!releaseState || study.releaseState === releaseState) && (!priority || caseData.priority === priority);
  });
}

function renderWorklist() {
  const studies = filteredStudies().slice().reverse();
  $('worklistCount').textContent = `${studies.length} case${studies.length === 1 ? '' : 's'}`;
  elements.worklist.innerHTML = studies.length ? studies.map((study) => {
    const caseData = study.case || {};
    return `<button class="worklist-item ${study.id === state.selectedStudyId ? 'active' : ''}" type="button" data-study-id="${escapeHtml(study.id)}">
      <strong>${escapeHtml(study.modality)} · ${escapeHtml(study.id)}</strong><span>${escapeHtml(study.studyDesc)}</span><small>${escapeHtml(caseData.priority || 'NORMAL')} · ${escapeHtml(study.releaseState || 'Ready')}${caseData.owner ? ` · ${escapeHtml(caseData.owner)}` : ''}</small>
    </button>`;
  }).join('') : '<div class="empty-worklist">No cases match the current filters.</div>';
  elements.worklist.querySelectorAll('[data-study-id]').forEach((button) => button.addEventListener('click', () => openStudy(button.dataset.studyId)));
}

async function openStudy(studyId) {
  try {
    state.selectedStudyId = studyId;
    await renderResults(await api(`/api/studies/${encodeURIComponent(studyId)}`));
    elements.results.classList.remove('hidden');
    renderWorklist();
    elements.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { showToast(error.message, true); }
}

function setProgress(index, title) {
  const percent = [12, 32, 56, 78, 92, 100][index];
  elements.progressTitle.textContent = title;
  elements.progressPercent.textContent = `${percent}%`;
  elements.progressBar.style.width = `${percent}%`;
  [...elements.pipelineSteps.children].forEach((step, stepIndex) => {
    step.classList.toggle('active', stepIndex === index);
    step.classList.toggle('done', stepIndex < index);
  });
}

async function uploadSelectedFiles() {
  setProgress(0, 'Securely ingesting DICOM input');
  const form = new FormData();
  state.files.forEach((file) => form.append('files', file));
  const result = await api('/api/studies/batch-upload', { method: 'POST', body: form });
  if (!result.accepted.length) throw new Error(result.rejected[0]?.reason || 'No files were accepted');
  if (result.rejected.length) showToast(`${result.rejected.length} file(s) were rejected during intake.`, true);
  return result.accepted.map((item) => item.studyId);
}

async function runPipeline() {
  if (state.running) return;
  if (state.mode === 'upload' && state.files.length > 1 && elements.reviewMode.value === 'manual') {
    showToast('Batch processing requires automated review. Use one file for manual review.', true);
    return;
  }
  state.running = true;
  elements.runButton.disabled = true;
  elements.progressCard.classList.remove('hidden');
  elements.results.classList.add('hidden');
  elements.progressCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
  try {
    const studyIds = state.mode === 'upload' ? await uploadSelectedFiles() : [elements.demoSelect.value];
    let manualReviewPending = false;
    for (let index = 0; index < studyIds.length; index += 1) {
      const result = await processStudy(studyIds[index], studyIds.length > 1 ? true : elements.reviewMode.value === 'manual', index + 1, studyIds.length);
      manualReviewPending ||= result.manualReviewPending;
      if (manualReviewPending) break;
    }
    const lastStudyId = studyIds[manualReviewPending ? 0 : studyIds.length - 1];
    await finishRun(lastStudyId, manualReviewPending ? 'Analyst review required before release' : `${studyIds.length} case${studyIds.length === 1 ? '' : 's'} processed successfully`);
  } catch (error) {
    elements.progressCard.classList.add('hidden');
    showToast(error.message, true);
  } finally {
    state.running = false;
    updateSelection();
  }
}

async function processStudy(studyId, autoReview, index, total) {
  state.selectedStudyId = studyId;
  const prefix = total > 1 ? `Case ${index} of ${total}: ` : '';
  setProgress(1, `${prefix}discovering identifiers`);
  await api(`/api/studies/${encodeURIComponent(studyId)}/discover`, { method: 'POST' });
  setProgress(2, `${prefix}applying the selected policy`);
  await api(`/api/studies/${encodeURIComponent(studyId)}/transform`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policyId: elements.policySelect.value })
  });
  const reviewState = await api(`/api/studies/${encodeURIComponent(studyId)}`);
  if (!autoReview && reviewState.reviewPendingCount > 0) {
    setProgress(3, 'Waiting for analyst review');
    return { manualReviewPending: true };
  }
  await completeValidation(studyId, prefix);
  return { manualReviewPending: false };
}

async function completeValidation(studyId, prefix = '') {
  await api(`/api/studies/${encodeURIComponent(studyId)}/review/action`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ bulk: true, action: 'approve' })
  });
  setProgress(3, `${prefix}running independent validation`);
  await api(`/api/studies/${encodeURIComponent(studyId)}/validate`, { method: 'POST' });
  setProgress(4, `${prefix}running adversarial privacy probes`);
  await api(`/api/studies/${encodeURIComponent(studyId)}/attack`, { method: 'POST' });
  setProgress(5, 'Processing complete');
}

async function finishRun(studyId, message) {
  await renderResults(await api(`/api/studies/${encodeURIComponent(studyId)}`));
  await loadStudies();
  setTimeout(() => {
    elements.progressCard.classList.add('hidden');
    elements.results.classList.remove('hidden');
    elements.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast(message);
  }, 300);
}

async function renderResults(study) {
  const approved = study.releaseState === 'APPROVE';
  const id = encodeURIComponent(study.id);
  $('releaseBadge').textContent = approved ? 'Approved for release' : `${study.releaseState} — export blocked`;
  $('releaseBadge').classList.toggle('blocked', !approved);
  $('metrics').innerHTML = [
    ['PHI findings', study.findingsCount, ''], ['Transform actions', study.transformManifest?.length || 0, ''],
    ['Validation', study.validationStatus, approved ? 'good' : ''], ['Attack leaks', study.attackFindingsCount, study.attackFindingsCount === 0 ? 'good' : '']
  ].map(([label, value, className]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong class="${className}">${escapeHtml(value)}</strong></div>`).join('');
  $('originalModality').textContent = `${study.modality} · ${study.instanceCount} instance${study.instanceCount === 1 ? '' : 's'}`;
  $('inputHash').textContent = study.hashes.input;
  $('outputHash').textContent = study.hashes.output;
  $('findingCount').textContent = `${study.findingsCount} finding${study.findingsCount === 1 ? '' : 's'}`;
  $('downloadFindings').href = `/api/studies/${id}/findings.csv`;
  state.selectedStudyId = study.id;
  state.slice = 1;
  elements.sliceRange.max = Math.max(1, study.instanceCount || 1);
  elements.sliceRange.value = state.slice;
  setViewerMode('original');
  const findings = study.findings || [];
  $('findingsBody').innerHTML = findings.length ? findings.slice(0, 12).map((finding) => `
    <tr><td>${escapeHtml(finding.loc)}</td><td>${escapeHtml(finding.type)}</td><td class="action-tag">${escapeHtml(finding.action)}</td><td class="status-check">✓ Protected</td></tr>`
  ).join('') : '<tr class="empty-row"><td colspan="4">No identifiers were detected in this study.</td></tr>';
  const labels = { privacy: 'Privacy truth', pixel: 'Pixel integrity', structural: 'DICOM structure' };
  $('truthList').innerHTML = Object.entries(study.truths || {}).map(([key, value]) => `
    <div class="truth-item"><span><i class="truth-icon"><svg viewBox="0 0 24 24"><path d="m7 12 3 3 7-7"/></svg></i>${labels[key] || key}</span><strong class="${value === 'PASS' ? '' : 'fail'}">${escapeHtml(value)}</strong></div>`
  ).join('');
  $('attackResult').textContent = study.attackFindingsCount === 0 ? 'No leaks found' : `${study.attackFindingsCount} leak(s)`;
  $('releaseResult').textContent = study.releaseState;
  const links = [$('downloadDicom'), $('downloadPackage')];
  links[0].href = approved ? `/api/studies/${id}/export?format=dicom` : '#';
  links[1].href = approved ? `/api/studies/${id}/export?format=zip` : '#';
  links.forEach((link) => { link.setAttribute('aria-disabled', String(!approved)); link.style.pointerEvents = approved ? 'auto' : 'none'; link.style.opacity = approved ? '1' : '.45'; });
  $('downloadCertificate').disabled = !approved;
  $('downloadCertificate').style.opacity = approved ? '1' : '.45';
  renderReviewQueue(study);
  renderMetadata(study);
  renderNotes(study.notes || []);
  renderCase(study.case || {});
  $('integrityResult').className = 'integrity-result';
  $('integrityResult').textContent = 'Integrity has not been checked in this session.';
  await Promise.all([loadAudit(study.id), loadDossier(study.id), loadTechnicalMetadata(study.id)]);
}

function renderReviewQueue(study) {
  const pending = (study.reviewItems || []).filter((item) => item.status === 'pending');
  elements.reviewPanel.classList.toggle('hidden', pending.length === 0);
  $('reviewQueue').innerHTML = pending.map((item) => `
    <div class="review-item"><div><strong>${escapeHtml(item.category)}</strong><span>${escapeHtml(item.text)}</span></div><button type="button" data-review-id="${escapeHtml(item.id)}">Approve finding</button></div>`
  ).join('');
  $('approveAllButton').textContent = pending.length ? 'Approve all and continue' : 'Continue validation';
  $('reviewQueue').querySelectorAll('[data-review-id]').forEach((button) => button.addEventListener('click', () => approveFinding(button.dataset.reviewId)));
}

function renderMetadata(study) {
  const metadata = [['Study ID', study.id], ['Modality', study.modality], ['Policy', study.policyId || '—'], ['Series / instances', `${study.seriesCount} / ${study.instanceCount}`], ['Notes', (study.notes || []).length]];
  $('metadataList').innerHTML = metadata.map(([label, value]) => `<div class="metadata-row"><span>${escapeHtml(label)}</span><span>${escapeHtml(value)}</span></div>`).join('');
}

function renderCase(caseData) {
  $('casePriority').value = caseData.priority || 'NORMAL';
  $('caseOwner').value = caseData.owner || '';
  $('caseDueDate').value = caseData.dueDate || '';
  $('caseTags').value = (caseData.tags || []).join(', ');
}

function renderNotes(notes) {
  $('noteList').innerHTML = notes.length ? notes.slice().reverse().map((note) => `<li>${escapeHtml(note.text)}</li>`).join('') : '<li>No analyst notes.</li>';
}

async function approveFinding(itemId) {
  try {
    await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}/review/action`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ itemId, action: 'approve' }) });
    await renderResults(await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}`));
  } catch (error) { showToast(error.message, true); }
}

async function approveAllAndContinue() {
  if (!state.selectedStudyId || state.running) return;
  state.running = true;
  elements.progressCard.classList.remove('hidden');
  try {
    await completeValidation(state.selectedStudyId);
    await finishRun(state.selectedStudyId, 'Manual review completed and release checks passed');
  } catch (error) { showToast(error.message, true); }
  finally { state.running = false; updateSelection(); }
}

function setViewerMode(mode) {
  state.viewMode = mode;
  document.querySelectorAll('[data-view]').forEach((button) => button.classList.toggle('active', button.dataset.view === mode));
  updateViewer();
}

function updateViewer() {
  if (!state.selectedStudyId) return;
  const id = encodeURIComponent(state.selectedStudyId);
  const timestamp = Date.now();
  $('originalImage').src = `/api/studies/${id}/slice?mode=${state.viewMode}&slice_index=${state.slice}&t=${timestamp}`;
  $('outputImage').src = `/api/studies/${id}/slice?mode=validated&slice_index=${state.slice}&t=${timestamp}`;
  elements.sliceValue.textContent = `${state.slice} / ${elements.sliceRange.max}`;
}

async function loadAudit(studyId) {
  try {
    const audit = await api(`/api/audit?study_id=${encodeURIComponent(studyId)}&last_n=4`);
    $('auditHead').textContent = audit.chainHead.slice(0, 12);
    $('auditList').innerHTML = audit.entries.length ? audit.entries.slice().reverse().map((entry) => `<li>${escapeHtml(entry.step)} — ${escapeHtml(entry.detail)}</li>`).join('') : '<li>No recorded events.</li>';
  } catch (_) { $('auditList').innerHTML = '<li>Audit history unavailable.</li>'; }
}

async function loadDossier(studyId) {
  try {
    const dossier = await api(`/api/studies/${encodeURIComponent(studyId)}/dossier`);
    $('riskScore').textContent = dossier.riskScore;
    $('riskBand').textContent = `${dossier.riskBand} risk`;
    $('riskDetail').textContent = `${dossier.lifecycle.pendingReview} pending review · ${dossier.notesCount} analyst note(s)`;
  } catch (_) { $('riskScore').textContent = '—'; $('riskBand').textContent = 'Risk unavailable'; $('riskDetail').textContent = 'Dossier service did not respond'; }
}

async function loadTechnicalMetadata(studyId) {
  try {
    const result = await api(`/api/studies/${encodeURIComponent(studyId)}/metadata`);
    $('technicalMetadata').innerHTML = Object.entries(result.metadata).map(([key, value]) => `<div class="metadata-row"><span>${escapeHtml(key)}</span><span>${escapeHtml(value)}</span></div>`).join('');
  } catch (_) { $('technicalMetadata').textContent = 'Metadata unavailable.'; }
}

async function verifyIntegrity() {
  if (!state.selectedStudyId) return;
  try {
    const result = await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}/integrity`);
    const verified = result.status === 'VERIFIED';
    $('integrityResult').className = `integrity-result ${verified ? 'verified' : 'mismatch'}`;
    $('integrityResult').textContent = verified
      ? `Verified: source, output, and Merkle evidence match (${result.auditEvents} audit events).`
      : 'Evidence mismatch detected. Keep this case quarantined and investigate the audit history.';
    await loadAudit(state.selectedStudyId);
  } catch (error) { showToast(error.message, true); }
}

async function saveCase() {
  if (!state.selectedStudyId) return;
  const tags = $('caseTags').value.split(',').map((tag) => tag.trim()).filter(Boolean);
  try {
    await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}/case`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ priority: $('casePriority').value, owner: $('caseOwner').value, dueDate: $('caseDueDate').value, tags })
    });
    await renderResults(await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}`));
    await loadStudies();
    showToast('Case management details saved');
  } catch (error) { showToast(error.message, true); }
}

async function downloadCertificate() {
  if (!state.selectedStudyId) return;
  try {
    const certificate = await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}/certificate`);
    const blob = new Blob([JSON.stringify(certificate, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${certificate.certificateId}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    await loadAudit(state.selectedStudyId);
  } catch (error) { showToast(error.message, true); }
}

async function saveNote() {
  const note = $('caseNote').value.trim();
  if (!note || !state.selectedStudyId) return;
  try {
    await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}/notes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ note }) });
    $('caseNote').value = '';
    await renderResults(await api(`/api/studies/${encodeURIComponent(state.selectedStudyId)}`));
    showToast('Analyst note saved');
  } catch (error) { showToast(error.message, true); }
}

elements.uploadTab.addEventListener('click', () => setMode('upload'));
elements.demoTab.addEventListener('click', () => setMode('demo'));
elements.dropZone.addEventListener('click', () => elements.fileInput.click());
elements.fileInput.addEventListener('change', () => chooseFiles(elements.fileInput.files));
elements.removeFile.addEventListener('click', () => { state.files = []; elements.fileInput.value = ''; elements.fileSelection.classList.add('hidden'); updateSelection(); });
['dragenter', 'dragover'].forEach((name) => elements.dropZone.addEventListener(name, (event) => { event.preventDefault(); elements.dropZone.classList.add('dragging'); }));
['dragleave', 'drop'].forEach((name) => elements.dropZone.addEventListener(name, (event) => { event.preventDefault(); elements.dropZone.classList.remove('dragging'); }));
elements.dropZone.addEventListener('drop', (event) => chooseFiles(event.dataTransfer.files));
elements.demoSelect.addEventListener('change', updateSelection);
elements.runButton.addEventListener('click', runPipeline);
$('approveAllButton').addEventListener('click', approveAllAndContinue);
$('downloadCertificate').addEventListener('click', downloadCertificate);
$('verifyIntegrity').addEventListener('click', verifyIntegrity);
$('saveCase').addEventListener('click', saveCase);
$('saveNote').addEventListener('click', saveNote);
elements.sliceRange.addEventListener('input', () => { state.slice = Number(elements.sliceRange.value); updateViewer(); });
document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => setViewerMode(button.dataset.view)));
['worklistSearch', 'worklistState', 'worklistPriority'].forEach((id) => $(id).addEventListener(id === 'worklistSearch' ? 'input' : 'change', renderWorklist));
$('refreshButton').addEventListener('click', loadStudies);
document.querySelectorAll('[data-scroll]').forEach((button) => button.addEventListener('click', () => { const target = $(button.dataset.scroll); if (target && !target.classList.contains('hidden')) target.scrollIntoView({ behavior: 'smooth' }); }));

loadStudies();
