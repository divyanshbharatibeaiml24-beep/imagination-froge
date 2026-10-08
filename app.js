const state = { mode: 'upload', file: null, studies: [], selectedStudyId: null, running: false };
const $ = (id) => document.getElementById(id);

const elements = {
  uploadTab: $('uploadTab'), demoTab: $('demoTab'), uploadPanel: $('uploadPanel'), demoPanel: $('demoPanel'),
  fileInput: $('fileInput'), dropZone: $('dropZone'), fileSelection: $('fileSelection'), fileName: $('fileName'),
  fileMeta: $('fileMeta'), removeFile: $('removeFile'), demoSelect: $('demoSelect'), selectionSummary: $('selectionSummary'),
  runButton: $('runButton'), progressCard: $('progressCard'), progressTitle: $('progressTitle'), progressPercent: $('progressPercent'),
  progressBar: $('progressBar'), pipelineSteps: $('pipelineSteps'), results: $('resultsSection'), toast: $('toast')
};

async function api(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).detail || message; } catch (_) { /* response is not JSON */ }
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
  if (state.mode === 'upload') {
    const ready = Boolean(state.file);
    elements.selectionSummary.textContent = ready ? `${state.file.name} is ready to ingest` : 'Select a DICOM file to continue';
    elements.runButton.disabled = !ready || state.running;
    dot.classList.toggle('ready', ready);
  } else {
    const study = state.studies.find((item) => item.id === elements.demoSelect.value);
    elements.selectionSummary.textContent = study ? `${study.modality} · ${study.studyDesc}` : 'Choose a demo study';
    elements.runButton.disabled = !study || state.running;
    dot.classList.toggle('ready', Boolean(study));
  }
}

function chooseFile(file) {
  if (!file) return;
  if (file.size > 50 * 1024 * 1024) return showToast('The file must be 50 MB or smaller.', true);
  state.file = file;
  elements.fileName.textContent = file.name;
  elements.fileMeta.textContent = `${(file.size / 1024 / 1024).toFixed(2)} MB · DICOM input`;
  elements.fileSelection.classList.remove('hidden');
  updateSelection();
}

async function loadStudies() {
  try {
    const [health, studies] = await Promise.all([api('/api/health'), api('/api/studies')]);
    $('systemLabel').textContent = 'All systems operational';
    $('policyLabel').textContent = health.activePolicy.replaceAll('_', ' ');
    state.studies = studies.filter((study) => study.id.startsWith('ST-'));
    elements.demoSelect.innerHTML = state.studies.map((study) =>
      `<option value="${escapeHtml(study.id)}">${escapeHtml(study.modality)} — ${escapeHtml(study.studyDesc)}</option>`
    ).join('');
    updateSelection();
  } catch (error) {
    $('systemLabel').textContent = 'Backend unavailable';
    $('policyLabel').textContent = 'Start backend.py to connect';
    showToast(error.message, true);
  }
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

async function uploadSelectedFile() {
  setProgress(0, 'Securely ingesting DICOM');
  const form = new FormData();
  form.append('file', state.file);
  const result = await api('/api/studies/upload', { method: 'POST', body: form });
  return result.studyId;
}

async function runPipeline() {
  if (state.running) return;
  state.running = true;
  elements.runButton.disabled = true;
  elements.progressCard.classList.remove('hidden');
  elements.results.classList.add('hidden');
  elements.progressCard.scrollIntoView({ behavior: 'smooth', block: 'center' });

  try {
    const studyId = state.mode === 'upload' ? await uploadSelectedFile() : elements.demoSelect.value;
    state.selectedStudyId = studyId;
    setProgress(1, 'Discovering identifiers across eight planes');
    await api(`/api/studies/${encodeURIComponent(studyId)}/discover`, { method: 'POST' });
    setProgress(2, 'Applying deterministic transformations');
    await api(`/api/studies/${encodeURIComponent(studyId)}/transform`, { method: 'POST' });
    await api(`/api/studies/${encodeURIComponent(studyId)}/review/action`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ bulk: true, action: 'approve' })
    });
    setProgress(3, 'Running independent three-truth validation');
    await api(`/api/studies/${encodeURIComponent(studyId)}/validate`, { method: 'POST' });
    setProgress(4, 'Running adversarial privacy probes');
    await api(`/api/studies/${encodeURIComponent(studyId)}/attack`, { method: 'POST' });
    setProgress(5, 'Processing complete');
    const study = await api(`/api/studies/${encodeURIComponent(studyId)}`);
    renderResults(study);
    setTimeout(() => {
      elements.progressCard.classList.add('hidden');
      elements.results.classList.remove('hidden');
      elements.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 450);
  } catch (error) {
    elements.progressCard.classList.add('hidden');
    showToast(error.message, true);
  } finally {
    state.running = false;
    updateSelection();
  }
}

function renderResults(study) {
  const approved = study.releaseState === 'APPROVE';
  const id = encodeURIComponent(study.id);
  $('releaseBadge').textContent = approved ? 'Approved for release' : `${study.releaseState} — export blocked`;
  $('releaseBadge').classList.toggle('blocked', !approved);
  $('metrics').innerHTML = [
    ['PHI findings', study.findingsCount, ''],
    ['Transform actions', study.transformManifest?.length || 0, ''],
    ['Validation', study.validationStatus, approved ? 'good' : ''],
    ['Attack leaks', study.attackFindingsCount, study.attackFindingsCount === 0 ? 'good' : '']
  ].map(([label, value, className]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong class="${className}">${escapeHtml(value)}</strong></div>`).join('');

  $('originalModality').textContent = `${study.modality} · ${study.instanceCount} instance${study.instanceCount === 1 ? '' : 's'}`;
  $('originalImage').src = `/api/studies/${id}/slice?mode=original&t=${Date.now()}`;
  $('outputImage').src = `/api/studies/${id}/slice?mode=validated&t=${Date.now()}`;
  $('inputHash').textContent = study.hashes.input;
  $('outputHash').textContent = study.hashes.output;
  $('findingCount').textContent = `${study.findingsCount} finding${study.findingsCount === 1 ? '' : 's'}`;

  const findings = study.findings || [];
  $('findingsBody').innerHTML = findings.length ? findings.slice(0, 12).map((finding) => `
    <tr>
      <td>${escapeHtml(finding.loc)}</td>
      <td>${escapeHtml(finding.type)}</td>
      <td class="action-tag">${escapeHtml(finding.action)}</td>
      <td class="status-check">✓ Protected</td>
    </tr>`).join('') : '<tr class="empty-row"><td colspan="4">No identifiers were detected in this study.</td></tr>';

  const labels = { privacy: 'Privacy truth', pixel: 'Pixel integrity', structural: 'DICOM structure' };
  $('truthList').innerHTML = Object.entries(study.truths || {}).map(([key, value]) => `
    <div class="truth-item"><span><i class="truth-icon"><svg viewBox="0 0 24 24"><path d="m7 12 3 3 7-7"/></svg></i>${labels[key] || key}</span><strong class="${value === 'PASS' ? '' : 'fail'}">${escapeHtml(value)}</strong></div>
  `).join('');
  $('attackResult').textContent = study.attackFindingsCount === 0 ? 'No leaks found' : `${study.attackFindingsCount} leak(s)`;
  $('releaseResult').textContent = study.releaseState;

  const links = [$('downloadDicom'), $('downloadPackage')];
  links[0].href = approved ? `/api/studies/${id}/export?format=dicom` : '#';
  links[1].href = approved ? `/api/studies/${id}/export?format=zip` : '#';
  links.forEach((link) => {
    link.setAttribute('aria-disabled', String(!approved));
    link.style.pointerEvents = approved ? 'auto' : 'none';
    link.style.opacity = approved ? '1' : '.45';
  });
}

elements.uploadTab.addEventListener('click', () => setMode('upload'));
elements.demoTab.addEventListener('click', () => setMode('demo'));
elements.dropZone.addEventListener('click', () => elements.fileInput.click());
elements.fileInput.addEventListener('change', () => chooseFile(elements.fileInput.files[0]));
elements.removeFile.addEventListener('click', () => {
  state.file = null; elements.fileInput.value = ''; elements.fileSelection.classList.add('hidden'); updateSelection();
});
['dragenter', 'dragover'].forEach((name) => elements.dropZone.addEventListener(name, (event) => {
  event.preventDefault(); elements.dropZone.classList.add('dragging');
}));
['dragleave', 'drop'].forEach((name) => elements.dropZone.addEventListener(name, (event) => {
  event.preventDefault(); elements.dropZone.classList.remove('dragging');
}));
elements.dropZone.addEventListener('drop', (event) => chooseFile(event.dataTransfer.files[0]));
elements.demoSelect.addEventListener('change', updateSelection);
elements.runButton.addEventListener('click', runPipeline);
$('refreshButton').addEventListener('click', loadStudies);
document.querySelectorAll('[data-scroll]').forEach((button) => button.addEventListener('click', () => {
  const target = $(button.dataset.scroll); if (target && !target.classList.contains('hidden')) target.scrollIntoView({ behavior: 'smooth' });
}));

loadStudies();
