import { CSV_COLUMNS, V2_COLUMNS, PASSWORD_COLUMNS, FEATURE_COLUMNS, MAX_BYTES, parseCSV, recommendation } from './schema.js';
import { MOCK_CARDS } from './mock-view.js';
import { predictRisk, loadModel, getModelStatus } from './model-adapter.js';
import { createRetention } from './lifecycle.js';
import { buildSessions } from './sessions.js';

const $ = id => document.getElementById(id);
let sessions = [...MOCK_CARDS];
let selectedId = sessions[0].id;
let mode = 'mock';
let csvVersion = 'legacy';
let importGeneration = 0;
let page = 0;
const PAGE_SIZE = 50;
let retentionMessage = 'No CSV has been imported.';
const retention = createRetention({ onExpire: () => resetView('Time expired: application references to imported data were released.') });
const labels = { high: 'High', medium: 'Medium', low: 'Low', pending: 'Pending' };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
const shortId = id => id.length > 22 ? `${id.slice(0, 11)}…${id.slice(-7)}` : id;
const eventTime = session => session.mock ? `${session.time} UTC · Mock` : `${session.latest.event_ts_utc.replace('T', ' ').replace('Z', '')} UTC`;
function sessionTitle(session) { return session.mock ? session.title : shortId(session.id); }
function filteredSessions() {
  const term = $('search').value.trim().toLocaleLowerCase('en');
  const filter = $('risk-filter').value;
  return sessions.filter(session =>
    (!term || session.id.toLocaleLowerCase('en').includes(term) || (session.mock && session.title.toLocaleLowerCase('en').includes(term))) &&
    (filter === 'all' || recommendation(session.score).level === filter));
}

function renderList() {
  const matches = filteredSessions();
  const pageCount = Math.max(1, Math.ceil(matches.length / PAGE_SIZE));
  page = Math.min(page, pageCount - 1);
  const visible = matches.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  if (!visible.some(session => session.id === selectedId)) selectedId = visible[0]?.id ?? null;
  $('session-list').replaceChildren();
  for (const session of visible) {
    const risk = recommendation(session.score);
    const button = el('button', `session-row${session.id === selectedId ? ' selected' : ''}`);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(session.id === selectedId));
    button.setAttribute('aria-label', `${sessionTitle(session)}, ${session.score ?? 'awaiting score'}${session.mock ? ', mock' : ''}`);
    const identity = el('span', 'session-identity');
    const icon = el('span', 'session-icon', session.mock ? '◇' : '◫');
    icon.setAttribute('aria-hidden', 'true');
    const content = el('span', 'session-text');
    content.append(el('span', 'session-title', sessionTitle(session)));
    content.append(el('span', 'session-subtitle', session.mock ? shortId(session.id) : `${session.events.length} events · Opaque session token`));
    content.append(el('span', 'session-meta', `${eventTime(session)}${session.mock ? ` · ${session.count}` : ''}`));
    identity.append(icon, content);
    const right = el('span', `row-risk ${risk.level}`);
    const score = el('span', 'score-cell');
    score.append(el('strong', '', session.score === null ? '—' : String(Math.round(session.score))), el('span', 'risk-label', risk.label));
    const chevron = el('span', 'row-chevron', '›'); chevron.setAttribute('aria-hidden', 'true');
    right.append(score, chevron);
    button.append(identity, right);
    button.addEventListener('click', () => { if (retention.check()) return; selectedId = session.id; renderList(); renderDetail(); $('session-list').querySelector('[aria-pressed="true"]')?.focus({ preventScroll: true }); });
    $('session-list').append(button);
  }
  if (!visible.length) $('session-list').append(el('p', 'empty-state', 'No matching sessions. Try a different search or risk filter.'));
  $('shown-count').textContent = `${visible.length} shown · ${matches.length} matches / ${sessions.length} sessions`;
  $('page-count').textContent = `${page + 1} / ${pageCount}`;
  $('page-prev').disabled = page === 0;
  $('page-next').disabled = page >= pageCount - 1;
  $('list-count').textContent = String(sessions.length);
}

function renderDetail() {
  const root = $('session-detail'); root.replaceChildren();
  const session = sessions.find(item => item.id === selectedId);
  if (!session) { root.append(el('p', 'empty-state', 'Choose a session to explore its details.')); return; }
  const risk = recommendation(session.score);
  const hero = el('div', 'detail-hero');
  const head = el('div', 'detail-head');
  head.append(el('h2', '', 'Your session, explained'), el('span', 'pill', session.mock ? 'MOCK SCORE' : session.score === null ? 'AWAITING SCORE' : csvVersion === 'v2' ? 'COMBINED SCORE' : 'MODEL OUTPUT'));
  hero.append(head, el('p', 'detail-session', shortId(session.id)));
  const scoreLine = el('div', 'score-line');
  const scoreContext = el('div', 'score-context');
  scoreContext.append(el('strong', '', risk.label), el('span', '', '100 is the highest risk'));
  scoreLine.append(el('div', 'hero-score', session.score === null ? '—' : String(Math.round(session.score))), scoreContext);
  hero.append(scoreLine);
  const meter = el('div', 'hero-meter'); meter.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < 20; i++) meter.append(el('span', session.score !== null && i < session.score / 5 ? 'filled' : ''));
  const endpoints = el('div', 'meter-labels'); endpoints.append(el('span', '', '0 · Low'), el('span', '', '100 · High'));
  hero.append(meter, endpoints);

  const body = el('div', 'detail-content');
  body.append(el('h3', '', session.mock ? 'Illustrative risk reasons' : session.score === null ? 'Scoring status' : 'What shaped this score'));
  const reasons = el('ul', 'reason-list');
  const explanations = session.mock ? session.reasons : session.score === null ?
    [session.error ? 'The model response could not be validated. This session has no score.' : getModelStatus().state !== 'ready' ? 'The local model could not be loaded. Check the model file and import the CSV again.' : 'At least one event has a missing feature, missing password flag or unsupported category. The entire session remains unscored.',
      'Target labels and attack metadata never become risk reasons.',
      'Unknown history is not assumed to be normal behavior.'] :
    session.reasons.length ? session.reasons : ['The model returned no explanation. No reasons were invented.'];
  explanations.forEach(reason => reasons.append(el('li', '', reason)));
  body.append(reasons);
  const signals = el('div', 'signals');
  const source = session.scoredEvent || session.latest;
  const signalValues = session.mock ? session.signals : [
    ['Attempts / 2 min', source.attempts_2m ?? 'Unknown'],
    ['Accounts / 2 min', source.distinct_accounts_2m ?? 'Unknown'],
    ['New device', source.device_new === null ? 'Unknown' : source.device_new ? 'Yes' : 'No'],
  ];
  signalValues.forEach(([key, value]) => { const signal = el('span', 'signal', `${key}: `); signal.append(el('strong', '', String(value))); signals.append(signal); });
  body.append(signals);
  const action = el('div', 'action-box');
  action.append(el('div', 'action-kicker', 'A THOUGHTFUL NEXT STEP'), el('h3', '', `↗  ${risk.action}`), el('p', '', risk.detail));
  const foot = el('p', 'detail-foot');
  foot.textContent = session.mock ? 'Mock scenario · Thresholds are demo policy only. No account locking or real MFA is triggered.' :
    session.score === null ? 'No score does not mean low risk. Signals describe the latest event. CSV stays in browser memory.' :
    `Model: ${session.modelVersion} · All events scored; this is the session maximum. Reasons describe that event. Contributions explain the model calculation, not causality. The 30/70 demo action thresholds are separate from the model benchmark threshold and are unvalidated in real use.`;
  root.append(hero, body, action, foot);
}

function renderStats() {
  const count = { high: 0, medium: 0, low: 0, pending: 0 };
  sessions.forEach(session => count[recommendation(session.score).level]++);
  $('total-count').textContent = sessions.length;
  $('high-count').replaceChildren(document.createTextNode(String(count.high)), el('span', 'stat-unit', 'sessions'));
  $('mfa-count').replaceChildren(document.createTextNode(String(count.high + count.medium)), el('span', 'stat-unit', 'sessions'));
  $('total-caption').textContent = mode === 'mock' ? 'Fixed mock scenarios' : `${sessions.reduce((sum, s) => sum + s.events.length, 0)} events · ${count.pending} sessions awaiting score`;
  $('distribution-caption').textContent = mode === 'mock' ? 'The distribution of mock cards only, not model performance.' : 'All imported sessions. Pending sessions are not counted as low risk.';
  $('distribution-bar').replaceChildren(); $('distribution-legend').replaceChildren();
  for (const level of ['low', 'medium', 'high', 'pending']) {
    if (!count[level]) continue;
    const bar = el('span', level); bar.style.setProperty('--size', count[level]);
    $('distribution-bar').append(bar);
    const legend = el('span', `legend-item ${level}`); legend.append(el('i'), document.createTextNode(`${labels[level]} ${count[level]}`));
    $('distribution-legend').append(legend);
  }
}

function renderNotice() {
  const notice = $('notice'); notice.replaceChildren();
  let text = mode === 'mock' ? 'Scores and reasons are fixed illustrations, not model results or performance metrics.' : 'CSV is processed only in browser memory. The model learned from synthetic data; scores are not real attack probabilities or proven performance. Missing or unsupported context remains unscored.';
  if (mode === 'csv') text = 'Historical experiment, not the current server policy. ' + (csvVersion === 'v2' ? 'V2 combined score: base ML risk + separate password policy, capped at 100. ' : 'Legacy CSV: base ML score only; password risk was not checked. ') + text;
  const paragraph = el('p'); paragraph.append(el('strong', '', mode === 'mock' ? 'Interface preview. ' : 'Local CSV view. '), document.createTextNode(text));
  notice.append(el('span', 'pill mock-pill', mode === 'mock' ? 'MOCK' : 'LOCAL CSV'), paragraph);
}

function renderModelStatus() {
  const model = getModelStatus();
  $('model-status').textContent = model.state === 'ready' ? `Local model ready · ${model.version}` : model.state === 'loading' ? 'Loading the local model…' : 'Model unavailable · imported sessions remain unscored';
  $('model-status').classList.toggle('pending', model.state !== 'ready');
}
function renderRetention() {
  const remaining = retention.remaining();
  $('retention-status').textContent = remaining === null ? retentionMessage : `Memory retention: ${Math.ceil(remaining / 60000)} min left · not a physical memory-wiping guarantee`;
}
function render() { renderList(); renderDetail(); renderStats(); renderNotice(); renderModelStatus(); renderRetention(); }
function resetView(message = 'Application references to imported data were released.') {
  importGeneration++;
  retention.clear();
  retentionMessage = message;
  sessions = [...MOCK_CARDS]; selectedId = sessions[0].id; mode = 'mock'; page = 0;
  $('search').value = ''; $('risk-filter').value = 'all'; $('csv-input').value = '';
  $('error').hidden = true; $('error').textContent = '';
  $('import-button').disabled = false;
  render(); showView('overview');
}
function showView(view) {
  const descriptions = {
    overview: ['Overview', 'See the whole story', 'Turn sign-in signals into a clearer next step.'],
    contract: ['Data contract', 'A common language', 'Clear boundaries between identity, model features and evaluation.'],
    privacy: ['Privacy boundaries', 'Care, from the start', 'Customer information stays in the customer environment.'],
  };
  if (!descriptions[view]) view = 'overview';
  const [name, title, description] = descriptions[view];
  for (const key of Object.keys(descriptions)) $(`${key}-view`).hidden = view !== key;
  $('page-name').textContent = name;
  $('page-title').replaceChildren(document.createTextNode(title), el('span', '', '.'));
  $('page-description').textContent = description;
  document.querySelectorAll('.nav-item').forEach(button => {
    const active = button.dataset.view === view;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  });
}

document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));
document.querySelector('.brand').addEventListener('click', event => { event.preventDefault(); showView('overview'); });
$('search').addEventListener('input', () => { if (retention.check()) return; page = 0; renderList(); renderDetail(); });
$('risk-filter').addEventListener('change', () => { if (retention.check()) return; page = 0; renderList(); renderDetail(); });
$('page-prev').addEventListener('click', () => { if (retention.check()) return; page = Math.max(0, page - 1); renderList(); renderDetail(); });
$('page-next').addEventListener('click', () => { if (retention.check()) return; page++; renderList(); renderDetail(); });
$('import-button').addEventListener('click', () => $('csv-input').click());
$('reset-button').addEventListener('click', () => resetView());
$('csv-input').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  const generation = ++importGeneration;
  $('error').hidden = true; $('error').textContent = '';
  $('import-button').disabled = true;
  $('notice').replaceChildren(el('p', '', 'Validating CSV and preparing sessions…'));
  try {
    if (file.size > MAX_BYTES) throw new Error('The file limit is 2 MiB. Choose a smaller CSV.');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    if (generation !== importGeneration) return;
    const events = parseCSV(text);
    const modelLoad = loadModel(); renderModelStatus();
    await modelLoad;
    if (generation !== importGeneration) return;
    const imported = await buildSessions(events, features => {
      if (generation !== importGeneration) return null;
      return predictRisk(features);
    }, { active: () => generation === importGeneration, yieldControl: () => new Promise(resolve => setTimeout(resolve, 0)) });
    if (generation !== importGeneration) return;
    csvVersion = Object.hasOwn(events[0], 'password_in_blocklist') ? 'v2' : 'legacy';
    sessions = imported; selectedId = sessions[0]?.id ?? null; mode = 'csv'; page = 0;
    retention.start(Number($('retention-minutes').value));
    $('search').value = ''; $('risk-filter').value = 'all';
    render(); showView('overview');
  } catch (error) {
    if (generation !== importGeneration) return;
    // Only our controlled parse errors contain text; never print native decoding errors.
    const message = error instanceof TypeError ? 'The file could not be decoded as UTF-8.' : error.name === 'Error' ? error.message : 'The file could not be read safely.';
    $('error').textContent = `${message} The previous view was preserved. Never upload real records to an AI conversation.`;
    $('error').hidden = false;
    renderNotice();
  } finally {
    if (generation === importGeneration) { $('import-button').disabled = false; $('csv-input').value = ''; }
  }
});

$('schema-header').textContent = `Legacy (17): ${CSV_COLUMNS.join(',')}\n\nV2 (19): ${V2_COLUMNS.join(',')}`;
V2_COLUMNS.forEach(name => {
  const row = el('tr');
  const role = PASSWORD_COLUMNS.includes(name) ? 'V2 password policy flag · not an ML feature' : FEATURE_COLUMNS.includes(name) ? 'ML model feature' : name === 'is_suspicious' ? 'Target label · not a model input' : name === 'attack_type' ? 'Evaluation metadata · not a model input' : 'Grouping / ordering · not a model input';
  row.append(el('td', '', name), el('td', '', role)); $('schema-table-body').append(row);
});
render();
loadModel().then(renderModelStatus);
setInterval(() => { if (!retention.check()) renderRetention(); }, 1000);
document.addEventListener('visibilitychange', () => { if (!retention.check()) renderRetention(); });
window.addEventListener('pagehide', () => resetView('The page was left; application references were released.'));
window.addEventListener('pageshow', () => { if (!retention.check()) renderRetention(); });
