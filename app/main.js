import { CSV_COLUMNS, FEATURE_COLUMNS, MAX_BYTES, parseCSV, recommendation } from './schema.js';
import { MOCK_CARDS } from './mock-view.js';
import { predictRisk } from './model-adapter.js';
import { buildSessions } from './sessions.js';

const $ = id => document.getElementById(id);
let sessions = [...MOCK_CARDS];
let selectedId = sessions[0].id;
let mode = 'mock';
let importGeneration = 0;
const labels = { high: 'Yüksek', medium: 'Orta', low: 'Düşük', pending: 'Bekliyor' };

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
  const term = $('search').value.trim().toLocaleLowerCase('tr');
  const filter = $('risk-filter').value;
  return sessions.filter(session =>
    (!term || session.id.toLocaleLowerCase('tr').includes(term) || (session.mock && session.title.toLocaleLowerCase('tr').includes(term))) &&
    (filter === 'all' || recommendation(session.score).level === filter));
}

function renderList() {
  const visible = filteredSessions();
  if (!visible.some(session => session.id === selectedId)) selectedId = visible[0]?.id ?? null;
  $('session-list').replaceChildren();
  for (const session of visible) {
    const risk = recommendation(session.score);
    const button = el('button', `session-row${session.id === selectedId ? ' selected' : ''}`);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(session.id === selectedId));
    button.setAttribute('aria-label', `${sessionTitle(session)}, ${session.score ?? 'puan bekliyor'}${session.mock ? ', mock' : ''}`);
    const identity = el('span', 'session-identity');
    const icon = el('span', 'session-icon', session.mock ? '◇' : '◫');
    icon.setAttribute('aria-hidden', 'true');
    const content = el('span', 'session-text');
    content.append(el('span', 'session-title', sessionTitle(session)));
    content.append(el('span', 'session-subtitle', session.mock ? shortId(session.id) : `${session.events.length} olay · Opak oturum anahtarı`));
    content.append(el('span', 'session-meta', `${eventTime(session)}${session.mock ? ` · ${session.count}` : ''}`));
    identity.append(icon, content);
    const right = el('span', `row-risk ${risk.level}`);
    const score = el('span', 'score-cell');
    score.append(el('strong', '', session.score === null ? '—' : String(Math.round(session.score))), el('span', 'risk-label', risk.label));
    const chevron = el('span', 'row-chevron', '›'); chevron.setAttribute('aria-hidden', 'true');
    right.append(score, chevron);
    button.append(identity, right);
    button.addEventListener('click', () => { selectedId = session.id; renderList(); renderDetail(); $('session-list').querySelector('[aria-pressed="true"]')?.focus({ preventScroll: true }); });
    $('session-list').append(button);
  }
  if (!visible.length) $('session-list').append(el('p', 'empty-state', 'Bu filtreyle eşleşen oturum yok. Aramayı veya risk filtresini değiştirin.'));
  $('shown-count').textContent = `${visible.length} / ${sessions.length} oturum gösteriliyor`;
  $('list-count').textContent = String(sessions.length);
}

function renderDetail() {
  const root = $('session-detail'); root.replaceChildren();
  const session = sessions.find(item => item.id === selectedId);
  if (!session) { root.append(el('p', 'empty-state', 'Ayrıntıları görmek için listeden bir oturum seçin.')); return; }
  const risk = recommendation(session.score);
  const hero = el('div', 'detail-hero');
  const head = el('div', 'detail-head');
  head.append(el('h2', '', 'Oturum risk özeti'), el('span', 'pill', session.mock ? 'MOCK PUAN' : session.score === null ? 'MODEL BEKLENİYOR' : 'MODEL ÇIKTISI'));
  hero.append(head, el('p', 'detail-session', shortId(session.id)));
  const scoreLine = el('div', 'score-line');
  const scoreContext = el('div', 'score-context');
  scoreContext.append(el('strong', '', risk.label), el('span', '', '100 en yüksek risk'));
  scoreLine.append(el('div', 'hero-score', session.score === null ? '—' : String(Math.round(session.score))), scoreContext);
  hero.append(scoreLine);
  const meter = el('div', 'hero-meter'); meter.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < 20; i++) meter.append(el('span', session.score !== null && i < session.score / 5 ? 'filled' : ''));
  const endpoints = el('div', 'meter-labels'); endpoints.append(el('span', '', '0 · Düşük'), el('span', '', '100 · Yüksek'));
  hero.append(meter, endpoints);

  const body = el('div', 'detail-content');
  body.append(el('h3', '', session.mock ? 'Örnek risk nedenleri' : session.score === null ? 'Puanlama durumu' : 'Modelin risk nedenleri'));
  const reasons = el('ul', 'reason-list');
  const explanations = session.mock ? session.reasons : session.score === null ?
    [session.error ? 'Model yanıtı alınamadı veya doğrulanamadı. Bu oturum için puan üretilmedi.' : 'CSV doğrulandı. Gerçek model henüz bağlı olmadığı için bu oturum puanlanmadı.',
      'Hedef etiket ve saldırı türü risk gerekçesi olarak kullanılmaz.',
      'Bilinmeyen geçmiş olağan davranış olarak varsayılmaz.'] :
    session.reasons.length ? session.reasons : ['Model açıklama döndürmedi; gerekçe uydurulmadı.'];
  explanations.forEach(reason => reasons.append(el('li', '', reason)));
  body.append(reasons);
  const signals = el('div', 'signals');
  const source = session.scoredEvent || session.latest;
  const signalValues = session.mock ? session.signals : [
    ['Deneme / 2 dk', source.attempts_2m ?? 'Bilinmiyor'],
    ['Hesap / 2 dk', source.distinct_accounts_2m ?? 'Bilinmiyor'],
    ['Yeni cihaz', source.device_new === null ? 'Bilinmiyor' : source.device_new ? 'Evet' : 'Hayır'],
  ];
  signalValues.forEach(([key, value]) => { const signal = el('span', 'signal', `${key}: `); signal.append(el('strong', '', String(value))); signals.append(signal); });
  body.append(signals);
  const action = el('div', 'action-box');
  action.append(el('div', 'action-kicker', 'ÖNERİLEN SONRAKİ ADIM'), el('h3', '', `↗  ${risk.action}`), el('p', '', risk.detail));
  const foot = el('p', 'detail-foot');
  foot.textContent = session.mock ? 'Mock senaryo · Eşikler yalnızca demo politikasıdır. Otomatik kilitleme veya gerçek MFA işlemi yapılmaz.' :
    session.score === null ? 'Puan yok ≠ düşük risk. Gösterilen sinyaller en son olaya aittir. CSV yalnızca tarayıcı belleğinde tutulur.' :
    `Model: ${session.modelVersion} · Oturumun en yüksek olay puanı gösterilir. Sinyaller ve nedenler bu olaya aittir. Eşikler doğrulanmış değildir.`;
  root.append(hero, body, action, foot);
}

function renderStats() {
  const count = { high: 0, medium: 0, low: 0, pending: 0 };
  sessions.forEach(session => count[recommendation(session.score).level]++);
  $('total-count').textContent = sessions.length;
  $('high-count').replaceChildren(document.createTextNode(String(count.high)), el('span', 'stat-unit', 'oturum'));
  $('mfa-count').replaceChildren(document.createTextNode(String(count.high + count.medium)), el('span', 'stat-unit', 'oturum'));
  $('total-caption').textContent = mode === 'mock' ? 'Sabit mock senaryolar' : `${sessions.reduce((sum, s) => sum + s.events.length, 0)} olay · ${count.pending} oturum puan bekliyor`;
  $('distribution-caption').textContent = mode === 'mock' ? 'Yalnızca mock kartların dağılımı; model performansı değildir.' : 'İçe aktarılan tüm oturumlar. Puan bekleyenler düşük risk sayılmaz.';
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
  const text = mode === 'mock' ? 'Puanlar ve gerekçeler sabit gösterim örnekleridir; model sonucu veya başarı metriği değildir.' : 'CSV tarayıcı belleğinde işlendi. Model bağlanana kadar puanlar bekler; hedef etiketler modele veya risk nedenlerine aktarılmaz.';
  const paragraph = el('p'); paragraph.append(el('strong', '', mode === 'mock' ? 'Arayüz önizlemesi. ' : 'Yerel CSV görünümü. '), document.createTextNode(text));
  notice.append(el('span', 'pill mock-pill', mode === 'mock' ? 'MOCK' : 'YEREL CSV'), paragraph);
}

function render() { renderList(); renderDetail(); renderStats(); renderNotice(); }
function showView(view) {
  const descriptions = {
    overview: ['Genel görünüm', 'Oturum güvenliği', 'Şüpheli bağlamı fark edin. Bir sonraki adımı bilin.'],
    contract: ['Veri sözleşmesi', 'Ortak dil, net sınırlar', 'Kimlik, özellik ve etiket birbirinden ayrılır.'],
    privacy: ['Gizlilik sınırı', 'Gizlilik, en başından', 'Müşteri verisi müşteri ortamında kalır.'],
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
$('search').addEventListener('input', () => { renderList(); renderDetail(); });
$('risk-filter').addEventListener('change', () => { renderList(); renderDetail(); });
$('import-button').addEventListener('click', () => $('csv-input').click());
$('reset-button').addEventListener('click', () => {
  importGeneration++;
  sessions = [...MOCK_CARDS]; selectedId = sessions[0].id; mode = 'mock';
  $('search').value = ''; $('risk-filter').value = 'all'; $('csv-input').value = '';
  $('error').hidden = true; $('error').textContent = '';
  $('import-button').disabled = false;
  render(); showView('overview');
});
$('csv-input').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  const generation = ++importGeneration;
  $('error').hidden = true; $('error').textContent = '';
  $('import-button').disabled = true;
  $('notice').replaceChildren(el('p', '', 'CSV doğrulanıyor ve oturumlar hazırlanıyor…'));
  try {
    if (file.size > MAX_BYTES) throw new Error('Dosya sınırı 2 MiB. Daha küçük bir CSV seçin.');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    if (generation !== importGeneration) return;
    const events = parseCSV(text);
    const imported = await buildSessions(events, features => {
      if (generation !== importGeneration) return null;
      return predictRisk(features);
    });
    if (generation !== importGeneration) return;
    sessions = imported; selectedId = sessions[0]?.id ?? null; mode = 'csv';
    $('search').value = ''; $('risk-filter').value = 'all';
    render(); showView('overview');
  } catch (error) {
    if (generation !== importGeneration) return;
    // Only our controlled parse errors contain text; never print native decoding errors.
    const message = error instanceof TypeError ? 'Dosya UTF-8 olarak okunamadı.' : error.message;
    $('error').textContent = `${message} Önceki görünüm korundu. Gerçek kayıtları AI sohbetine yüklemeyin.`;
    $('error').hidden = false;
    renderNotice();
  } finally {
    if (generation === importGeneration) { $('import-button').disabled = false; $('csv-input').value = ''; }
  }
});

$('schema-header').textContent = CSV_COLUMNS.join(',');
CSV_COLUMNS.forEach(name => {
  const row = el('tr');
  const role = FEATURE_COLUMNS.includes(name) ? 'Model özelliği' : name === 'is_suspicious' ? 'Hedef etiket · model girdisi değil' : name === 'attack_type' ? 'Değerlendirme metaverisi · model girdisi değil' : 'Gruplama / sıralama · model girdisi değil';
  row.append(el('td', '', name), el('td', '', role)); $('schema-table-body').append(row);
});
render();
