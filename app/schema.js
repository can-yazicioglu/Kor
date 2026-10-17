// AI 1: shared schema is fixed. All model inputs go through this allowlist.
export const CSV_COLUMNS = Object.freeze([
  'event_id', 'event_ts_utc', 'session_token', 'account_token',
  'attempts_2m', 'attempts_1h', 'distinct_accounts_2m', 'failed_ratio_24h',
  'hour_deviation', 'typical_weekday', 'geo_velocity_kmh',
  'network_familiarity', 'asn_category', 'device_managed', 'device_new',
  'is_suspicious', 'attack_type',
]);
export const FEATURE_COLUMNS = Object.freeze(CSV_COLUMNS.slice(4, 15));
export const MAX_BYTES = 2 * 1024 * 1024;
export const MAX_ROWS = 10000;
const FLAGS = new Set(['typical_weekday', 'device_managed', 'device_new', 'is_suspicious']);
const COUNTS = new Set(['attempts_2m', 'attempts_1h', 'distinct_accounts_2m']);
const RATIOS = new Set(['failed_ratio_24h']);

function invalid(row, column, reason) {
  // Never echo a cell, token, file name, or entire row in an error.
  throw new Error(`Kayıt ${row} · ${column}: ${reason}`);
}

function readCells(text) {
  const rows = [];
  let row = [], cell = '', quoted = false, closed = false;
  const endCell = () => { row.push(cell); cell = ''; closed = false; };
  const endRow = () => {
    endCell();
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
    if (rows.length > MAX_ROWS + 1) throw new Error('En fazla 10.000 olay içe aktarılabilir.');
  };
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"') {
        if (text[i + 1] === '"') { cell += '"'; i++; }
        else { quoted = false; closed = true; }
      } else cell += char;
    } else if (char === ',') endCell();
    else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[i + 1] === '\n') i++;
      endRow();
    } else if (char === '"' && cell === '' && !closed) quoted = true;
    else if (closed || char === '"') throw new Error('CSV tırnak yapısı geçersiz.');
    else cell += char;
  }
  if (quoted) throw new Error('CSV içinde kapanmamış tırnak var.');
  if (cell !== '' || row.length || closed) endRow();
  return rows;
}

export function parseCSV(text) {
  if (new TextEncoder().encode(text).length > MAX_BYTES) throw new Error('Dosya sınırı 2 MiB.');
  const [header, ...rows] = readCells(text.replace(/^\uFEFF/, ''));
  if (!header || header.length !== CSV_COLUMNS.length || header.some((name, i) => name !== CSV_COLUMNS[i])) {
    throw new Error('CSV başlığı ortak 17 alanla ve alan sırasıyla tam eşleşmeli. Veri sözleşmesini kontrol edin.');
  }
  if (!rows.length) throw new Error('CSV başlığı doğru; gösterilecek olay yok.');
  const seen = new Set();
  return rows.map((cells, index) => {
    const rowNumber = index + 2;
    if (cells.length !== CSV_COLUMNS.length) invalid(rowNumber, 'CSV', '17 alan bekleniyor.');
    const event = {};
    CSV_COLUMNS.forEach((column, i) => {
      const value = cells[i].trim();
      if (i === 0 || i === 2 || i === 3) {
        if ((column !== 'account_token' && !value) || value.length > 128 || /[\x00-\x20\x7f]/.test(value)) {
          invalid(rowNumber, column, 'boşluksuz, en fazla 128 karakterlik opak anahtar bekleniyor.');
        }
        event[column] = value || null;
      } else if (column === 'event_ts_utc') {
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) {
          invalid(rowNumber, column, 'UTC ISO 8601 zaman damgası bekleniyor (Z).');
        }
        const date = new Date(value);
        if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 19) !== value.slice(0, 19)) {
          invalid(rowNumber, column, 'geçerli bir takvim zamanı bekleniyor.');
        }
        event[column] = value;
      } else if (column === 'asn_category' || column === 'attack_type' || column === 'network_familiarity') {
        if (value.length > 64 || /[\x00-\x1f\x7f]/.test(value)) invalid(rowNumber, column, 'en fazla 64 karakterlik kategori bekleniyor.');
        event[column] = value || null;
      } else if (!value) event[column] = null; // Missing history is unknown, never zero.
      else if (FLAGS.has(column)) {
        if (!['0', '1', 'true', 'false'].includes(value.toLowerCase())) invalid(rowNumber, column, '0/1 veya true/false bekleniyor.');
        event[column] = ['1', 'true'].includes(value.toLowerCase()) ? 1 : 0;
      } else {
        if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(value)) invalid(rowNumber, column, 'negatif olmayan sayı bekleniyor.');
        const number = Number(value);
        if (!Number.isFinite(number) || number > Number.MAX_SAFE_INTEGER || (COUNTS.has(column) && !Number.isSafeInteger(number)) || (RATIOS.has(column) && number > 1)) {
          invalid(rowNumber, column, RATIOS.has(column) ? '0–1 aralığı bekleniyor.' : 'geçerli, negatif olmayan sayı bekleniyor.');
        }
        event[column] = number;
      }
    });
    if (event.attempts_2m !== null && event.attempts_1h !== null && event.attempts_2m > event.attempts_1h) {
      invalid(rowNumber, 'attempts_2m', 'iki dakikalık sayı bir saatlik sayıyı aşamaz.');
    }
    if (event.hour_deviation !== null && event.hour_deviation > 12) invalid(rowNumber, 'hour_deviation', '0–12 saat aralığı bekleniyor.');
    if (seen.has(event.event_id)) invalid(rowNumber, 'event_id', 'yinelenen olay anahtarı.');
    seen.add(event.event_id);
    return event;
  });
}

export function selectFeatures(event) {
  return Object.fromEntries(FEATURE_COLUMNS.map(name => [name, event[name] ?? null]));
}

export function recommendation(score) {
  if (score === null) return { level: 'pending', label: 'Puan bekleniyor', action: 'Ek bağlamı incele', detail: 'Puan yok: model erişimini veya eksik bağlamı kontrol edin. Bu oturum düşük risk kabul edilmez; otomatik işlem yapılmaz.' };
  if (score >= 70) return { level: 'high', label: 'Yüksek risk', action: 'MFA + inceleme öner', detail: 'Ek doğrulama isteyin ve oturumu güvenlik ekibinin değerlendirmesine sunun.' };
  if (score >= 30) return { level: 'medium', label: 'Orta risk', action: 'MFA öner', detail: 'Kimlik sağlayıcısı üzerinden ek doğrulama değerlendirin.' };
  return { level: 'low', label: 'Düşük risk', action: 'İzlemeye devam et', detail: 'Bu puan güvenli oturum garantisi değildir. Mevcut güvenlik politikasını uygulayın.' };
}
