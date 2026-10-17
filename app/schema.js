// The original 17 fields stay fixed. V2 appends two independent password-policy flags.
export const CSV_COLUMNS = Object.freeze([
  'event_id', 'event_ts_utc', 'session_token', 'account_token',
  'attempts_2m', 'attempts_1h', 'distinct_accounts_2m', 'failed_ratio_24h',
  'hour_deviation', 'typical_weekday', 'geo_velocity_kmh',
  'network_familiarity', 'asn_category', 'device_managed', 'device_new',
  'is_suspicious', 'attack_type',
]);
export const PASSWORD_COLUMNS = Object.freeze(['password_in_blocklist', 'password_near_blocklist']);
export const V2_COLUMNS = Object.freeze([...CSV_COLUMNS, ...PASSWORD_COLUMNS]);
export const FEATURE_COLUMNS = Object.freeze(CSV_COLUMNS.slice(4, 15));
export const MAX_BYTES = 2 * 1024 * 1024;
export const MAX_ROWS = 10000;
const FLAGS = new Set(['typical_weekday', 'device_managed', 'device_new', 'is_suspicious', ...PASSWORD_COLUMNS]);
const COUNTS = new Set(['attempts_2m', 'attempts_1h', 'distinct_accounts_2m']);
const RATIOS = new Set(['failed_ratio_24h']);

function invalid(row, column, reason) {
  // Never echo a cell, token, file name, or entire row in an error.
  throw new Error(`Row ${row} · ${column}: ${reason}`);
}

function readCells(text) {
  const rows = [];
  let row = [], cell = '', quoted = false, closed = false;
  const endCell = () => { row.push(cell); cell = ''; closed = false; };
  const endRow = () => {
    endCell();
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
    if (rows.length > MAX_ROWS + 1) throw new Error('Import at most 10,000 events.');
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
    else if (closed || char === '"') throw new Error('Invalid CSV quoting.');
    else cell += char;
  }
  if (quoted) throw new Error('Unclosed quote in CSV.');
  if (cell !== '' || row.length || closed) endRow();
  return rows;
}

export function parseCSV(text) {
  if (new TextEncoder().encode(text).length > MAX_BYTES) throw new Error('The file limit is 2 MiB.');
  const [header, ...rows] = readCells(text.replace(/^\uFEFF/, ''));
  const columns = header?.length === V2_COLUMNS.length ? V2_COLUMNS : CSV_COLUMNS;
  if (!header || header.length !== columns.length || header.some((name, i) => name !== columns[i])) {
    throw new Error('CSV header must exactly match the 17 legacy fields or 19 V2 fields, in order. Check the data contract.');
  }
  if (!rows.length) throw new Error('CSV header is valid but there are no events to display.');
  const seen = new Set();
  return rows.map((cells, index) => {
    const rowNumber = index + 2;
    if (cells.length !== columns.length) invalid(rowNumber, 'CSV', `${columns.length} fields expected.`);
    const event = {};
    columns.forEach((column, i) => {
      const value = cells[i].trim();
      if (i === 0 || i === 2 || i === 3) {
        if ((column !== 'account_token' && !value) || value.length > 128 || /[\x00-\x20\x7f]/.test(value)) {
          invalid(rowNumber, column, 'an opaque token of at most 128 characters, without whitespace, is required.');
        }
        event[column] = value || null;
      } else if (column === 'event_ts_utc') {
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) {
          invalid(rowNumber, column, 'a UTC ISO 8601 timestamp ending in Z is required.');
        }
        const date = new Date(value);
        if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 19) !== value.slice(0, 19)) {
          invalid(rowNumber, column, 'a valid calendar timestamp is required.');
        }
        event[column] = value;
      } else if (column === 'asn_category' || column === 'attack_type' || column === 'network_familiarity') {
        if (value.length > 64 || /[\x00-\x1f\x7f]/.test(value)) invalid(rowNumber, column, 'a category of at most 64 characters is required.');
        event[column] = value || null;
      } else if (!value) event[column] = null; // Missing history is unknown, never zero.
      else if (PASSWORD_COLUMNS.includes(column)) {
        if (!['0', '1'].includes(value)) invalid(rowNumber, column, '0, 1 or an empty unknown value expected.');
        event[column] = Number(value);
      } else if (FLAGS.has(column)) {
        if (!['0', '1', 'true', 'false'].includes(value.toLowerCase())) invalid(rowNumber, column, '0/1 or true/false is required.');
        event[column] = ['1', 'true'].includes(value.toLowerCase()) ? 1 : 0;
      } else {
        if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(value)) invalid(rowNumber, column, 'a nonnegative number is required.');
        const number = Number(value);
        if (!Number.isFinite(number) || number > Number.MAX_SAFE_INTEGER || (COUNTS.has(column) && !Number.isSafeInteger(number)) || (RATIOS.has(column) && number > 1)) {
          invalid(rowNumber, column, RATIOS.has(column) ? 'a value between 0 and 1 is required.' : 'a valid nonnegative number is required.');
        }
        event[column] = number;
      }
    });
    if (event.attempts_2m !== null && event.attempts_1h !== null && event.attempts_2m > event.attempts_1h) {
      invalid(rowNumber, 'attempts_2m', 'the two-minute count cannot exceed the one-hour count.');
    }
    if (event.hour_deviation !== null && event.hour_deviation > 12) invalid(rowNumber, 'hour_deviation', 'a value between 0 and 12 hours is required.');
    if (event.password_in_blocklist === 1 && event.password_near_blocklist === 1) {
      invalid(rowNumber, 'password flags', 'exact and near matches cannot both be 1.');
    }
    if (seen.has(event.event_id)) invalid(rowNumber, 'event_id', 'duplicate event token.');
    seen.add(event.event_id);
    return event;
  });
}

export function selectFeatures(event) {
  return Object.fromEntries(FEATURE_COLUMNS.map(name => [name, event[name] ?? null]));
}

export function recommendation(score) {
  if (score === null) return { level: 'pending', label: 'Awaiting score', action: 'Review additional context', detail: 'No score: check model availability or missing context. This session is not treated as low risk. No action is triggered automatically.' };
  if (score >= 70) return { level: 'high', label: 'High risk', action: 'Recommend MFA + review', detail: 'Request additional verification and refer the session for security review.' };
  if (score >= 30) return { level: 'medium', label: 'Medium risk', action: 'Recommend MFA', detail: 'Consider additional verification through the identity provider.' };
  return { level: 'low', label: 'Low risk', action: 'Continue monitoring', detail: 'This score does not guarantee a safe session. Apply your existing security policy.' };
}
