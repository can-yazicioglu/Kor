// Public password-only reference hashes. Entered passwords are checked locally,
// never logged, retained in results, or sent to a password-checking service.
export const REFERENCE_URL = './password-reference.json';
export const PASSWORD_POLICY = Object.freeze({ exact: 25, near: 10, version: 'password-policy-v1' });
const LIMIT = 4 * 1024 * 1024;
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const LEET = { '4':'a', '@':'a', '0':'o', '1':'i', '!':'i', '|':'i', '3':'e', '5':'s', '$':'s', '7':'t', '+':'t' };
const NORMALIZATION = {unicode:'NFKC',case:'lower',leet_map:LEET,
  suffix_pattern:'[0-9!@#$%^&*?._-]{1,4}$',suffix_min_base_codepoints:4,
  edit_pattern:'[a-z0-9]{6,32}',edit_alphabet:ALPHABET,
  edit_order:['delete','insert','substitute','adjacent_swap'],max_candidates:5000,max_password_codepoints:256};
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value==='object' ?
  Object.fromEntries(Object.keys(value).sort().map(key=>[key,sorted(value[key])])) : value;
export const normalizePassword = text => text.normalize('NFKC').toLowerCase().replace(/[4@01!|35$7+]/g, char => LEET[char]);
const unknown = () => ({ status:'unknown', password_in_blocklist:null, password_near_blocklist:null, match_type:'unknown', bonus:null });
const result = type => ({ status:'checked', password_in_blocklist:type === 'exact' ? 1 : 0,
  password_near_blocklist:['normalized','suffix','single_edit'].includes(type) ? 1 : 0,
  match_type:type, bonus:type === 'exact' ? 25 : type === 'none' ? 0 : 10 });
export function assessmentFromFlags(exact, near) {
  if (![0,1].includes(exact) || ![0,1].includes(near) || exact + near > 1) return unknown();
  return result(exact ? 'exact' : near ? 'normalized' : 'none');
}
export function validateAssessment(value) {
  if (!value || value.status !== 'checked') return unknown();
  const flags = assessmentFromFlags(value.password_in_blocklist, value.password_near_blocklist);
  if (flags.status !== 'checked' || flags.bonus !== value.bonus) return unknown();
  if (value.match_type === 'exact' && flags.password_in_blocklist === 1) return result('exact');
  if (['normalized','suffix','single_edit'].includes(value.match_type) && flags.password_near_blocklist === 1) return result(value.match_type);
  if (value.match_type === 'none' && flags.bonus === 0) return result('none');
  return unknown();
}
export function passwordReason(assessment) {
  const checked = validateAssessment(assessment);
  if (checked.status !== 'checked') return 'Password reference check unavailable; additional risk is unknown.';
  if (checked.password_in_blocklist) return 'Exact match in the local common-password reference (+25 policy points).';
  if (checked.password_near_blocklist) return 'Close variant of a local common-password reference (+10 policy points).';
  return 'No match in the loaded reference lists; this does not prove password safety.';
}
export function applyPasswordRisk(prediction, assessment) {
  const checked = validateAssessment(assessment);
  if (prediction === null || checked.status !== 'checked') return null;
  return { risk_score:Math.min(100, prediction.risk_score + checked.bonus),
    reasons:checked.bonus ? [passwordReason(checked), ...prediction.reasons].slice(0,6) : [...prediction.reasons],
    model_version:prediction.model_version };
}
export function editCandidates(value) {
  if (!/^[a-z0-9]{6,32}$/.test(value)) return [];
  const candidates = new Set();
  const add = text => { if (text !== value && candidates.size < 5000) candidates.add(text); };
  for (let i=0;i<value.length;i++) add(value.slice(0,i)+value.slice(i+1));
  for (let i=0;i<=value.length;i++) for (const char of ALPHABET) add(value.slice(0,i)+char+value.slice(i));
  for (let i=0;i<value.length;i++) for (const char of ALPHABET) if (char !== value[i]) add(value.slice(0,i)+char+value.slice(i+1));
  for (let i=0;i<value.length-1;i++) if (value[i] !== value[i+1]) add(value.slice(0,i)+value[i+1]+value[i]+value.slice(i+2));
  return [...candidates];
}
const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
  .map(byte=>byte.toString(16).padStart(2,'0')).join('');
export function createPasswordChecker(reference) {
  const validHashes = values => Array.isArray(values) && values.length > 0 && values.length <= 30000 &&
    values.every((hash,i)=>typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash) && (!i || values[i-1]<hash));
  if (!reference || reference.schema_version !== 'els-password-reference-v1' ||
      JSON.stringify(sorted(reference.normalization)) !== JSON.stringify(sorted(NORMALIZATION)) ||
      !Array.isArray(reference.sources) || !reference.sources.length ||
      reference.sources.some(source=>!source || typeof source.name!=='string' || !/^[0-9a-f]{64}$/.test(source.sha256??'') ||
        !Number.isInteger(source.entry_count) || source.entry_count<1) ||
      reference.artifact_integrity?.canonicalization !== 'python_json_sort_keys_utf8_excluding_artifact_integrity' ||
      reference.artifact_integrity?.purpose !== 'accidental_corruption_not_authenticity' ||
      !validHashes(reference.exact_sha256) || !validHashes(reference.normalized_sha256) ||
      reference.artifact_integrity?.algorithm !== 'sha256' ||
      !/^[0-9a-f]{64}$/.test(reference.artifact_integrity?.digest ?? '')) throw new Error('Password reference unavailable.');
  const exact = new Set(reference.exact_sha256), normalized = new Set(reference.normalized_sha256);
  return async password => {
    if (typeof password !== 'string' || [...password].length < 1 || [...password].length > 256 ||
        /[\uD800-\uDFFF]/u.test(password)) return unknown();
    try {
      if (exact.has(await digest(password))) return result('exact');
      const base = normalizePassword(password);
      if (normalized.has(await digest(base))) return result('normalized');
      const stripped = password.replace(/[0-9!@#$%^&*?._-]{1,4}$/u,'');
      if (stripped !== password && [...stripped].length >= 4 && normalized.has(await digest(normalizePassword(stripped)))) return result('suffix');
      const candidates = editCandidates(base);
      for (let start=0;start<candidates.length;start+=128) {
        const hashes = await Promise.all(candidates.slice(start,start+128).map(digest));
        if (hashes.some(hash=>normalized.has(hash))) return result('single_edit');
      }
      return result('none');
    } catch { return unknown(); }
  };
}
let checker = null, referenceGeneration = 0;
let referenceStatus = { state:'idle', entries:0 };
export function getPasswordReferenceStatus() { return {...referenceStatus}; }
export async function loadPasswordReference(fetcher = globalThis.fetch) {
  const generation = ++referenceGeneration;
  checker = null; referenceStatus = {state:'loading',entries:0};
  const controller = new AbortController(), timeout = setTimeout(()=>controller.abort(),5000);
  try {
    const response = await fetcher(REFERENCE_URL,{method:'GET',credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal});
    if (!response.ok) throw Error();
    const text = await response.text();
    if (text.length > LIMIT) throw Error();
    const reference = JSON.parse(text);
    if (generation !== referenceGeneration) return getPasswordReferenceStatus();
    checker = createPasswordChecker(reference);
    referenceStatus = {state:'ready',entries:reference.exact_sha256.length};
  } catch { if (generation === referenceGeneration) referenceStatus = {state:'unavailable',entries:0}; }
  finally { clearTimeout(timeout); }
  return getPasswordReferenceStatus();
}
export const checkPassword = password => checker ? checker(password) : Promise.resolve(unknown());
