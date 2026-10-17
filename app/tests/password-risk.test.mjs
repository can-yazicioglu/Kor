import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createPasswordChecker,normalizePassword,editCandidates,assessmentFromFlags,
  applyPasswordRisk,loadPasswordReference,checkPassword,getPasswordReferenceStatus} from '../password-risk.js';
const reference=JSON.parse(readFileSync(new URL('../../data/password_reference.json',import.meta.url),'utf8'));
const check=createPasswordChecker(reference);
let count=0;
const cases=['password','pASsW0rD!!','passwprd','VelaDemo!42','ＰＡＳＳＷＯＲＤ','',null,'x'.repeat(257),'🦊🚀aZx!private-test-70','\ud800','password1234'];
const actual=await Promise.all(cases.map(check));
assert.equal(actual[0].bonus,25);assert.equal(actual[1].bonus,10);
assert.equal(actual[2].match_type,'single_edit');assert.equal(actual[3].bonus,0);
assert.equal(actual[5].status,'unknown');assert.equal(actual[7].status,'unknown');
assert.equal(actual[9].status,'unknown');count++;
const python=spawnSync('.venv/bin/python',['-c',[
  'import sys,json',
  'from src.security.password_check import PasswordChecker',
  "check=PasswordChecker.from_file('data/password_reference.json').check",
  'print(json.dumps([check(x) for x in json.load(sys.stdin)]))',
].join('\n')],{cwd:new URL('../../',import.meta.url),input:JSON.stringify(cases),encoding:'utf8'});
// Use the repo interpreter when invoked from app/ or repository root.
if(python.error) {
  const fallback=spawnSync('python3',['-c',"import sys,json;from src.security.password_check import PasswordChecker;c=PasswordChecker.from_file('data/password_reference.json');print(json.dumps([c.check(x) for x in json.load(sys.stdin)]))"],
    {cwd:new URL('../../',import.meta.url),input:JSON.stringify(cases),encoding:'utf8'});
  assert.equal(fallback.status,0,fallback.stderr);assert.deepEqual(actual,JSON.parse(fallback.stdout));
} else {assert.equal(python.status,0,python.stderr);assert.deepEqual(actual,JSON.parse(python.stdout));}
count++;
assert.equal(normalizePassword('ＰＡＳＳＷ０ＲＤ'),'password');
assert.ok(editCandidates('passwprd').includes('password'));
assert.ok(editCandidates('a'.repeat(32)).length<=5000);
assert.equal(editCandidates('x'.repeat(33)).length,0);count++;
const prediction={risk_score:90,reasons:['Base model contribution'],model_version:'test'};
assert.equal(applyPasswordRisk(prediction,actual[0]).risk_score,100);
assert.equal(prediction.risk_score,90);
assert.equal(applyPasswordRisk(prediction,actual[5]),null);
assert.equal(applyPasswordRisk(null,actual[0]),null);
assert.equal(assessmentFromFlags(1,1).status,'unknown');
assert.equal(assessmentFromFlags(null,0).status,'unknown');count++;
const bad=structuredClone(reference);bad.normalization.unicode='NFC';
assert.throws(()=>createPasswordChecker(bad));
assert.throws(()=>createPasswordChecker({...reference,sources:[]}));
assert.throws(()=>createPasswordChecker({...reference,exact_sha256:['invalid']}));
count++;
const calls=[];
await loadPasswordReference(async(url,options)=>{calls.push({url,options});return {ok:true,text:async()=>JSON.stringify(reference)};});
assert.equal((await checkPassword('password')).bonus,25);
assert.equal(calls.length,1);assert.equal(calls[0].options.method,'GET');assert.equal(calls[0].options.body,undefined);count++;
let release;
const slow=loadPasswordReference(()=>new Promise(resolve=>{release=resolve;}));
await loadPasswordReference(async()=>({ok:false}));
release({ok:true,text:async()=>JSON.stringify(reference)});await slow;
assert.equal(getPasswordReferenceStatus().state,'unavailable');
assert.equal((await checkPassword('password')).status,'unknown');count++;
console.log(count+' password reference and policy checks passed (including Python/JS parity).');
