// Builds docs/index.html: a login page that holds the app encrypted, unlockable by
// any user listed in .secrets.json (gitignored), each with their own password.
//
//   node build.mjs                 build with the users in .secrets.json
//   node build.mjs add "Πάνος"     add a user (random password), then build
//   node build.mjs reset "Θωμάς"   give a user a new random password, then build
//
// How it works
// - The app (src/app.html) is encrypted once with a random content key (AES-256-GCM).
// - For every user, that content key + the user's name + their personal write token are
//   encrypted with a key derived from their password (PBKDF2-SHA256, 600k iterations).
//   The login page tries the typed password against each user's slot.
// - The shared data key (dataKey) is baked into the encrypted app; the browser uses it to
//   encrypt the state stored in Supabase. The server only knows sha256(token) per user,
//   so it can tell who saved what (logs) without being able to read the data.
// After adding a user or resetting a password, run the SQL that this script prints.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { webcrypto as crypto, randomBytes, randomInt, createHash } from 'node:crypto';

const ITER = 600000;
const enc = new TextEncoder();
const root = new URL('./', import.meta.url);
const secretsPath = new URL('.secrets.json', root);
const b64 = u => Buffer.from(u).toString('base64');
const genPassword = () => {
  const w = 'abcdefghjkmnpqrstuvwxyz23456789';
  let s = '';
  for (let i = 0; i < 12; i++) s += w[randomInt(w.length)];
  return `barber-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
};

if (!existsSync(secretsPath)) {
  writeFileSync(secretsPath, JSON.stringify({ dataKey: randomBytes(32).toString('hex'), users: [] }, null, 2), { mode: 0o600 });
}
const sec = JSON.parse(readFileSync(secretsPath, 'utf8'));
const [cmd, who] = process.argv.slice(2);
const changed = [];
if (cmd === 'add') {
  if (!who) throw new Error('usage: node build.mjs add "Name"');
  if (sec.users.some(u => u.name === who)) throw new Error(`user ${who} exists`);
  sec.users.push({ name: who, password: genPassword(), token: randomBytes(32).toString('hex') });
  changed.push(who);
} else if (cmd === 'reset') {
  const u = sec.users.find(x => x.name === who);
  if (!u) throw new Error(`no user ${who}`);
  u.password = genPassword(); u.token = randomBytes(32).toString('hex');
  changed.push(who);
} else if (cmd) throw new Error(`unknown command ${cmd}`);
if (!sec.users.length) throw new Error('no users: run  node build.mjs add "Name"');
writeFileSync(secretsPath, JSON.stringify(sec, null, 2), { mode: 0o600 });

// 1. encrypt the app with a random content key
let html = readFileSync(new URL('src/app.html', root), 'utf8');
const BUILD = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
html = html.replace('__BARBER_BUILD__', BUILD);
if (!html.includes('__BARBER_DATA_KEY__')) throw new Error('placeholder __BARBER_DATA_KEY__ missing in src/app.html');
html = html.replace('__BARBER_DATA_KEY__', sec.dataKey);
const cekRaw = crypto.getRandomValues(new Uint8Array(32));
const cek = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['encrypt']);
const appIv = crypto.getRandomValues(new Uint8Array(12));
const appCt = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: appIv }, cek, enc.encode(html)));

// 2. one slot per user
const salt = crypto.getRandomValues(new Uint8Array(16));
const slots = [];
for (const u of sec.users) {
  const base = await crypto.subtle.importKey('raw', enc.encode(u.password), 'PBKDF2', false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = enc.encode(JSON.stringify({ k: b64(cekRaw), u: u.name, t: u.token }));
  slots.push({ i: b64(iv), c: b64(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, body))) });
}
// shuffle so slot order does not reveal the user order
for (let i = slots.length - 1; i > 0; i--) { const j = randomInt(i + 1); [slots[i], slots[j]] = [slots[j], slots[i]]; }
const payload = JSON.stringify({ n: ITER, s: b64(salt), a: { i: b64(appIv), c: b64(appCt) }, slots });

const page = `<!doctype html>
<html lang="el">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#1c1915">
<title>Barber</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg">
<link rel="icon" type="image/png" sizes="32x32" href="favicon-32.png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<style>
:root{--bg:#f5f1ea;--surface:#fffdf9;--ink:#1c1915;--muted:#6e665a;--line:#e0d8ca;--accent:#9c6a22;--neg:#b0402d;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#13110e;--surface:#1c1915;--ink:#f0e9de;--muted:#a59b8b;--line:#332e26;--accent:#d8a650;--neg:#e57a66;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
form{width:100%;max-width:340px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:28px 24px}
.logo{width:44px;height:44px;margin-bottom:14px;display:block}
h1{margin:0;font-size:20px;letter-spacing:.22em;text-transform:uppercase}
p{margin:4px 0 20px;color:var(--muted);font-size:14px}
input[type=password]{width:100%;font:inherit;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:inherit;outline:none}
input[type=password]:focus{border-color:var(--accent)}
label{display:flex;gap:8px;align-items:center;font-size:13px;color:var(--muted);margin:12px 0 16px}
label input{accent-color:var(--accent)}
button{width:100%;font:inherit;font-weight:600;padding:11px;border:0;border-radius:10px;background:var(--accent);color:#fff;cursor:pointer}
button:disabled{opacity:.6}
.err{color:var(--neg);font-size:13px;min-height:18px;margin-top:10px}
</style>
</head>
<body>
<form id="f" autocomplete="on">
  <img class="logo" src="favicon.svg" alt="">
  <h1>Barber</h1>
  <p>Πλάνο Καλαμάτας · μόνο για εταίρους</p>
  <input type="password" id="pw" placeholder="Ο κωδικός σου" autocomplete="current-password" autofocus required>
  <label><input type="checkbox" id="rm"> Να με θυμάσαι σε αυτή τη συσκευή</label>
  <button id="go">Είσοδος</button>
  <div class="err" id="err"></div>
</form>
<script>
(()=>{
const P=${payload};
const d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const te=new TextEncoder(),td=new TextDecoder();
async function unlock(pw){
  const base=await crypto.subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
  const kek=await crypto.subtle.deriveKey({name:'PBKDF2',salt:d(P.s),iterations:P.n,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  for(const sl of P.slots){
    let o;
    try{o=JSON.parse(td.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:d(sl.i)},kek,d(sl.c))));}catch(e){continue;}
    const cek=await crypto.subtle.importKey('raw',d(o.k),'AES-GCM',false,['decrypt']);
    const html=td.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:d(P.a.i)},cek,d(P.a.c)));
    return {html,user:o.u,token:o.t};
  }
  throw new Error('bad password');
}
function show(r){window.__barber={user:r.user,token:r.token};document.open();document.write(r.html);document.close();}
const ls={get:k=>{try{return localStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}},del:k=>{try{localStorage.removeItem(k)}catch(e){}}};
const ss={get:k=>{try{return sessionStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{sessionStorage.setItem(k,v)}catch(e){}}};
const saved=ls.get('barber.pw')||ss.get('barber.pw');
if(saved){unlock(saved).then(show).catch(()=>ls.del('barber.pw'));}
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const b=document.getElementById('go'),err=document.getElementById('err'),pw=document.getElementById('pw').value;
  b.disabled=true;b.textContent='Ξεκλείδωμα…';err.textContent='';
  try{const r=await unlock(pw);ss.set('barber.pw',pw);if(document.getElementById('rm').checked)ls.set('barber.pw',pw);show(r);}
  catch(x){err.textContent='Λάθος κωδικός';b.disabled=false;b.textContent='Είσοδος';}
});
})();
</script>
</body>
</html>
`;

mkdirSync(new URL('docs/', root), { recursive: true });
writeFileSync(new URL('docs/index.html', root), page);
writeFileSync(new URL('docs/.nojekyll', root), '');
writeFileSync(new URL('docs/version.txt', root), BUILD);

const sha = t => createHash('sha256').update(t, 'utf8').digest('hex');
const sql = sec.users.map(u => `('${u.name.replace(/'/g, "''")}', '${sha(u.token)}')`).join(',\n  ');
console.log(`docs/index.html written (${(page.length / 1024).toFixed(0)} KB, ${sec.users.length} users: ${sec.users.map(u => u.name).join(', ')})`);
console.log(`\nSync users in Supabase (SQL editor):\n  delete from public.barber_users where name not in (${sec.users.map(u => `'${u.name.replace(/'/g, "''")}'`).join(', ')});\n  insert into public.barber_users (name, token_hash) values\n  ${sql}\n  on conflict (name) do update set token_hash = excluded.token_hash;\n`);
if (changed.length) console.log(`New password for ${changed.join(', ')}: see .secrets.json`);
