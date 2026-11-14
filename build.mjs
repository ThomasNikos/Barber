// Encrypts src/app.html with a password and writes a self-unlocking docs/index.html
// for GitHub Pages. The published page contains only ciphertext (AES-256-GCM,
// key derived with PBKDF2-SHA256), so the numbers are not readable without the password.
//
//   BARBER_PASSWORD='...' node build.mjs
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const pw = process.env.BARBER_PASSWORD;
if (!pw) {
  console.error('Set BARBER_PASSWORD, e.g.  BARBER_PASSWORD="..." node build.mjs');
  process.exit(1);
}

const ITER = 600000;
const enc = new TextEncoder();
const html = readFileSync(new URL('./src/app.html', import.meta.url), 'utf8');
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(html)));
const b64 = u => Buffer.from(u).toString('base64');
const payload = JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(ct), n: ITER });

const page = `<!doctype html>
<html lang="el">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Barber</title>
<style>
:root{--bg:#f5f1ea;--surface:#fffdf9;--ink:#1c1915;--muted:#6e665a;--line:#e0d8ca;--accent:#9c6a22;--neg:#b0402d;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#13110e;--surface:#1c1915;--ink:#f0e9de;--muted:#a59b8b;--line:#332e26;--accent:#d8a650;--neg:#e57a66;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
form{width:100%;max-width:340px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:28px 24px}
.pole{width:12px;height:36px;border-radius:6px;margin-bottom:14px;background:repeating-linear-gradient(-45deg,#b0402d 0 6px,#fff 6px 12px,#3f6e8c 12px 18px,#fff 18px 24px);border:1px solid var(--line)}
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
  <div class="pole"></div>
  <h1>Barber</h1>
  <p>Πλάνο Καλαμάτας · μόνο για εταίρους</p>
  <input type="password" id="pw" placeholder="Κωδικός" autocomplete="current-password" autofocus required>
  <label><input type="checkbox" id="rm"> Να με θυμάσαι σε αυτή τη συσκευή</label>
  <button id="go">Είσοδος</button>
  <div class="err" id="err"></div>
</form>
<script>
(()=>{
const P=${payload};
const d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function unlock(pw){
  const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:d(P.s),iterations:P.n,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['decrypt']);
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:d(P.i)},key,d(P.c)));
}
function show(html){document.open();document.write(html);document.close();}
const ls={get:k=>{try{return localStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}},del:k=>{try{localStorage.removeItem(k)}catch(e){}}};
const saved=ls.get('barber.pw');
if(saved){unlock(saved).then(h=>{window.__barberPw=saved;show(h);}).catch(()=>ls.del('barber.pw'));}
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const b=document.getElementById('go'),err=document.getElementById('err'),pw=document.getElementById('pw').value;
  b.disabled=true;b.textContent='Ξεκλείδωμα…';err.textContent='';
  try{const h=await unlock(pw);window.__barberPw=pw;if(document.getElementById('rm').checked)ls.set('barber.pw',pw);show(h);}
  catch(x){err.textContent='Λάθος κωδικός';b.disabled=false;b.textContent='Είσοδος';}
});
})();
</script>
</body>
</html>
`;

mkdirSync(new URL('./docs/', import.meta.url), { recursive: true });
writeFileSync(new URL('./docs/index.html', import.meta.url), page);
writeFileSync(new URL('./docs/.nojekyll', import.meta.url), '');
// Write token for the shared Supabase state (must match the browser derivation in src/app.html).
const syncBase = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
const syncBits = new Uint8Array(await crypto.subtle.deriveBits(
  { name: 'PBKDF2', salt: enc.encode('barber-sync-v1'), iterations: 600000, hash: 'SHA-256' }, syncBase, 512));
const token = Buffer.from(syncBits.slice(32)).toString('hex');
const tokenHash = Buffer.from(await crypto.subtle.digest('SHA-256', enc.encode(token))).toString('hex');
console.log(`\nRun once in Supabase (SQL editor) after changing the password:\n  insert into public.barber_secret (id, token_hash) values ('main', '${tokenHash}')\n  on conflict (id) do update set token_hash = excluded.token_hash;\n`);
console.log(`docs/index.html written (${(page.length / 1024).toFixed(0)} KB, PBKDF2 ${ITER} iterations)`);
