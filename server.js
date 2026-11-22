// BouncyBall relay: принимает команды из панели управления и раздаёт их
// программам BouncyBall.exe (long polling по обычному HTTPS). Без зависимостей.
//
// Запуск:  ADMIN_TOKEN=придумай-длинный-пароль node server.js
// Переменные окружения: ADMIN_TOKEN (обязательно, от 8 символов), PORT (по умолчанию 3000)
'use strict';
const http = require('http');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
if (ADMIN_TOKEN.length < 8) {
  console.error('Задай переменную окружения ADMIN_TOKEN (минимум 8 символов).');
  process.exit(1);
}

const POLL_MS = 25000;          // сколько сервер держит запрос, если команд нет
const HISTORY = 50;             // сколько последних команд помнить в комнате
const MAX_ROOMS = 500;
const PRESENCE_MS = 45000;      // клиент считается «онлайн», если опрашивал недавно
const ROOM_RE = /^[A-Za-z0-9_.-]{8,64}$/;

const rooms = new Map();        // ключ комнаты -> состояние

function getRoom(key, create) {
  let r = rooms.get(key);
  if (!r && create) {
    if (rooms.size >= MAX_ROOMS) return null;
    r = { last: 0, cmds: [], waiters: new Set(), clients: new Map(), touched: Date.now() };
    rooms.set(key, r);
  }
  if (r) r.touched = Date.now();
  return r || null;
}

function onlineCount(r) {
  const now = Date.now();
  let n = 0;
  for (const [id, ts] of r.clients) {
    if (now - ts > PRESENCE_MS) r.clients.delete(id); else n++;
  }
  return n;
}

// чистим давно не используемые комнаты
setInterval(() => {
  const now = Date.now();
  for (const [k, r] of rooms) {
    if (r.waiters.size === 0 && now - r.touched > 6 * 3600 * 1000) rooms.delete(k);
  }
}, 10 * 60 * 1000).unref();

// ---------- команды (белый список: ничего, кроме этого, клиент не исполняет) ----------

function cleanText(s, max) {
  s = String(s == null ? '' : s).replace(/\r\n?/g, '\n');
  s = s.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, ' ');   // управляющие символы (кроме \n)
  s = Array.from(s).slice(0, max).join('').trim();
  return s.replace(/\n/g, '\u000B');                            // перевод строки -> VT (в протоколе строки разделены \n)
}

function intIn(v, lo, hi, def) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(hi, Math.max(lo, n));
}

function buildCommand(b) {
  const cmd = String(b.cmd || '');
  switch (cmd) {
    case 'kick':      return { cmd, a: ['', '', ''] };
    case 'add':       return { cmd, a: [String(intIn(b.a1, 1, 5, 1)), '', ''] };
    case 'remove':    return { cmd, a: [String(intIn(b.a1, 1, 5, 1)), '', ''] };
    case 'size':      return ['up', 'down', 'reset'].includes(b.a1) ? { cmd, a: [b.a1, '', ''] } : null;
    case 'mode':      return ['cat', 'plain'].includes(b.a1) ? { cmd, a: [b.a1, '', ''] } : null;
    case 'clearsign': return { cmd, a: ['', '', ''] };
    case 'sign': {
      const text = cleanText(b.a1, 300);
      if (!text) return null;
      const secs = intIn(b.a2, 3, 300, 10);
      const style = ['note', 'alert', 'plain'].includes(b.a3) ? b.a3 : 'note';
      return { cmd, a: [text, String(secs), style] };
    }
    default: return null;
  }
}

function pushCommand(r, c) {
  const id = ++r.last;
  const line = 'C ' + id + '\t' + c.cmd + '\t' + c.a.join('\t');
  r.cmds.push({ id, line });
  if (r.cmds.length > HISTORY) r.cmds.shift();
  for (const w of Array.from(r.waiters)) flushWaiter(r, w);
  return id;
}

function bodyFor(r, since) {
  const out = ['L ' + r.last];
  for (const c of r.cmds) if (c.id > since) out.push(c.line);
  return out.join('\n') + '\n';
}

function flushWaiter(r, w) {
  if (r.last <= w.since) return;
  clearTimeout(w.timer);
  r.waiters.delete(w);
  reply(w.res, 200, bodyFor(r, w.since), 'text/plain; charset=utf-8');
}

// ---------- вспомогательное ----------

function reply(res, code, body, type) {
  if (res.writableEnded) return;
  res.writeHead(code, {
    'Content-Type': type || 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}
const json = (res, code, obj) => reply(res, code, JSON.stringify(obj));

function isAdmin(req) {
  const given = String(req.headers['x-admin'] || '');
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(ADMIN_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
}

const hits = new Map();   // простейший лимит запросов: ip -> [время, ...]
function rateOk(ip, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < windowMs);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length <= max;
}
setInterval(() => hits.clear(), 5 * 60 * 1000).unref();

// Защита от подбора пароля: после 10 неудачных попыток с одного адреса - пауза
function authOk(req, ip) {
  const key = 'fail:' + ip, now = Date.now();
  const recent = (hits.get(key) || []).filter(t => now - t < 10 * 60 * 1000);
  if (recent.length >= 10) return false;
  if (isAdmin(req)) return true;
  recent.push(now);
  hits.set(key, recent);
  return false;
}

function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.socket.remoteAddress || '?';
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', d => {
      size += d.length;
      if (size > limit) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// ---------- HTTP ----------

const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, 'http://x'); } catch { return json(res, 400, { ok: false }); }
  const path = url.pathname;
  const ip = clientIp(req);

  try {
    if (req.method === 'GET' && path === '/') return reply(res, 200, PANEL_HTML, 'text/html; charset=utf-8');
    if (req.method === 'GET' && path === '/healthz') return reply(res, 200, 'ok', 'text/plain');

    // --- опрос от программы: GET /api/poll?room=...&since=N&c=clientId ---
    if (req.method === 'GET' && path === '/api/poll') {
      if (!rateOk('poll:' + ip, 120, 60000)) return reply(res, 429, 'slow down\n', 'text/plain');
      const key = url.searchParams.get('room') || '';
      if (!ROOM_RE.test(key)) return reply(res, 400, 'bad room\n', 'text/plain');
      const r = getRoom(key, true);
      if (!r) return reply(res, 503, 'busy\n', 'text/plain');
      const cid = (url.searchParams.get('c') || '').slice(0, 32) || ip;
      r.clients.set(cid, Date.now());
      let since = parseInt(url.searchParams.get('since') || '-1', 10);
      if (!Number.isFinite(since)) since = -1;
      // первый запрос (-1) или сервер перезапускался (since больше last): просто синхронизируем номер
      if (since < 0 || since > r.last) return reply(res, 200, 'L ' + r.last + '\n', 'text/plain; charset=utf-8');
      if (r.last > since) return reply(res, 200, bodyFor(r, since), 'text/plain; charset=utf-8');
      const w = { res, since, timer: null };
      w.timer = setTimeout(() => {
        r.waiters.delete(w);
        r.clients.set(cid, Date.now());
        reply(res, 200, 'L ' + r.last + '\n', 'text/plain; charset=utf-8');
      }, POLL_MS);
      r.waiters.add(w);
      req.on('close', () => { clearTimeout(w.timer); r.waiters.delete(w); });
      return;
    }

    // --- отправка команды: POST /api/send (нужен заголовок x-admin) ---
    if (req.method === 'POST' && path === '/api/send') {
      if (!rateOk('send:' + ip, 30, 10000)) return json(res, 429, { ok: false, error: 'слишком часто' });
      if (!authOk(req, ip)) return json(res, 401, { ok: false, error: 'неверный пароль администратора' });
      let b;
      try { b = JSON.parse(await readBody(req, 4096)); } catch { return json(res, 400, { ok: false, error: 'плохой запрос' }); }
      const key = String(b.room || '');
      if (!ROOM_RE.test(key)) return json(res, 400, { ok: false, error: 'ключ комнаты: 8-64 символа (буквы, цифры, _ . -)' });
      const c = buildCommand(b);
      if (!c) return json(res, 400, { ok: false, error: 'неизвестная команда или неверные параметры' });
      const r = getRoom(key, true);
      if (!r) return json(res, 503, { ok: false, error: 'сервер занят' });
      const id = pushCommand(r, c);
      return json(res, 200, { ok: true, id, online: onlineCount(r) });
    }

    // --- статус комнаты: GET /api/status?room=... (нужен x-admin) ---
    if (req.method === 'GET' && path === '/api/status') {
      if (!rateOk('status:' + ip, 60, 60000)) return json(res, 429, { ok: false });
      if (!authOk(req, ip)) return json(res, 401, { ok: false, error: 'неверный пароль администратора' });
      const key = url.searchParams.get('room') || '';
      if (!ROOM_RE.test(key)) return json(res, 400, { ok: false, error: 'плохой ключ комнаты' });
      const r = getRoom(key, false);
      return json(res, 200, { ok: true, online: r ? onlineCount(r) : 0 });
    }

    return reply(res, 404, 'not found', 'text/plain');
  } catch (e) {
    console.error(e);
    return json(res, 500, { ok: false });
  }
});
server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;
server.listen(PORT, () => console.log('BouncyBall relay слушает порт ' + PORT));

// ---------- панель управления ----------

const PANEL_HTML = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BouncyBall: пульт</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--fg:#1d2230;--mut:#667085;--acc:#2f6fed;--bd:#dfe3ea;--ok:#12a150;--bad:#d92d20}
@media(prefers-color-scheme:dark){:root{--bg:#14161c;--card:#1d2028;--fg:#e8ebf2;--mut:#9aa3b5;--bd:#2c3140;--acc:#6b9bff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.4 system-ui,Segoe UI,sans-serif}
main{max-width:640px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:8px 0 16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;margin-bottom:14px}
.card h2{font-size:14px;color:var(--mut);margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em}
label{display:block;font-size:13px;color:var(--mut);margin:8px 0 4px}
input,textarea,select{width:100%;padding:10px;border:1px solid var(--bd);border-radius:8px;background:transparent;color:inherit;font:inherit}
textarea{min-height:80px;resize:vertical}
.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1 1 120px}
button{padding:11px 12px;border:0;border-radius:8px;background:var(--acc);color:#fff;font:inherit;cursor:pointer}
button.sec{background:transparent;color:var(--fg);border:1px solid var(--bd)}
button:active{transform:translateY(1px)}
#st{font-size:14px}#st.ok{color:var(--ok)}#st.bad{color:var(--bad)}
#log{font:13px/1.5 ui-monospace,monospace;color:var(--mut);max-height:140px;overflow:auto;white-space:pre-wrap}
</style></head><body><main>
<h1>⚽ BouncyBall: пульт</h1>
<div class="card"><h2>Подключение</h2>
 <label>Ключ комнаты (как в настройках программы)</label><input id="room" autocomplete="off" placeholder="например: moya-komnata-2026">
 <label>Пароль администратора</label><input id="tok" type="password" autocomplete="off">
 <p id="st">—</p></div>
<div class="card"><h2>Мячи</h2>
 <div class="row"><button data-c="kick">🚀 Подбросить все</button><button data-c="add" data-a1="1">＋ Мяч</button><button data-c="add" data-a1="3">＋ 3 мяча</button><button class="sec" data-c="remove" data-a1="1">− Мяч</button></div>
 <div class="row" style="margin-top:8px"><button class="sec" data-c="size" data-a1="down">Меньше</button><button class="sec" data-c="size" data-a1="up">Больше</button><button class="sec" data-c="size" data-a1="reset">Размер 100%</button></div>
 <div class="row" style="margin-top:8px"><button class="sec" data-c="mode" data-a1="cat">🐱 Котик</button><button class="sec" data-c="mode" data-a1="plain">🔴 Цветные мячи</button></div></div>
<div class="card"><h2>Табличка</h2>
 <label>Текст</label><textarea id="stext" maxlength="300" placeholder="Что написать на табличке?"></textarea>
 <div class="row"><div><label>Сколько секунд показывать</label><input id="ssec" type="number" min="3" max="300" value="10"></div>
 <div><label>Вид</label><select id="sstyle"><option value="note">Жёлтая записка</option><option value="alert">Красная (важно)</option><option value="plain">Белая</option></select></div></div>
 <div class="row" style="margin-top:10px"><button id="sendSign">Показать табличку</button><button class="sec" data-c="clearsign">Убрать все таблички</button></div></div>
<div class="card"><h2>Журнал</h2><div id="log"></div></div>
</main>
<script>
const $=id=>document.getElementById(id), L=$('log');
$('room').value=localStorage.getItem('bb_room')||''; $('tok').value=localStorage.getItem('bb_tok')||'';
function log(s){L.textContent=new Date().toLocaleTimeString()+'  '+s+'\\n'+L.textContent}
function save(){localStorage.setItem('bb_room',$('room').value.trim());localStorage.setItem('bb_tok',$('tok').value)}
async function send(cmd,a1,a2,a3){
  save();
  try{
    const r=await fetch('/api/send',{method:'POST',headers:{'content-type':'application/json','x-admin':$('tok').value},
      body:JSON.stringify({room:$('room').value.trim(),cmd,a1,a2,a3})});
    const j=await r.json();
    log(j.ok?('✓ '+cmd+' (онлайн: '+j.online+')'):('✗ '+(j.error||r.status)));
    refresh();
  }catch(e){log('✗ нет связи с сервером')}
}
document.querySelectorAll('button[data-c]').forEach(b=>b.onclick=()=>send(b.dataset.c,b.dataset.a1));
$('sendSign').onclick=()=>{const t=$('stext').value.trim();if(!t){log('✗ напиши текст');return}send('sign',t,$('ssec').value,$('sstyle').value)};
async function refresh(){
  const room=$('room').value.trim(), st=$('st');
  if(!room||!$('tok').value){st.textContent='введи ключ комнаты и пароль';st.className='';return}
  try{
    const r=await fetch('/api/status?room='+encodeURIComponent(room),{headers:{'x-admin':$('tok').value}});
    const j=await r.json();
    if(j.ok){st.textContent='Программ онлайн: '+j.online;st.className=j.online?'ok':''}
    else{st.textContent=j.error||'ошибка';st.className='bad'}
  }catch(e){st.textContent='нет связи';st.className='bad'}
}
$('room').oninput=$('tok').oninput=()=>{save();refresh()};
refresh(); setInterval(refresh,5000);
</script></body></html>`;
