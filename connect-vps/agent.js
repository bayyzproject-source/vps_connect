'use strict';
// Hiyoka Agent - jalan di VPS (pm2: hiyoka-agent). Connect KELUAR ke bot Hiyoka (Pterodactyl) lewat
// WebSocket terenkripsi, lalu mengerjakan perintah dari bot: file manager dan uninstall agent (/disconnect).
// Semua pengaturan ada di agent.conf. Tidak ada port yang dibuka di VPS.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const { masterKey, randomNonce, sessionKeys, Channel } = require('./proto');

const VERSION = '1.1.0';
const AGENT_DIR = __dirname;
const MB = 1024 * 1024;
const log = (...a) => console.log(new Date().toISOString().replace('T', ' ').slice(0, 19), '[agent]', ...a);

// ---------- konfigurasi (agent.conf: KEY=VALUE) ----------
function loadConf() {
  const out = {};
  let raw = '';
  try { raw = fs.readFileSync(path.join(AGENT_DIR, 'agent.conf'), 'utf8'); } catch (_) { throw new Error('agent.conf tidak ditemukan'); }
  for (const line of raw.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue;
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m) out[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
  return out;
}

const conf = loadConf();
const HOST = conf.HIYOKA_HOST || '';
const PORT = Number(conf.HIYOKA_PORT || 0);
const SECRET = conf.HIYOKA_SECRET || '';
const ROOT = path.resolve(conf.UPLOAD_ROOT || '/root');
const KURO_DIR = path.resolve(conf.KURO_DIR || '/root/kuronime-api');
const ENV_PATH = path.join(KURO_DIR, '.env');
const MAX_UNZIPPED = (Number(conf.MAX_UNZIPPED_MB) || 200) * MB;
const MAX_ENTRIES = Number(conf.MAX_ZIP_ENTRIES) || 5000;
const HARD_CAP = 100 * MB;

if (!HOST || !PORT) { console.error('HIYOKA_HOST / HIYOKA_PORT belum diisi di agent.conf'); process.exit(1); }
if (SECRET.length < 16) { console.error('HIYOKA_SECRET di agent.conf minimal 16 karakter'); process.exit(1); }
if (process.argv.includes('--check')) {
  console.log(`OK konfigurasi: bot ws://${HOST}:${PORT} | root ${ROOT}`);
  process.exit(0);
}

// ---------- helper & aturan keamanan file ----------
class RpcError extends Error {
  constructor(msg, extra) { super(msg); this.extra = extra || {}; }
}
class Reply { constructor(result, body) { this.result = result; this.body = body; } }

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
const fmtSize = (b) => (b >= 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`);
const SKIP_DIRS = new Set(['node_modules', '.git']);
const ALLOWED_DOT = new Set(['.env.example', '.gitignore', '.gitattributes', '.npmrc', '.dockerignore', '.prettierrc', '.eslintrc', '.editorconfig']);
const isProtectedName = (name) => /^\.env($|\.(?!example$))/i.test(name);
const isHidden = (n) => n.startsWith('.') && !ALLOWED_DOT.has(n.toLowerCase());
const isHiddenBlocked = (name) => isHidden(name) && !isProtectedName(name);

// file rahasia: agent.conf (berisi secret) dan .env di folder KURO_DIR. Tidak boleh didownload / ditimpa / dihapus lewat bot
const SECRET_FILES = [path.join(AGENT_DIR, 'agent.conf'), ENV_PATH];
function isSecretFile(abs) {
  const cands = new Set([path.resolve(abs)]);
  try { cands.add(fs.realpathSync(abs)); } catch (_) {}
  return SECRET_FILES.some((f) => {
    if (cands.has(path.resolve(f))) return true;
    try { return cands.has(fs.realpathSync(f)); } catch (_) { return false; }
  });
}

function insideRoot(abs) {
  try {
    const root = fs.realpathSync(ROOT);
    const real = fs.realpathSync(abs);
    return real === root || real.startsWith(root + path.sep);
  } catch (_) {
    return false;
  }
}

// rel dari bot ('.' atau 'a/b') -> path absolut di bawah ROOT. Tolak '..', path absolut, dan komponen tersembunyi.
function rel2abs(rel) {
  if (typeof rel !== 'string' || rel.includes('\0')) throw new RpcError('Path tidak valid.');
  if (rel === '.' || rel === '') return ROOT;
  const parts = rel.split('/');
  if (rel.startsWith('/') || parts.some((p) => p === '' || p === '.' || p === '..')) throw new RpcError('Path tidak valid.');
  if (parts.some(isHidden)) throw new RpcError('Path tersembunyi tidak diizinkan.');
  return path.join(ROOT, rel);
}
const mustInside = (abs) => { if (!insideRoot(abs)) throw new RpcError(`Di luar ${ROOT}, ditolak.`); };

function safeName(raw) {
  let n = path.basename(String(raw || '').replace(/\\/g, '/')).replace(/[^A-Za-z0-9._ -]/g, '_').trim();
  if (!n || /^\.+$/.test(n)) n = 'upload.bin';
  return n.slice(0, 100);
}

function runCmd(cmd, args, timeoutMs = 60000, opt = {}) {
  return new Promise((resolve) => {
    const c = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opt });
    let out = '';
    const grab = (d) => { out += d; if (out.length > 20000) out = out.slice(-10000); };
    c.stdout.on('data', grab);
    c.stderr.on('data', grab);
    const t = setTimeout(() => c.kill('SIGKILL'), timeoutMs);
    c.on('error', (e) => {
      clearTimeout(t);
      resolve({ code: -1, out: e.code === 'ENOENT' ? `${cmd} tidak terpasang (apt install ${cmd} -y)` : e.message });
    });
    c.on('close', (code) => { clearTimeout(t); resolve({ code, out }); });
  });
}

// ---------- operasi file ----------
function fmCount(abs, cap = 5000) {
  let n = 0;
  const walk = (d) => {
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    for (const e of ents) {
      if (n >= cap) return;
      n++;
      if (e.isDirectory()) walk(path.join(d, e.name));
    }
  };
  walk(abs);
  return n;
}

// '' kalau boleh; kalau tidak, isinya alasan penolakan
function protectedReason(rel) {
  if (rel === '.') return 'Folder root tidak boleh diubah lewat bot.';
  const abs0 = rel2abs(rel);
  try {
    const abs = fs.realpathSync(abs0);
    const guarded = [AGENT_DIR, KURO_DIR].map((d) => { try { return fs.realpathSync(d); } catch (_) { return null; } }).filter(Boolean);
    if (guarded.some((g) => g === abs || g.startsWith(abs + path.sep))) return 'Folder agent / kuronime-api (atau folder induknya) tidak boleh dihapus/di-rename lewat bot.';
    if (isSecretFile(abs)) return 'File konfigurasi (agent.conf / .env) tidak boleh dihapus/di-rename lewat bot.';
    if (!insideRoot(abs)) return `Di luar ${ROOT}, ditolak.`;
  } catch (_) {
    return 'Item sudah tidak ada.';
  }
  return '';
}

function opList(a) {
  const abs = rel2abs(a.rel);
  mustInside(abs);
  let ents;
  try { ents = fs.readdirSync(abs, { withFileTypes: true }); } catch (e) { throw new RpcError(`Folder tidak bisa dibaca (${e.code || e.message}).`); }
  const entries = ents
    .filter((e) => (e.isDirectory() || e.isFile()) && !SKIP_DIRS.has(e.name) && !isHidden(e.name)) // symlink tidak ikut
    .slice(0, 3000)
    .map((e) => {
      let size = 0;
      if (e.isFile()) { try { size = fs.statSync(path.join(abs, e.name)).size; } catch (_) {} }
      return { name: e.name, dir: e.isDirectory(), size };
    })
    .sort((x, y) => (x.dir === y.dir ? x.name.localeCompare(y.name) : x.dir ? -1 : 1));
  return { entries };
}

function opStat(a) {
  const abs = rel2abs(a.rel);
  let st;
  try { st = fs.lstatSync(abs); } catch (_) { return { exists: false }; }
  mustInside(abs);
  const dir = st.isDirectory();
  const r = { exists: true, abs, dir, file: st.isFile(), symlink: st.isSymbolicLink(), size: st.size, mtimeMs: st.mtimeMs, mode: st.mode & 0o777 };
  if (dir) {
    try { r.count = fs.readdirSync(abs).length; } catch (_) { r.count = 0; }
    if (a.deep) r.deep = fmCount(abs);
  }
  return r;
}

function opRead(a) {
  if (!a.rel || a.rel === '.') throw new RpcError('Item tidak valid.');
  const abs = rel2abs(a.rel);
  let st;
  try { st = fs.lstatSync(abs); } catch (_) { throw new RpcError('File sudah tidak ada.'); }
  if (!st.isFile()) throw new RpcError('Hanya file yang bisa didownload (folder tidak).');
  mustInside(abs);
  const base = path.basename(abs);
  if (isProtectedName(base) || isHidden(base) || isSecretFile(abs)) throw new RpcError('File ini tidak boleh didownload lewat bot.');
  if (st.size === 0) throw new RpcError('File kosong (0 byte), Telegram menolak mengirim file kosong.');
  const max = Math.min(Number(a.max) || 50 * MB, HARD_CAP);
  if (st.size > max) throw new RpcError(`File ${fmtSize(st.size)} terlalu besar (maks ${Math.round(max / MB)} MB lewat bot). Pakai SFTP.`);
  return new Reply({ abs, name: base, size: st.size }, fs.readFileSync(abs));
}

function opWrite(a, buf) {
  const name = safeName(a.name);
  if (!buf || !buf.length) throw new RpcError('File kosong.');
  const absDir = rel2abs(a.rel);
  mustInside(absDir);
  if (isProtectedName(name)) throw new RpcError('File .env tidak boleh diupload lewat bot.');
  if (isHiddenBlocked(name)) throw new RpcError(`File tersembunyi (${name}) tidak boleh diupload lewat bot.`);
  const dest = path.join(absDir, name);
  if (path.dirname(dest) !== absDir) throw new RpcError('Nama file tidak valid.');
  if (isSecretFile(dest)) throw new RpcError('File konfigurasi (agent.conf) tidak boleh ditimpa lewat bot.');
  let existed = false;
  try {
    const st = fs.lstatSync(dest);
    if (st.isSymbolicLink() || st.isDirectory()) throw new RpcError('Tujuan berupa symlink/folder, ditolak.');
    existed = true;
  } catch (e) {
    if (e instanceof RpcError) throw e;
    if (e.code !== 'ENOENT') throw e;
  }
  if (existed && !a.force) throw new RpcError('conflict', { conflict: { kind: 'file', name } });
  const tmp = `${dest}.upload-tmp`;
  fs.writeFileSync(tmp, buf); // tulis file baru dulu, supaya kalau gagal file lama tidak hilang
  if (existed) fs.unlinkSync(dest);
  fs.renameSync(tmp, dest);
  return { name, size: buf.length, existed };
}

async function opUnzip(a, buf) {
  if (!buf || !buf.length) throw new RpcError('Zip kosong.');
  const absDir = rel2abs(a.rel);
  mustInside(absDir);
  const tmpZip = path.join(os.tmpdir(), `hiyoka-agent-${Date.now()}-${Math.random().toString(36).slice(2)}.zip`);
  try {
    fs.writeFileSync(tmpZip, buf);
    const names = (await runCmd('unzip', ['-Z1', tmpZip])).out.split('\n').filter(Boolean);
    if (!names.length) throw new RpcError('Zip kosong atau tidak bisa dibaca (zip berpassword tidak didukung).');
    if (names.length > MAX_ENTRIES) throw new RpcError(`Isi zip terlalu banyak (maks ${MAX_ENTRIES} entri).`);

    const long = await runCmd('unzip', ['-Z', tmpZip]);
    if (long.out.split('\n').some((l) => l.startsWith('l'))) throw new RpcError('Zip berisi symlink, ditolak.');
    const tot = /(\d+) files?, (\d+) bytes uncompressed/.exec(long.out);
    if (tot && Number(tot[2]) > MAX_UNZIPPED) throw new RpcError(`Isi zip terlalu besar setelah diekstrak (maks ${Math.round(MAX_UNZIPPED / MB)} MB).`);

    for (const n of names) {
      const parts = n.split('/').filter(Boolean);
      if (n.startsWith('/') || /^[A-Za-z]:/.test(n) || n.includes('\\') || parts.includes('..')) throw new RpcError(`Zip ditolak, path berbahaya: ${n}`);
      if (parts.some((p) => p === 'node_modules' || p === '.git') || isProtectedName(parts[parts.length - 1] || '')) {
        throw new RpcError(`Zip ditolak, berisi file terlarang (.env / node_modules / .git): ${n}`);
      }
      if (parts.some((p) => isHiddenBlocked(p))) throw new RpcError(`Zip ditolak, berisi file/folder tersembunyi (.ssh, .bashrc, dst): ${n}`);
      if (!n.endsWith('/') && isSecretFile(path.join(absDir, n))) throw new RpcError(`Zip ditolak, akan menimpa file konfigurasi: ${n}`);
    }

    const files = names.filter((n) => !n.endsWith('/'));
    const overList = files.filter((n) => fs.existsSync(path.join(absDir, n)));
    if (overList.length && !a.force) throw new RpcError('conflict', { conflict: { kind: 'zip', over: overList.length, sample: overList.slice(0, 10) } });
    if (a.force) for (const n of overList) { try { if (fs.lstatSync(path.join(absDir, n)).isFile()) fs.unlinkSync(path.join(absDir, n)); } catch (_) {} }
    const x = await runCmd('unzip', ['-o', '-q', tmpZip, '-d', absDir]);
    if (x.code !== 0) throw new RpcError(`unzip gagal: ${stripAnsi(x.out).trim().split('\n').slice(-2).join(' ')}`);
    return { files: files.length, over: overList.length, names: files.slice(0, 12) };
  } finally {
    try { fs.rmSync(tmpZip, { force: true }); } catch (_) {}
  }
}

function opRm(a) {
  const why = protectedReason(a.rel);
  if (why) throw new RpcError(why);
  fs.rmSync(rel2abs(a.rel), { recursive: true, force: false });
  return {};
}

function opRename(a) {
  const why = protectedReason(a.rel);
  if (why) throw new RpcError(why);
  const name = String(a.name || '').trim();
  const from = rel2abs(a.rel);
  const old = path.basename(from);
  if (!/^[A-Za-z0-9._ -]{1,100}$/.test(name) || /^\.+$/.test(name)) throw new RpcError('Nama tidak valid (huruf/angka/. _ - dan spasi, maks 100 karakter).');
  if (isHidden(name) || isProtectedName(name)) throw new RpcError('Nama file tersembunyi/.env tidak diperbolehkan.');
  if (name === old) throw new RpcError('Nama sama dengan yang lama.');
  const to = path.join(path.dirname(from), name);
  if (path.dirname(to) !== path.dirname(from)) throw new RpcError('Nama tidak valid.');
  if (isSecretFile(to)) throw new RpcError('Nama tujuan adalah file konfigurasi, tidak diperbolehkan.');
  try {
    fs.lstatSync(to);
    throw new RpcError(`"${name}" sudah ada di folder ini.`);
  } catch (e) {
    if (e instanceof RpcError) throw e;
    if (e.code !== 'ENOENT') throw new RpcError(e.message);
  }
  fs.renameSync(from, to);
  return { name };
}

// ---------- uninstall agent (dipanggil /disconnect dari bot) ----------
function opUninstall() {
  setTimeout(() => {
    stopping = true;
    try { ws && ws.close(); } catch (_) {}
    const c = spawn('bash', ['-c', 'pm2 delete hiyoka-agent >/dev/null 2>&1; pm2 save >/dev/null 2>&1'], { detached: true, stdio: 'ignore' });
    c.unref();
    setTimeout(() => process.exit(0), 3000);
  }, 800);
  return { ok: true };
}

// ---------- sistem ----------
const opSys = () => ({
  load: os.loadavg()[0],
  cpus: os.cpus().length,
  mem: Math.round((1 - os.freemem() / os.totalmem()) * 100),
  host: os.hostname(),
  up: os.uptime(),
});

const OPS = {
  sys: opSys,
  'agent.uninstall': opUninstall,
  'fs.list': opList,
  'fs.stat': opStat,
  'fs.protected': (a) => ({ why: protectedReason(a.rel) }),
  'fs.read': opRead,
  'fs.write': opWrite,
  'fs.unzip': opUnzip,
  'fs.rm': opRm,
  'fs.rename': opRename,
};

// ---------- koneksi ke bot ----------
const MASTER = masterKey(SECRET);
const PING_DEAD_MS = 30000;
let ws = null;
let backoff = 2000;
let stopping = false;

function connect() {
  const url = `ws://${HOST}:${PORT}`;
  const sock = new WebSocket(url, { maxPayload: 160 * MB, handshakeTimeout: 10000 });
  ws = sock;
  const myNonce = randomNonce();
  let st = 'hello';
  let ch = null;
  let lastSeen = Date.now();
  let closed = false;

  const hsTimer = setTimeout(() => { if (st !== 'up') sock.terminate(); }, 12000);
  const dog = setInterval(() => { if (st === 'up' && Date.now() - lastSeen > PING_DEAD_MS) { log('bot tidak merespons, sambung ulang'); sock.terminate(); } }, 5000);

  const reply = (header, body) => {
    if (sock.readyState !== WebSocket.OPEN || !ch) return;
    sock.send(ch.seal(header, body)); // seal + send harus berurutan (counter)
  };

  sock.on('open', () => sock.send(JSON.stringify({ t: 'hello', v: 1, n: myNonce })));

  sock.on('message', (data, isBinary) => {
    try {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (st === 'hello') {
        const m = JSON.parse(buf.toString('utf8'));
        if (isBinary || m.t !== 'welcome' || !/^[0-9a-f]{32}$/.test(m.n)) throw new Error('welcome tidak valid');
        const k = sessionKeys(MASTER, myNonce, m.n);
        ch = new Channel(k.a2b, k.b2a);
        st = 'ack';
        sock.send(ch.seal({ t: 'ready', info: { host: os.hostname(), root: ROOT, ver: VERSION, node: process.version } }));
        return;
      }
      if (!isBinary) throw new Error('frame teks tidak diharapkan');
      const { header, body } = ch.open(buf);
      lastSeen = Date.now();
      if (st === 'ack') {
        if (header.t !== 'ack') throw new Error('ack tidak valid');
        st = 'up';
        clearTimeout(hsTimer);
        backoff = 2000;
        log(`terhubung ke bot ws://${HOST}:${PORT}`);
        return;
      }
      if (header.t === 'ping') return reply({ t: 'pong', ts: header.ts });
      if (header.t === 'req') handleReq(header, body, reply);
    } catch (e) {
      log('protokol error:', e.message);
      sock.terminate();
    }
  });

  sock.on('error', (e) => { if (st !== 'up') log(`gagal connect: ${e.message}`); });
  sock.on('close', () => {
    if (closed) return;
    closed = true;
    clearTimeout(hsTimer);
    clearInterval(dog);
    if (st === 'up') log('koneksi ke bot terputus');
    if (stopping) return;
    setTimeout(connect, backoff);
    backoff = Math.min(Math.round(backoff * 1.5), 15000);
  });
}

async function handleReq(h, body, reply) {
  const id = h.id;
  try {
    const fn = OPS[h.op];
    if (!fn) throw new RpcError(`Perintah tidak dikenal: ${h.op}`);
    const out = await fn(h.args || {}, body);
    if (out instanceof Reply) reply({ t: 'res', id, ok: true, result: out.result }, out.body);
    else reply({ t: 'res', id, ok: true, result: out === undefined ? {} : out });
  } catch (e) {
    const extra = e instanceof RpcError ? e.extra : {};
    if (!(e instanceof RpcError)) log(`op ${h.op} error:`, e.message);
    reply({ t: 'res', id, ok: false, error: e.message, ...extra });
  }
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { stopping = true; try { ws && ws.close(); } catch (_) {} setTimeout(() => process.exit(0), 300); });
}
process.on('unhandledRejection', (e) => log('unhandled:', e && e.message ? e.message : e));

log(`Hiyoka Agent v${VERSION} | root ${ROOT}`);
connect();
