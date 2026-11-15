'use strict';
// Hiyoka Agent - jalan di VPS (pm2: hiyoka-agent). Connect KELUAR ke bot Hiyoka (Pterodactyl) lewat
// WebSocket terenkripsi, lalu mengerjakan perintah dari bot: file manager, pm2 restart, cek API, backup.
// Semua pengaturan ada di agent.conf. Tidak ada port yang dibuka di VPS.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFile } = require('child_process');
const WebSocket = require('ws');
const { masterKey, randomNonce, sessionKeys, Channel } = require('./proto');

const VERSION = '1.0.0';
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
const LOCAL = String(conf.KURO_API || 'http://127.0.0.1:3000').replace(/\/$/, '');
const API_PM2 = conf.KURO_PM2 || 'kuronime-api';
const BACKUP_SCRIPT = conf.BACKUP_SCRIPT || 'backup.sh';
const BACKUP_TIMEOUT = (Number(conf.BACKUP_TIMEOUT_MIN) || 10) * 60 * 1000;
const MAX_UNZIPPED = (Number(conf.MAX_UNZIPPED_MB) || 200) * MB;
const MAX_ENTRIES = Number(conf.MAX_ZIP_ENTRIES) || 5000;
const HARD_CAP = 100 * MB;

if (!HOST || !PORT) { console.error('HIYOKA_HOST / HIYOKA_PORT belum diisi di agent.conf'); process.exit(1); }
if (SECRET.length < 16) { console.error('HIYOKA_SECRET di agent.conf minimal 16 karakter'); process.exit(1); }
if (process.argv.includes('--check')) {
  console.log(`OK konfigurasi: bot ws://${HOST}:${PORT} | root ${ROOT} | kuronime ${KURO_DIR} | pm2 ${API_PM2}`);
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

// file rahasia: agent.conf (berisi secret) dan .env kuronime-api. Tidak boleh didownload / ditimpa / dihapus lewat bot
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

// ---------- .env kuronime-api (hanya API_KEY) ----------
const ENV_NAMES = new Set(['API_KEY']);
function readEnv(name) {
  try {
    const hit = fs.readFileSync(ENV_PATH, 'utf8').split(/\r?\n/).filter((l) => l.startsWith(name + '=')).pop();
    return hit ? hit.slice(name.length + 1).trim().replace(/^(['"])(.*)\1$/, '$2') : '';
  } catch (_) {
    return '';
  }
}
function writeEnv(name, value) {
  let lines = [];
  try { lines = fs.readFileSync(ENV_PATH, 'utf8').split(/\r?\n/); } catch (_) {}
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  const out = [];
  let done = false;
  for (const l of lines) {
    if (l.startsWith(name + '=')) {
      if (!done) out.push(`${name}=${value}`);
      done = true;
    } else out.push(l);
  }
  if (!done) out.push(`${name}=${value}`);
  const tmp = ENV_PATH + '.tmp';
  fs.writeFileSync(tmp, out.join('\n') + '\n', { mode: 0o600 });
  fs.renameSync(tmp, ENV_PATH);
  fs.chmodSync(ENV_PATH, 0o600);
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

async function unzipInto(zipPath, absDir, force) {
  const names = (await runCmd('unzip', ['-Z1', zipPath])).out.split('\n').filter(Boolean);
  if (!names.length) throw new RpcError('Zip kosong atau tidak bisa dibaca (zip berpassword tidak didukung).');
  if (names.length > MAX_ENTRIES) throw new RpcError(`Isi zip terlalu banyak (maks ${MAX_ENTRIES} entri).`);

  const long = await runCmd('unzip', ['-Z', zipPath]);
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
  if (overList.length && !force) throw new RpcError('conflict', { conflict: { kind: 'zip', over: overList.length, sample: overList.slice(0, 10) } });
  if (force) for (const n of overList) { try { if (fs.lstatSync(path.join(absDir, n)).isFile()) fs.unlinkSync(path.join(absDir, n)); } catch (_) {} }
  const x = await runCmd('unzip', ['-o', '-q', zipPath, '-d', absDir]);
  if (x.code !== 0) throw new RpcError(`unzip gagal: ${stripAnsi(x.out).trim().split('\n').slice(-2).join(' ')}`);
  return { files: files.length, over: overList.length, names: files.slice(0, 12) };
}

// ---------- ekstrak arsip: zip, tar(.gz/.bz2/.xz/.zst), gz/bz2/xz/zst tunggal, 7z, rar ----------
const ARCH_RE = /\.(zip|cbz|jar|apk|tar|tar\.(?:gz|bz2|xz|zst)|tgz|tbz2?|txz|tzst|gz|bz2|xz|zst|7z|rar)$/i;
function archiveKind(name) {
  const n = String(name).toLowerCase();
  if (/\.(zip|cbz|jar|apk)$/.test(n)) return 'zip';
  if (/\.(tar|tar\.(gz|bz2|xz|zst)|tgz|tbz2?|txz|tzst)$/.test(n)) return 'tar';
  if (/\.(gz|bz2|xz|zst)$/.test(n)) return 'single';
  if (/\.(7z|rar)$/.test(n)) return 'seven';
  return null;
}
const PKG = { tar: 'tar', gzip: 'gzip', bzip2: 'bzip2', xz: 'xz-utils', zstd: 'zstd', unzip: 'unzip' };
// jalankan perintah, stdout dan stderr dipisah, buffer besar (daftar isi arsip bisa panjang)
function runBig(cmd, args, timeoutMs = 120000, opt = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 64 * MB, timeout: timeoutMs, env: { ...process.env, LC_ALL: 'C' }, ...opt }, (err, stdout, stderr) => {
      if (err && err.code === 'ENOENT') return reject(new RpcError(`${cmd} tidak terpasang di VPS (apt install ${PKG[cmd] || cmd} -y)`));
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, out: String(stdout), err: String(stderr) });
    });
  });
}
// nama entri arsip: tolak path berbahaya / tersembunyi / terlarang (aturan sama dengan zip)
function checkEntryName(n) {
  const parts = n.split('/').filter(Boolean);
  if (n.startsWith('/') || /^[A-Za-z]:/.test(n) || n.includes('\\') || parts.includes('..')) throw new RpcError(`Arsip ditolak, path berbahaya: ${n}`);
  if (parts.some((p) => p === 'node_modules' || p === '.git') || isProtectedName(parts[parts.length - 1] || '')) throw new RpcError(`Arsip ditolak, berisi file terlarang (.env / node_modules / .git): ${n}`);
  if (parts.some((p) => isHiddenBlocked(p))) throw new RpcError(`Arsip ditolak, berisi file/folder tersembunyi (.ssh, .bashrc, dst): ${n}`);
}
// cek konflik + hapus file lama kalau force; mengembalikan daftar file yang ditimpa
function resolveOverwrites(absDir, files, force) {
  const overList = files.filter((n) => fs.existsSync(path.join(absDir, n)));
  if (overList.length && !force) throw new RpcError('conflict', { conflict: { kind: 'zip', over: overList.length, sample: overList.slice(0, 10) } });
  if (force) for (const n of overList) { try { if (fs.lstatSync(path.join(absDir, n)).isFile()) fs.unlinkSync(path.join(absDir, n)); } catch (_) {} }
  return overList;
}

async function tarInto(arc, absDir, force) {
  const lst = await runBig('tar', ['-tf', arc, '--quoting-style=literal']);
  if (lst.code !== 0) throw new RpcError(`Arsip tidak bisa dibaca: ${lst.err.trim().split('\n').slice(-1)[0] || 'format tidak dikenal'}`);
  const raw = lst.out.split('\n').filter(Boolean);
  const vl = (await runBig('tar', ['-tvf', arc, '--quoting-style=literal'])).out.split('\n').filter(Boolean);
  if (vl.length !== raw.length) throw new RpcError('Arsip tidak bisa dibaca (nama entri tidak biasa).');
  const ents = raw.map((n, i) => ({ n: n.replace(/^(\.\/)+/, ''), line: vl[i] })).filter((e) => e.n && e.n !== '.');
  if (!ents.length) throw new RpcError('Arsip kosong.');
  if (ents.length > MAX_ENTRIES) throw new RpcError(`Isi arsip terlalu banyak (maks ${MAX_ENTRIES} entri).`);
  let total = 0;
  for (const e of ents) {
    const t = e.line[0];
    if (t !== '-' && t !== 'd') throw new RpcError('Arsip berisi symlink/hardlink/file khusus, ditolak.');
    if (t === '-') total += Number(e.line.trim().split(/\s+/)[2]) || 0;
  }
  if (total > MAX_UNZIPPED) throw new RpcError(`Isi arsip terlalu besar setelah diekstrak (maks ${Math.round(MAX_UNZIPPED / MB)} MB).`);
  ents.forEach((e) => checkEntryName(e.n));
  const files = ents.filter((e) => e.line[0] === '-').map((e) => e.n);
  for (const n of files) if (isSecretFile(path.join(absDir, n))) throw new RpcError(`Arsip ditolak, akan menimpa file konfigurasi: ${n}`);
  const overList = resolveOverwrites(absDir, files, force);
  const x = await runBig('tar', ['-xf', arc, '-C', absDir, '--no-same-owner', '--no-same-permissions'], 280000);
  if (x.code !== 0) throw new RpcError(`tar gagal: ${x.err.trim().split('\n').slice(-2).join(' ')}`);
  return { files: files.length, over: overList.length, names: files.slice(0, 12) };
}

// .gz/.bz2/.xz/.zst tunggal -> satu file (nama tanpa ekstensi kompresi), dibatasi MAX_UNZIPPED
async function singleInto(arc, absDir, force) {
  const base = path.basename(arc);
  const m = /\.(gz|bz2|xz|zst)$/i.exec(base);
  const tool = { gz: ['gzip', ['-dc']], bz2: ['bzip2', ['-dc']], xz: ['xz', ['-dc']], zst: ['zstd', ['-dc', '-q']] }[m[1].toLowerCase()];
  const out = safeName(base.slice(0, -m[0].length)).replace(/^\.+/, '') || 'hasil';
  checkEntryName(out);
  const dest = path.join(absDir, out);
  if (isSecretFile(dest)) throw new RpcError('Tujuan adalah file konfigurasi, tidak diperbolehkan.');
  let existed = false;
  try {
    const st = fs.lstatSync(dest);
    if (!st.isFile()) throw new RpcError('Tujuan berupa folder/symlink, ditolak.');
    existed = true;
  } catch (e) {
    if (e instanceof RpcError) throw e;
    if (e.code !== 'ENOENT') throw new RpcError(e.message);
  }
  if (existed && !force) throw new RpcError('conflict', { conflict: { kind: 'zip', over: 1, sample: [out] } });
  const tmp = path.join(absDir, `.part-${Date.now()}.tmp`);
  await new Promise((resolve, reject) => {
    const c = spawn(tool[0], [...tool[1], arc], { stdio: ['ignore', 'pipe', 'pipe'] });
    const w = fs.createWriteStream(tmp);
    let n = 0, err = '', over = false, closed = false, finished = false, code = 0;
    const done = () => {
      if (!(closed && finished) && !over) return;
      if (over) return reject(new RpcError(`Hasil ekstrak terlalu besar (maks ${Math.round(MAX_UNZIPPED / MB)} MB).`));
      if (code !== 0) return reject(new RpcError(`Ekstrak gagal: ${err.trim().split('\n').slice(-1)[0] || `kode ${code}`}`));
      resolve();
    };
    c.stderr.on('data', (d) => { err = (err + d).slice(-1000); });
    c.stdout.on('data', (d) => { n += d.length; if (n > MAX_UNZIPPED && !over) { over = true; c.kill('SIGKILL'); w.destroy(); done(); } });
    c.stdout.pipe(w);
    w.on('finish', () => { finished = true; done(); });
    c.on('error', (e) => reject(new RpcError(e.code === 'ENOENT' ? `${tool[0]} tidak terpasang di VPS (apt install ${PKG[tool[0]] || tool[0]} -y)` : e.message)));
    c.on('close', (cd) => { closed = true; code = cd; done(); });
  }).catch((e) => { try { fs.rmSync(tmp, { force: true }); } catch (_) {} throw e; });
  if (existed) fs.unlinkSync(dest);
  fs.renameSync(tmp, dest);
  return { files: 1, over: existed ? 1 : 0, names: [out] };
}

// .7z / .rar: ekstrak dulu ke folder sementara, periksa hasilnya (symlink, nama, ukuran), baru dipindah ke tujuan
async function sevenInto(arc, absDir, force) {
  let bin = null;
  for (const b of ['7z', '7zz', '7za', '7zr']) {
    const r = await runBig(b, ['i'], 15000).catch(() => null);
    if (r) { bin = b; break; }
  }
  if (!bin) throw new RpcError('7z tidak terpasang di VPS (apt install p7zip-full -y). Untuk .rar pakai paket p7zip-rar atau 7zip terbaru.');
  const stage = path.join(absDir, `.extract-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  fs.mkdirSync(stage);
  const cleanup = () => { try { fs.rmSync(stage, { recursive: true, force: true }); } catch (_) {} };
  try {
    const x = await runBig(bin, ['x', '-y', '-bd', `-o${stage}`, arc], 280000);
    if (x.code !== 0) throw new RpcError(`Ekstrak gagal: ${(x.err || x.out).trim().split('\n').slice(-2).join(' ') || `kode ${x.code}`}`);
    const files = [];
    const dirs = [];
    let total = 0, count = 0;
    const walk = (d, rel) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (++count > MAX_ENTRIES) throw new RpcError(`Isi arsip terlalu banyak (maks ${MAX_ENTRIES} entri).`);
        if (e.isSymbolicLink()) throw new RpcError('Arsip berisi symlink, ditolak.');
        if (e.isDirectory()) { checkEntryName(r); dirs.push(r); walk(path.join(d, e.name), r); }
        else if (e.isFile()) { checkEntryName(r); total += fs.statSync(path.join(d, e.name)).size; files.push(r); }
        else throw new RpcError('Arsip berisi file khusus, ditolak.');
      }
    };
    walk(stage, '');
    if (!files.length && !dirs.length) throw new RpcError('Arsip kosong.');
    if (total > MAX_UNZIPPED) throw new RpcError(`Isi arsip terlalu besar setelah diekstrak (maks ${Math.round(MAX_UNZIPPED / MB)} MB).`);
    for (const n of files) if (isSecretFile(path.join(absDir, n))) throw new RpcError(`Arsip ditolak, akan menimpa file konfigurasi: ${n}`);
    const overList = resolveOverwrites(absDir, files, force);
    for (const d of dirs) fs.mkdirSync(path.join(absDir, d), { recursive: true });
    for (const n of files) { fs.mkdirSync(path.dirname(path.join(absDir, n)), { recursive: true }); fs.renameSync(path.join(stage, n), path.join(absDir, n)); }
    return { files: files.length, over: overList.length, names: files.slice(0, 12) };
  } finally {
    cleanup();
  }
}

async function extractArchive(arc, absDir, force) {
  const kind = archiveKind(arc);
  if (kind === 'zip') return unzipInto(arc, absDir, force);
  if (kind === 'tar') return tarInto(arc, absDir, force);
  if (kind === 'single') return singleInto(arc, absDir, force);
  if (kind === 'seven') return sevenInto(arc, absDir, force);
  throw new RpcError('Format arsip tidak didukung (zip, tar, tar.gz, tgz, tar.bz2, tar.xz, tar.zst, gz, bz2, xz, zst, 7z, rar).');
}

async function opUnzip(a, buf) {
  if (!buf || !buf.length) throw new RpcError('Arsip kosong.');
  const absDir = rel2abs(a.rel);
  mustInside(absDir);
  const em = ARCH_RE.exec(String(a.name || 'x.zip'));
  const tmpZip = path.join(os.tmpdir(), `hiyoka-agent-${Date.now()}-${Math.random().toString(36).slice(2)}${em ? em[0].toLowerCase() : '.zip'}`);
  try {
    fs.writeFileSync(tmpZip, buf);
    return await extractArchive(tmpZip, absDir, a.force);
  } finally {
    try { fs.rmSync(tmpZip, { force: true }); } catch (_) {}
  }
}

// ekstrak file arsip yang sudah ada di VPS. a.mode: 'here' (di folder zip) atau 'folder' (ke folder bernama sama dengan zip)
async function opUnzipFile(a) {
  const zipAbs = rel2abs(a.rel);
  let st;
  try { st = fs.lstatSync(zipAbs); } catch (_) { throw new RpcError('File sudah tidak ada.'); }
  mustInside(zipAbs);
  if (!st.isFile()) throw new RpcError('Bukan file.');
  if (!archiveKind(zipAbs)) throw new RpcError('Format arsip tidak didukung (zip, tar, tar.gz, tgz, tar.bz2, tar.xz, tar.zst, gz, bz2, xz, zst, 7z, rar).');
  const parentAbs = path.dirname(zipAbs);
  let absDir = parentAbs;
  let created = false;
  if (a.mode === 'folder') {
    const base = safeName(path.basename(zipAbs).replace(ARCH_RE, '')).replace(/^\.+/, '') || 'hasil';
    absDir = path.join(parentAbs, base);
    try {
      const d = fs.lstatSync(absDir);
      if (!d.isDirectory()) throw new RpcError(`"${base}" sudah ada dan bukan folder.`);
    } catch (e) {
      if (e instanceof RpcError) throw e;
      if (e.code !== 'ENOENT') throw new RpcError(e.message);
      fs.mkdirSync(absDir);
      created = true;
    }
  }
  try {
    const r = await extractArchive(zipAbs, absDir, !!a.force);
    return { ...r, folder: path.basename(absDir), mode: a.mode === 'folder' ? 'folder' : 'here' };
  } catch (e) {
    if (created) { try { fs.rmdirSync(absDir); } catch (_) {} }
    throw e;
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

// ---------- pm2: daftar proses + restart per proses (id harus ada di daftar pm2, bukan input bebas) ----------
function pm2Procs() {
  return new Promise((resolve, reject) => {
    execFile('pm2', ['jlist'], { maxBuffer: 20 * MB, timeout: 30000 }, (err, stdout) => {
      if (err && !stdout) return reject(new RpcError(err.code === 'ENOENT' ? 'pm2 tidak terpasang di VPS.' : `pm2 gagal: ${err.message}`));
      const line = String(stdout).split('\n').reverse().find((l) => l.startsWith('[{') || l.trim() === '[]');
      let arr;
      try { arr = JSON.parse(line || stdout); } catch (_) { return reject(new RpcError('Output pm2 tidak bisa dibaca.')); }
      resolve(arr.map((p) => ({
        id: p.pm_id,
        name: String(p.name || ''),
        status: (p.pm2_env && p.pm2_env.status) || '?',
        since: (p.pm2_env && p.pm2_env.pm_uptime) || 0,
        restarts: (p.pm2_env && p.pm2_env.restart_time) || 0,
        mem: (p.monit && p.monit.memory) || 0,
        self: String(p.pm_id) === String(process.env.pm_id) || p.name === 'hiyoka-agent',
      })));
    });
  });
}
async function opPm2List() {
  return { procs: (await pm2Procs()).slice(0, 30), now: Date.now() };
}
async function opPm2Proc(a) {
  const procs = await pm2Procs();
  const p = procs.find((x) => x.id === Number(a.id));
  if (!p) throw new RpcError('Proses pm2 tidak ditemukan (daftar sudah berubah).');
  if (p.self) {
    // restart diri sendiri: balas dulu, restart sebentar lagi (koneksi akan putus lalu sambung otomatis)
    setTimeout(() => { try { spawn('pm2', ['restart', String(p.id)], { detached: true, stdio: 'ignore' }).unref(); } catch (_) {} }, 800);
    return { ok: true, self: true, name: p.name };
  }
  const r = await runCmd('pm2', ['restart', String(p.id)], 60000);
  return { ok: r.code === 0, self: false, name: p.name, msg: stripAnsi(r.out).trim().split('\n').slice(-3).join('\n') };
}

// buat zip dari item terpilih (a.rels, semua di folder a.dir). Hasil disimpan di a.dir, tidak menimpa apa pun.
// File tersembunyi (.env, .ssh, dst), .git, node_modules tidak ikut; symlink disimpan sebagai link (tidak diikuti).
async function opZip(a) {
  const rels = Array.isArray(a.rels) ? a.rels : [];
  if (!rels.length) throw new RpcError('Belum ada item dipilih.');
  if (rels.length > 300) throw new RpcError('Terlalu banyak item dipilih (maks 300).');
  const absDir = rel2abs(a.dir);
  mustInside(absDir);
  let dst;
  try { dst = fs.lstatSync(absDir); } catch (_) { throw new RpcError('Folder tidak ada.'); }
  if (!dst.isDirectory()) throw new RpcError('Tujuan bukan folder.');
  const names = [];
  for (const rel of rels) {
    if (typeof rel !== 'string' || rel === '.') throw new RpcError('Item tidak valid.');
    const why = protectedReason(rel);
    if (why) throw new RpcError(why.replace('dihapus/di-rename', 'di-zip'));
    const abs = rel2abs(rel);
    if (path.dirname(abs) !== absDir) throw new RpcError('Semua item harus berada di folder yang sama.');
    let st;
    try { st = fs.lstatSync(abs); } catch (_) { throw new RpcError(`${path.basename(abs)} sudah tidak ada.`); }
    if (!st.isFile() && !st.isDirectory()) throw new RpcError(`${path.basename(abs)} bukan file/folder biasa.`);
    names.push(path.basename(abs));
  }
  let base = String(a.name || '').trim().replace(/\.zip$/i, '');
  if (!base) {
    const d = new Date(Date.now() + 7 * 3600 * 1000).toISOString().replace(/[-:T]/g, '').slice(0, 14);
    base = names.length === 1 ? names[0] : `arsip_${d.slice(0, 8)}_${d.slice(8)}`;
  }
  base = safeName(base).replace(/^\.+/, '').slice(0, 90) || 'arsip';
  let name = `${base}.zip`;
  for (let i = 1; fs.existsSync(path.join(absDir, name)) && i < 1000; i++) name = `${base}_${i}.zip`;
  const tmp = path.join(absDir, `.part-${Date.now()}.zip`);
  const x = await runCmd('zip', ['-r', '-y', '-q', tmp, ...names.map((n) => `./${n}`), '-x', '*/.*', '*/node_modules/*', '*/.git/*'], 280000, { cwd: absDir });
  if (x.code !== 0) {
    try { fs.rmSync(tmp, { force: true }); } catch (_) {}
    throw new RpcError(`zip gagal: ${stripAnsi(x.out).trim().split('\n').slice(-2).join(' ') || `kode ${x.code}`}`);
  }
  const final = path.join(absDir, name);
  fs.renameSync(tmp, final);
  return { name, size: fs.statSync(final).size, count: names.length };
}

// salin file/folder ke folder lain (boleh ke folder yang sama). Tidak pernah menimpa: kalau nama sudah ada jadi nama_salinan, nama_salinan2, dst.
async function opCopy(a) {
  const why = protectedReason(a.rel);
  if (why) throw new RpcError(why.replace('dihapus/di-rename', 'disalin'));
  const from = rel2abs(a.rel);
  const destDir = rel2abs(a.dest);
  mustInside(destDir);
  let dst;
  try { dst = fs.lstatSync(destDir); } catch (_) { throw new RpcError('Folder tujuan tidak ada.'); }
  if (!dst.isDirectory()) throw new RpcError('Tujuan bukan folder.');
  let srcSt;
  try { srcSt = fs.lstatSync(from); } catch (_) { throw new RpcError('Item sudah tidak ada.'); }
  if (!srcSt.isFile() && !srcSt.isDirectory()) throw new RpcError('Hanya file/folder biasa yang bisa disalin.');
  const fromReal = fs.realpathSync(from);
  const destReal = fs.realpathSync(destDir);
  if (srcSt.isDirectory() && (destReal === fromReal || destReal.startsWith(fromReal + path.sep))) throw new RpcError('Folder tidak bisa disalin ke dalam dirinya sendiri.');
  const orig = path.basename(from);
  const m = srcSt.isFile() ? /(\.tar\.(?:gz|bz2|xz)|\.[A-Za-z0-9]{1,8})$/i.exec(orig) : null;
  const ext = m && m.index > 0 ? m[1] : '';
  const stem = ext ? orig.slice(0, -ext.length) : orig;
  let name = orig;
  for (let i = 1; fs.existsSync(path.join(destDir, name)) || isSecretFile(path.join(destDir, name)); i++) {
    if (i > 999) throw new RpcError('Terlalu banyak salinan dengan nama sama.');
    name = `${stem}_salinan${i > 1 ? i : ''}${ext}`;
  }
  try {
    await fs.promises.cp(from, path.join(destDir, name), { recursive: true, errorOnExist: true, force: false, verbatimSymlinks: true });
  } catch (e) {
    throw new RpcError(`Gagal menyalin (${e.code || e.message}).`);
  }
  return { name, renamed: name !== orig };
}

// pindah file/folder ke folder lain (a.rel = sumber, a.dest = folder tujuan). Tidak menimpa apa pun.
async function opMove(a) {
  const why = protectedReason(a.rel);
  if (why) throw new RpcError(why.replace('dihapus/di-rename', 'dipindah'));
  const from = rel2abs(a.rel);
  const destDir = rel2abs(a.dest);
  mustInside(destDir);
  let dst;
  try { dst = fs.lstatSync(destDir); } catch (_) { throw new RpcError('Folder tujuan tidak ada.'); }
  if (!dst.isDirectory()) throw new RpcError('Tujuan bukan folder.');
  const name = path.basename(from);
  if (path.dirname(from) === destDir) throw new RpcError('Item sudah berada di folder itu.');
  const fromReal = fs.realpathSync(from);
  const destReal = fs.realpathSync(destDir);
  if (destReal === fromReal || destReal.startsWith(fromReal + path.sep)) throw new RpcError('Folder tidak bisa dipindah ke dalam dirinya sendiri.');
  const to = path.join(destDir, name);
  if (isSecretFile(to)) throw new RpcError('Tujuan adalah file konfigurasi, tidak diperbolehkan.');
  try {
    fs.lstatSync(to);
    throw new RpcError(`"${name}" sudah ada di folder tujuan.`);
  } catch (e) {
    if (e instanceof RpcError) throw e;
    if (e.code !== 'ENOENT') throw new RpcError(e.message);
  }
  try {
    fs.renameSync(from, to);
  } catch (e) {
    if (e.code !== 'EXDEV') throw new RpcError(`Gagal memindah (${e.code || e.message}).`);
    // beda filesystem: salin lalu hapus sumber
    await fs.promises.cp(from, to, { recursive: true, errorOnExist: true, force: false, verbatimSymlinks: true });
    await fs.promises.rm(from, { recursive: true });
  }
  return { name };
}

// ---------- operasi API / pm2 / backup / sistem ----------
async function opHttp(a) {
  const p = String(a.path || '');
  if (!p.startsWith('/') || p.startsWith('//') || /[\s\0]/.test(p)) throw new RpcError('Path API tidak valid.');
  const headers = {};
  if (a.auth === 'env') {
    const k = readEnv('API_KEY');
    if (k) headers['x-api-key'] = k;
  } else if (a.auth === 'key' && typeof a.key === 'string' && a.key) headers['x-api-key'] = a.key;
  const timeout = Math.min(Math.max(Number(a.timeoutMs) || 10000, 1000), 120000);
  const t0 = Date.now();
  try {
    const res = await fetch(LOCAL + p, { headers, signal: AbortSignal.timeout(timeout) });
    const body = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, body, ms: Date.now() - t0 };
  } catch (e) {
    throw new RpcError(e.name === 'TimeoutError' ? 'timeout API' : e.message, { code: e.name === 'TimeoutError' ? 'TIMEOUT' : undefined });
  }
}

const PROBE_UA = 'Mozilla/5.0 (Linux; Android 13; SM-A135F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36';
async function opProbe(a) {
  if (!/^https?:\/\//i.test(String(a.url || ''))) throw new RpcError('URL tidak valid.');
  const timeoutMs = Math.min(Math.max(Number(a.timeoutMs) || 8000, 1000), 30000);
  const t0 = Date.now();
  try {
    const res = await fetch(a.url, {
      headers: { 'User-Agent': PROBE_UA, Range: 'bytes=0-1', ...(a.headers && typeof a.headers === 'object' ? a.headers : {}) },
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const ms = Date.now() - t0;
    try { await res.body?.cancel(); } catch (_) {}
    const html = /text\/html/i.test(res.headers.get('content-type') || '');
    const good = (res.status === 200 || res.status === 206) && !html;
    return { ok: good, status: res.status, ms, note: html ? 'respon HTML, bukan video' : '' };
  } catch (e) {
    return { ok: false, status: 0, ms: Date.now() - t0, note: e.name === 'TimeoutError' ? 'timeout' : e.message };
  }
}

async function opPm2Restart(a) {
  if (a.target !== 'api') throw new RpcError('Target restart tidak dikenal.');
  const r = await runCmd('pm2', ['restart', API_PM2], 60000);
  return { ok: r.code === 0, msg: stripAnsi(r.out).trim().split('\n').slice(-3).join('\n') };
}

let backupRunning = false;
async function opBackup(a) {
  if (backupRunning) throw new RpcError('Backup sebelumnya masih berjalan.');
  const pass = String(a.pass || '');
  if (pass.length > 128) throw new RpcError('Password terlalu panjang.');
  backupRunning = true;
  try {
    const env = { ...process.env, BACKUP_PASS: pass }; // BACKUP_PASS kosong = tanpa password
    const r = await runCmd('bash', [BACKUP_SCRIPT, 'auto'], BACKUP_TIMEOUT, { cwd: KURO_DIR, env });
    return { code: r.code, out: stripAnsi(r.out).trim().split('\n').slice(-8).join('\n').slice(-800) };
  } finally {
    backupRunning = false;
  }
}

function opEnvGet(a) {
  if (!ENV_NAMES.has(a.name)) throw new RpcError('Variabel tidak diizinkan.');
  return { value: readEnv(a.name) };
}
function opEnvSet(a) {
  if (!ENV_NAMES.has(a.name)) throw new RpcError('Variabel tidak diizinkan.');
  const v = String(a.value == null ? '' : a.value);
  if (!/^[A-Za-z0-9_.~-]{0,64}$/.test(v)) throw new RpcError('Nilai tidak valid.');
  writeEnv(a.name, v);
  return {};
}

const opSys = () => ({
  load: os.loadavg()[0],
  cpus: os.cpus().length,
  mem: Math.round((1 - os.freemem() / os.totalmem()) * 100),
  host: os.hostname(),
  up: os.uptime(),
});

const OPS = {
  sys: opSys,
  'env.get': opEnvGet,
  'env.set': opEnvSet,
  http: opHttp,
  probe: opProbe,
  'pm2.restart': opPm2Restart,
  'backup.run': opBackup,
  'fs.list': opList,
  'fs.stat': opStat,
  'fs.protected': (a) => ({ why: protectedReason(a.rel) }),
  'fs.read': opRead,
  'fs.write': opWrite,
  'fs.unzip': opUnzip,
  'fs.rm': opRm,
  'fs.rename': opRename,
  'fs.move': opMove,
  'fs.copy': opCopy,
  'fs.unzipfile': opUnzipFile,
  'fs.zip': opZip,
  'pm2.list': opPm2List,
  'pm2.proc': opPm2Proc,
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
        sock.send(ch.seal({ t: 'ready', info: { host: os.hostname(), root: ROOT, ver: VERSION, node: process.version, kuro: KURO_DIR, pm2: API_PM2 } }));
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

log(`Hiyoka Agent v${VERSION} | root ${ROOT} | kuronime ${KURO_DIR}`);
connect();
