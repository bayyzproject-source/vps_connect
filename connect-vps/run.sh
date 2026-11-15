#!/usr/bin/env bash
# Hiyoka Agent - installer otomatis.
#   bash run.sh            pasang / update, lalu jalan di pm2 (nama: hiyoka-agent)
#   bash run.sh status     lihat status + log terakhir
#   bash run.sh uninstall  hentikan dan hapus dari pm2
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
DIR="$(pwd)"
NAME="hiyoka-agent"
CONF="$DIR/agent.conf"

c_ok()  { printf '\033[32m✔ %s\033[0m\n' "$*"; }
c_err() { printf '\033[31m✘ %s\033[0m\n' "$*" >&2; }
c_inf() { printf '\033[36m➜ %s\033[0m\n' "$*"; }

conf_get() { grep -E "^$1=" "$CONF" | tail -1 | cut -d= -f2- | tr -d '\r' || true; }
conf_set() {
  local k="$1" v="$2"
  if grep -qE "^$k=" "$CONF"; then
    local esc; esc=$(printf '%s' "$v" | sed -e 's/[\/&|]/\\&/g')
    sed -i "s|^$k=.*|$k=$esc|" "$CONF"
  else
    printf '%s=%s\n' "$k" "$v" >> "$CONF"
  fi
}

case "${1:-install}" in
  status)
    pm2 describe "$NAME" >/dev/null 2>&1 || { c_err "$NAME belum terpasang. Jalankan: bash run.sh"; exit 1; }
    pm2 status "$NAME"
    pm2 logs "$NAME" --lines 20 --nostream
    exit 0 ;;
  uninstall)
    pm2 delete "$NAME" >/dev/null 2>&1 && pm2 save >/dev/null 2>&1 || true
    c_ok "$NAME dihapus dari pm2 (folder $DIR tidak dihapus)."
    exit 0 ;;
  install) ;;
  *) c_err "Perintah tidak dikenal: $1 (pakai: install | status | uninstall)"; exit 1 ;;
esac

[ -f "$CONF" ] || { c_err "agent.conf tidak ada di $DIR"; exit 1; }

# 1) Node.js >= 22
if ! command -v node >/dev/null 2>&1; then
  c_err "Node.js belum terpasang. Pasang Node 22+ dulu, lalu jalankan ulang."
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 22 ] || { c_err "Node $(node -v) terlalu lama, butuh 22+."; exit 1; }
command -v npm >/dev/null 2>&1 || { c_err "npm tidak ditemukan."; exit 1; }
c_ok "Node $(node -v)"

# 2) paket pendukung: unzip (untuk upload zip), pm2
if ! command -v unzip >/dev/null 2>&1; then
  c_inf "Memasang unzip..."
  if command -v apt-get >/dev/null 2>&1; then apt-get install -y unzip >/dev/null 2>&1 || c_err "Gagal pasang unzip, pasang manual: apt install unzip -y"
  else c_err "unzip belum ada, pasang manual (fitur upload zip butuh ini)."; fi
fi
if ! command -v pm2 >/dev/null 2>&1; then
  c_inf "Memasang pm2..."
  npm install -g pm2 >/dev/null 2>&1 || { c_err "Gagal pasang pm2 (coba: npm i -g pm2)."; exit 1; }
fi
c_ok "pm2 $(pm2 -v)"

# 3) alamat bot (HOST:PORT)
HOST="${HIYOKA_HOST:-$(conf_get HIYOKA_HOST)}"
PORT="${HIYOKA_PORT:-$(conf_get HIYOKA_PORT)}"
if [ -z "$HOST" ] || [ -z "$PORT" ]; then
  echo
  echo "Isi alamat bot Hiyoka di panel Pterodactyl:"
  echo "  - IP/domain NODE (lihat di halaman server > Settings atau tab Network, contoh 103.xx.xx.xx)"
  echo "  - Port allocation yang dipakai server bot (tab Network, contoh 25565)"
  [ -r /dev/tty ] || { c_err "Tidak ada terminal interaktif. Jalankan: HIYOKA_HOST=ip HIYOKA_PORT=port bash run.sh"; exit 1; }
  read -rp "IP/domain node : " HOST </dev/tty
  read -rp "Port bot       : " PORT </dev/tty
fi
HOST="$(echo "$HOST" | tr -d '[:space:]')"; PORT="$(echo "$PORT" | tr -d '[:space:]')"
[[ "$HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { c_err "IP/domain tidak valid: $HOST"; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { c_err "Port tidak valid: $PORT"; exit 1; }
conf_set HIYOKA_HOST "$HOST"
conf_set HIYOKA_PORT "$PORT"
# secret bisa dikirim lewat env (dipakai /connect di bot), jadi tidak perlu ada di repo/zip
if [ -n "${HIYOKA_SECRET:-}" ]; then conf_set HIYOKA_SECRET "$HIYOKA_SECRET"; fi
SECRET_LEN="$(conf_get HIYOKA_SECRET | tr -d '[:space:]' | wc -c)"
[ "$SECRET_LEN" -ge 16 ] || { c_err "HIYOKA_SECRET kosong/kurang dari 16 karakter. Isi di agent.conf atau jalankan: HIYOKA_SECRET=xxxx bash run.sh"; exit 1; }
chmod 600 "$CONF"
c_ok "Bot: ws://$HOST:$PORT"

# 4) dependensi
c_inf "Memasang dependensi (npm install)..."
npm install --omit=dev --no-audit --no-fund >/dev/null 2>&1 || { c_err "npm install gagal. Cek koneksi internet VPS."; exit 1; }
node agent.js --check
c_ok "Dependensi terpasang"

# 5) cek port bot bisa dijangkau (hanya peringatan, agent akan terus mencoba sambung sendiri)
if timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/$PORT" 2>/dev/null; then
  c_ok "Port bot terjangkau"
else
  printf '\033[33m⚠ Port %s di %s belum terjangkau.\033[0m Pastikan bot sudah dinyalakan di panel dan port allocation-nya benar.\n  Agent tetap dipasang dan akan terus mencoba sambung otomatis.\n' "$PORT" "$HOST"
fi

# 6) jalankan di pm2 + auto start saat reboot
pm2 delete "$NAME" >/dev/null 2>&1 || true
pm2 start "$DIR/agent.js" --name "$NAME" --cwd "$DIR" --max-restarts 50 --restart-delay 3000 >/dev/null
pm2 save >/dev/null 2>&1 || true
if [ "$(id -u)" = "0" ]; then
  pm2 startup systemd -u root --hp "${HOME:-/root}" >/dev/null 2>&1 || true
  pm2 save >/dev/null 2>&1 || true
fi
c_ok "Agent berjalan di pm2 sebagai '$NAME'"

sleep 4
echo
pm2 logs "$NAME" --lines 8 --nostream 2>/dev/null || true
echo
echo "Selesai. Kalau sudah tersambung, bot akan kirim chat: ✅ Status terhubung"
echo "Cek kapan saja: bash run.sh status"
