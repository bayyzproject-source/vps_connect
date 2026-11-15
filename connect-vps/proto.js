'use strict';
// Protokol enkripsi Hiyoka (SAMA PERSIS di bot dan agent VPS).
// Handshake: hello(nonce agent) -> welcome(nonce bot) -> kunci sesi per arah (HKDF dari secret + kedua nonce).
// Tiap frame = AES-256-GCM dengan IV dari counter, jadi tidak bisa diputar ulang / disisipkan tanpa tahu secret.
const crypto = require('crypto');

const SALT = 'hiyoka-link-v1';

const masterKey = (secret) => crypto.scryptSync(String(secret), SALT, 32);
const randomNonce = () => crypto.randomBytes(16).toString('hex');

function sessionKeys(master, nonceAgentHex, nonceBotHex) {
  const salt = Buffer.concat([Buffer.from(nonceAgentHex, 'hex'), Buffer.from(nonceBotHex, 'hex')]);
  return {
    a2b: Buffer.from(crypto.hkdfSync('sha256', master, salt, 'hiyoka a2b', 32)),
    b2a: Buffer.from(crypto.hkdfSync('sha256', master, salt, 'hiyoka b2a', 32)),
  };
}

class Channel {
  constructor(sendKey, recvKey) {
    this.sk = sendKey;
    this.rk = recvKey;
    this.sc = 0n;
    this.rc = 0n;
  }
  static iv(n) {
    const b = Buffer.alloc(12);
    b.writeBigUInt64BE(n, 4);
    return b;
  }
  // header = objek JSON kecil, body = Buffer opsional (isi file, dst)
  seal(header, body) {
    const h = Buffer.from(JSON.stringify(header));
    const len = Buffer.alloc(4);
    len.writeUInt32BE(h.length);
    const plain = Buffer.concat([len, h, body && body.length ? body : Buffer.alloc(0)]);
    const c = crypto.createCipheriv('aes-256-gcm', this.sk, Channel.iv(this.sc++));
    const enc = Buffer.concat([c.update(plain), c.final()]);
    return Buffer.concat([enc, c.getAuthTag()]);
  }
  open(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 4 + 16) throw new Error('frame tidak valid');
    const d = crypto.createDecipheriv('aes-256-gcm', this.rk, Channel.iv(this.rc++));
    d.setAuthTag(buf.subarray(buf.length - 16));
    const plain = Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]);
    const hl = plain.readUInt32BE(0);
    if (hl > plain.length - 4) throw new Error('header rusak');
    return { header: JSON.parse(plain.subarray(4, 4 + hl).toString('utf8')), body: plain.subarray(4 + hl) };
  }
}

module.exports = { masterKey, randomNonce, sessionKeys, Channel };
