'use strict';
// AES-256-GCM helpers for encrypting secrets (client secrets, JWKS private keys)
// before they're written to the shared KV store.

const crypto = require('crypto');

function getKey() {
  const raw = process.env.TENANT_ENCRYPTION_KEY;
  if (!raw) return null;
  // Accept either a 32-byte base64/hex string or an arbitrary passphrase (hashed to 32 bytes).
  if (/^[0-9a-f]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  try {
    const b = Buffer.from(raw, 'base64');
    if (b.length === 32) return b;
  } catch {}
  return crypto.createHash('sha256').update(raw).digest();
}

const KEY = getKey();

// Returns a string. If no TENANT_ENCRYPTION_KEY is configured, stores in
// clear text (prefixed so decrypt() can tell) rather than failing hard —
// this keeps local dev working without forcing key setup.
function encrypt(plaintext) {
  if (plaintext === undefined || plaintext === null) return plaintext;
  const text = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
  if (!KEY) return `plain:${text}`;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
}

function decrypt(stored) {
  if (stored === undefined || stored === null) return stored;
  if (stored.startsWith('plain:')) return stored.slice('plain:'.length);
  if (!stored.startsWith('enc:')) return stored; // not something we encrypted
  if (!KEY) throw new Error('TENANT_ENCRYPTION_KEY is required to decrypt stored secrets');
  const [, ivB64, tagB64, dataB64] = stored.split(':');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
}

function decryptJson(stored) {
  const s = decrypt(stored);
  if (s === undefined || s === null) return s;
  try { return JSON.parse(s); } catch { return s; }
}

module.exports = { encrypt, decrypt, decryptJson };
