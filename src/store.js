'use strict';
// Key/value storage abstraction, in priority order:
//   1. Postgres (Neon serverless driver) — primary target for Vercel deploys
//   2. Redis (Upstash REST API) — used if a Redis integration is configured instead
//   3. Local JSON file — dev fallback, no cloud account needed
//
// All backends implement the same get/set/del/sadd/srem/smembers interface.

const fs = require('fs');
const path = require('path');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.DATABASE_URL_UNPOOLED;
const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

let backend;

if (DATABASE_URL) {
  // ─── Postgres (Neon) backend ────────────────────────────────────────────
  const { neon } = require('@neondatabase/serverless');
  const sql = neon(DATABASE_URL);

  let ensured = null;
  function ensureTable() {
    if (!ensured) {
      ensured = sql`CREATE TABLE IF NOT EXISTS kv_store (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL,
        expires_at TIMESTAMPTZ
      )`;
    }
    return ensured;
  }

  function parseValue(v) {
    return typeof v === 'string' ? JSON.parse(v) : v;
  }

  backend = {
    async get(key) {
      await ensureTable();
      const rows = await sql`SELECT value, expires_at FROM kv_store WHERE key = ${key}`;
      if (!rows.length) return null;
      const row = rows[0];
      if (row.expires_at && new Date(row.expires_at) < new Date()) {
        await sql`DELETE FROM kv_store WHERE key = ${key}`;
        return null;
      }
      return parseValue(row.value);
    },
    async set(key, value, ttlSeconds) {
      await ensureTable();
      const expiresAt = ttlSeconds ? new Date(Date.now() + ttlSeconds * 1000).toISOString() : null;
      await sql`INSERT INTO kv_store (key, value, expires_at) VALUES (${key}, ${JSON.stringify(value)}::jsonb, ${expiresAt})
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`;
    },
    async del(key) {
      await ensureTable();
      await sql`DELETE FROM kv_store WHERE key = ${key}`;
    },
    async sadd(setKey, member) {
      const cur = new Set(await backend.get(setKey) || []);
      cur.add(member);
      await backend.set(setKey, [...cur]);
    },
    async srem(setKey, member) {
      const cur = new Set(await backend.get(setKey) || []);
      cur.delete(member);
      await backend.set(setKey, [...cur]);
    },
    async smembers(setKey) {
      return (await backend.get(setKey)) || [];
    }
  };

  console.log('  Storage: Postgres (Neon) via DATABASE_URL');
} else if (REDIS_URL && REDIS_TOKEN) {
  // ─── Redis (Upstash REST) backend ───────────────────────────────────────
  const { Redis } = require('@upstash/redis');
  const redis = new Redis({ url: REDIS_URL, token: REDIS_TOKEN });

  backend = {
    async get(key) {
      const v = await redis.get(key);
      return v === null || v === undefined ? null : v;
    },
    async set(key, value, ttlSeconds) {
      if (ttlSeconds) await redis.set(key, value, { ex: ttlSeconds });
      else await redis.set(key, value);
    },
    async del(key) { await redis.del(key); },
    async sadd(setKey, member) { await redis.sadd(setKey, member); },
    async srem(setKey, member) { await redis.srem(setKey, member); },
    async smembers(setKey) { return redis.smembers(setKey); }
  };

  console.log('  Storage: Redis (Upstash REST API)');
} else {
  // ─── Local JSON-file fallback (dev only) ────────────────────────────────
  const DATA_DIR = path.join(__dirname, '..', '.data');
  const DATA_FILE = path.join(DATA_DIR, 'store.json');

  function readAll() {
    try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
    catch { return {}; }
  }
  function writeAll(db) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  }

  backend = {
    async get(key) {
      const db = readAll();
      const entry = db[key];
      if (!entry) return null;
      if (entry.expiresAt && entry.expiresAt < Date.now()) { delete db[key]; writeAll(db); return null; }
      return entry.value;
    },
    async set(key, value, ttlSeconds) {
      const db = readAll();
      db[key] = { value, expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null };
      writeAll(db);
    },
    async del(key) {
      const db = readAll();
      delete db[key];
      writeAll(db);
    },
    async sadd(setKey, member) {
      const db = readAll();
      const cur = new Set(db[setKey]?.value || []);
      cur.add(member);
      db[setKey] = { value: [...cur], expiresAt: null };
      writeAll(db);
    },
    async srem(setKey, member) {
      const db = readAll();
      const cur = new Set(db[setKey]?.value || []);
      cur.delete(member);
      db[setKey] = { value: [...cur], expiresAt: null };
      writeAll(db);
    },
    async smembers(setKey) {
      const db = readAll();
      return db[setKey]?.value || [];
    }
  };

  console.log('  Storage: local JSON file fallback (.data/store.json) — set DATABASE_URL (or KV_REST_API_URL/TOKEN) to use a real store');
}

module.exports = backend;
