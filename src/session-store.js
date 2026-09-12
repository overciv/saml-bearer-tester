'use strict';
// express-session Store backed by src/store.js. Needed because the default
// MemoryStore doesn't survive serverless cold starts / multiple instances,
// and the Vercel KV / Upstash REST client isn't compatible with connect-redis
// (which expects an ioredis/node-redis TCP client).

const session = require('express-session');
const store = require('./store');

const PREFIX = 'sess:';

class KvSessionStore extends session.Store {
  async get(sid, cb) {
    try { cb(null, (await store.get(PREFIX + sid)) || null); }
    catch (e) { cb(e); }
  }

  async set(sid, sess, cb) {
    try {
      const ttlSeconds = Math.ceil((sess.cookie?.maxAge ?? 8 * 60 * 60 * 1000) / 1000);
      await store.set(PREFIX + sid, sess, ttlSeconds);
      cb(null);
    } catch (e) { cb(e); }
  }

  async destroy(sid, cb) {
    try { await store.del(PREFIX + sid); cb(null); }
    catch (e) { cb(e); }
  }

  async touch(sid, sess, cb) {
    try {
      const ttlSeconds = Math.ceil((sess.cookie?.maxAge ?? 8 * 60 * 60 * 1000) / 1000);
      await store.set(PREFIX + sid, sess, ttlSeconds);
      cb(null);
    } catch (e) { cb(e); }
  }
}

module.exports = { KvSessionStore };
