'use strict';
// App-wide (non-tenant) state: just the RS256 signing key used by the
// private_key_jwt testing pages (pkjwt.js, dpop.js, etc.) and by the app's
// own JWKS endpoint. Stored in the shared KV store so it survives across
// serverless invocations instead of local disk.

const { generateKeyPair, exportJWK } = require('jose');
const { v4: uuidv4 } = require('uuid');
const store = require('./store');

const SIGNING_KEY_KEY = 'signingkey';

let _signingKey = null;

async function getSigningKey() {
  if (_signingKey) return _signingKey;
  const stored = await store.get(SIGNING_KEY_KEY);
  if (stored) {
    _signingKey = stored;
    console.log(`  Signing key loaded  kid=${_signingKey.kid}`);
    return _signingKey;
  }
  console.log('  No signing key — generating RS256 key pair...');
  return generateSigningKey();
}

async function generateSigningKey() {
  const alg = 'RS256';
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true, modulusLength: 2048 });
  const [privateJwk, publicJwk] = await Promise.all([exportJWK(privateKey), exportJWK(publicKey)]);
  const kid = uuidv4();
  Object.assign(privateJwk, { alg, use: 'sig', kid });
  Object.assign(publicJwk, { alg, use: 'sig', kid });
  _signingKey = { alg, kid, privateJwk, publicJwk, jwks: { keys: [publicJwk] } };
  await store.set(SIGNING_KEY_KEY, _signingKey);
  console.log(`  Signing key generated  kid=${kid}`);
  return _signingKey;
}

function getPublicJwks() {
  if (!_signingKey) return { keys: [] };
  return { keys: [_signingKey.publicJwk] };
}

module.exports = { getSigningKey, generateSigningKey, getPublicJwks };
