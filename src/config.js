'use strict';
const fs = require('fs');
const path = require('path');
const { generateKeyPair, exportJWK } = require('jose');
const { v4: uuidv4 } = require('uuid');

const ROOT = path.join(__dirname, '..');
const CONFIG_FILE = path.join(ROOT, 'config.json');
const KEYS_DIR = path.join(ROOT, 'keys');
const SIGNING_KEY_FILE = path.join(KEYS_DIR, 'signing-key.json');

const DEFAULTS = {
  oktaDomain: '',
  authServerId: '',
  clientId: '',
  clientSecret: '',
  adminApiToken: '',
  authEnabled: false,
  authClientId: '',
  authScopes: ['openid', 'profile', 'email'],
  redirectUri: 'http://localhost:3000/auth/callback',
  sessionSecret: uuidv4()
};

let _config = null;
let _signingKey = null;

function getConfig() {
  if (_config) return _config;
  try {
    _config = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
  } catch {
    _config = { ...DEFAULTS };
    _saveConfigToDisk(_config);
  }
  return _config;
}

function _saveConfigToDisk(cfg) {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  } catch (e) {
    console.error('Failed to write config.json:', e.message);
  }
}

function saveConfig(data) {
  getConfig();
  // Never overwrite the session secret from a client call
  const { sessionSecret: _ignored, ...safe } = data;
  _config = { ..._config, ...safe };
  _saveConfigToDisk(_config);
  return _config;
}

async function getSigningKey() {
  if (_signingKey) return _signingKey;
  try {
    _signingKey = JSON.parse(fs.readFileSync(SIGNING_KEY_FILE, 'utf8'));
    console.log(`  Signing key loaded  kid=${_signingKey.kid}`);
    return _signingKey;
  } catch {
    console.log('  No signing key — generating RS256 key pair...');
    return generateSigningKey();
  }
}

async function generateSigningKey() {
  const alg = 'RS256';
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true, modulusLength: 2048 });
  const [privateJwk, publicJwk] = await Promise.all([exportJWK(privateKey), exportJWK(publicKey)]);
  const kid = uuidv4();
  Object.assign(privateJwk, { alg, use: 'sig', kid });
  Object.assign(publicJwk, { alg, use: 'sig', kid });
  _signingKey = { alg, kid, privateJwk, publicJwk, jwks: { keys: [publicJwk] } };
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  fs.writeFileSync(SIGNING_KEY_FILE, JSON.stringify(_signingKey, null, 2));
  console.log(`  Signing key generated  kid=${kid}`);
  return _signingKey;
}

function getPublicJwks() {
  if (!_signingKey) return { keys: [] };
  return { keys: [_signingKey.publicJwk] };
}

// Public view of config (no private fields)
function getPublicConfig() {
  const cfg = getConfig();
  return {
    oktaDomain: cfg.oktaDomain,
    authServerId: cfg.authServerId,
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    adminApiToken: cfg.adminApiToken,
    authEnabled: cfg.authEnabled,
    authClientId: cfg.authClientId,
    authScopes: cfg.authScopes,
    redirectUri: cfg.redirectUri
  };
}

module.exports = { getConfig, saveConfig, getSigningKey, generateSigningKey, getPublicJwks, getPublicConfig };
