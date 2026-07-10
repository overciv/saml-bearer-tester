'use strict';
const {
  generateKeyPair, exportJWK, importJWK,
  SignJWT, jwtVerify
} = require('jose');
const { v4: uuidv4 } = require('uuid');

async function generatePkjwtKeyPair(alg = 'RS256') {
  const opts = { extractable: true };
  if (alg.startsWith('RS') || alg.startsWith('PS')) opts.modulusLength = 2048;
  const { privateKey, publicKey } = await generateKeyPair(alg, opts);

  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = uuidv4();

  Object.assign(privateJwk, { alg, use: 'sig', kid });
  Object.assign(publicJwk, { alg, use: 'sig', kid });

  const jwks = { keys: [publicJwk] };
  return { privateJwk, publicJwk, jwks, kid, alg };
}

async function generateClientAssertion({ privateJwk, clientId, audience, validitySeconds = 300 }) {
  const alg = privateJwk.alg || 'RS256';
  const privateKey = await importJWK(privateJwk, alg);
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv4();

  const claims = {
    iss: clientId,
    sub: clientId,
    aud: audience,
    exp: now + validitySeconds,
    iat: now,
    jti
  };

  const assertion = await new SignJWT(claims)
    .setProtectedHeader({ alg, kid: privateJwk.kid })
    .sign(privateKey);

  return { assertion, claims, header: { alg, kid: privateJwk.kid } };
}

async function validateClientAssertion({ assertion, publicJwk, clientId, audience }) {
  const results = [];
  let valid = true;
  const fail = (check, detail) => { results.push({ check, ok: false, detail }); valid = false; };
  const pass = (check, detail) => results.push({ check, ok: true, detail });

  let payload;
  try {
    const alg = publicJwk.alg;
    const publicKey = await importJWK(publicJwk, alg);

    try {
      const result = await jwtVerify(assertion, publicKey, { algorithms: [alg] });
      payload = result.payload;
      pass(`Signature valid (${alg} with provided public JWK)`);
    } catch (e) {
      fail('Signature valid', e.message);
      const parts = assertion.split('.');
      try { payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); } catch {}
    }

    if (!payload) { fail('Parse assertion payload', 'Cannot decode JWT'); return { valid: false, results }; }

    // iss = clientId
    payload.iss === clientId
      ? pass(`iss = client_id ("${clientId}")`)
      : fail('iss = client_id', `Got "${payload.iss}"`);

    // sub = clientId
    payload.sub === clientId
      ? pass(`sub = client_id ("${clientId}")`)
      : fail('sub = client_id', `Got "${payload.sub}"`);

    // aud = audience
    const audMatch = payload.aud === audience || (Array.isArray(payload.aud) && payload.aud.includes(audience));
    audMatch
      ? pass('aud = token endpoint URL', String(payload.aud))
      : fail('aud = token endpoint URL', `Expected "${audience}", got "${payload.aud}"`);

    // exp not expired
    const now = Math.floor(Date.now() / 1000);
    payload.exp && payload.exp > now
      ? pass('exp is in the future', `${new Date(payload.exp * 1000).toISOString()} (${payload.exp - now}s remaining)`)
      : fail('exp is in the future', payload.exp ? `Expired ${now - payload.exp}s ago` : 'Missing exp claim');

    // exp within 1 hour of iat (Okta requirement)
    if (payload.iat && payload.exp) {
      const lifetime = payload.exp - payload.iat;
      lifetime <= 3600
        ? pass('Lifetime ≤ 1 hour (Okta requirement)', `${lifetime}s`)
        : fail('Lifetime ≤ 1 hour (Okta requirement)', `${lifetime}s — reduce exp`);
    }

    // jti (optional but recommended)
    payload.jti
      ? pass('jti present (one-time use ID)', payload.jti)
      : results.push({ check: 'jti present', ok: true, detail: 'Optional — omitted, token is reusable' });

  } catch (e) {
    fail('Parse assertion', e.message);
  }

  return { valid, results };
}

module.exports = { generatePkjwtKeyPair, generateClientAssertion, validateClientAssertion };
