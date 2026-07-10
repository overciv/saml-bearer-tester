'use strict';
const {
  generateKeyPair, exportJWK, importJWK,
  SignJWT, calculateJwkThumbprint, jwtVerify,
  decodeProtectedHeader
} = require('jose');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

async function generateDpopKeyPair(alg = 'ES256') {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);

  const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');
  Object.assign(privateJwk, { alg, use: 'sig', kid: thumbprint });
  Object.assign(publicJwk, { alg, use: 'sig', kid: thumbprint });

  return { privateJwk, publicJwk, thumbprint, alg };
}

async function generateDpopProof({ privateJwk, publicJwk, htm, htu, nonce, accessToken }) {
  const alg = privateJwk.alg || 'ES256';
  const privateKey = await importJWK(privateJwk, alg);

  const payload = {
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
    jti: uuidv4()
  };

  if (nonce) payload.nonce = nonce;

  if (accessToken) {
    const hash = crypto.createHash('sha256').update(accessToken, 'ascii').digest();
    payload.ath = hash.toString('base64url');
  }

  // Embed public JWK in header — strip kid per RFC 9449 recommendation
  const { kid: _k, ...headerJwk } = publicJwk;

  const proof = await new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg, jwk: headerJwk })
    .sign(privateKey);

  const header = { typ: 'dpop+jwt', alg, jwk: headerJwk };
  return { proof, decodedHeader: header, decodedPayload: payload };
}

async function validateDpopProof({ proof, accessToken, htm, htu }) {
  const results = [];
  let valid = true;

  const fail = (check, detail) => { results.push({ check, ok: false, detail }); valid = false; };
  const pass = (check, detail) => results.push({ check, ok: true, detail });

  try {
    const header = decodeProtectedHeader(proof);
    const parts = proof.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // 1. typ
    header.typ === 'dpop+jwt' ? pass('typ = "dpop+jwt"') : fail('typ = "dpop+jwt"', `Got "${header.typ}"`);

    // 2. asymmetric alg
    const asymAlgs = ['RS256','RS384','RS512','PS256','PS384','PS512','ES256','ES384','ES512'];
    asymAlgs.includes(header.alg)
      ? pass(`alg "${header.alg}" is asymmetric`)
      : fail(`alg is asymmetric`, `"${header.alg}" is not allowed`);

    // 3. JWK present
    if (!header.jwk) {
      fail('jwk present in header', 'Missing — server cannot verify the proof');
    } else {
      // 4. Signature verification
      try {
        const embeddedKey = await importJWK(header.jwk, header.alg);
        await jwtVerify(proof, embeddedKey, { typ: 'dpop+jwt' });
        pass('Signature valid (using embedded JWK)');
      } catch (e) {
        fail('Signature valid (using embedded JWK)', e.message);
      }

      // 5. JKT calculation
      const jkt = await calculateJwkThumbprint(header.jwk, 'sha256');
      pass('JKT calculated from embedded JWK', jkt);

      // 6. JKT vs access token cnf.jkt
      if (accessToken) {
        try {
          const tp = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString());
          const tokenJkt = tp?.cnf?.jkt;
          if (tokenJkt) {
            jkt === tokenJkt
              ? pass('JKT matches access_token cnf.jkt', jkt)
              : fail('JKT matches access_token cnf.jkt', `Proof: ${jkt} ≠ Token: ${tokenJkt}`);
          } else {
            fail('access_token has cnf.jkt', 'Missing — token is not DPoP-bound');
          }
        } catch (e) {
          fail('Decode access_token for cnf.jkt', e.message);
        }
      }
    }

    // 7. htm
    payload.htm === htm
      ? pass(`htm = "${htm}"`)
      : fail(`htm = "${htm}"`, `Got "${payload.htm}"`);

    // 8. htu
    payload.htu === htu
      ? pass('htu matches request URL')
      : fail('htu matches request URL', `Expected "${htu}", got "${payload.htu}"`);

    // 9. iat freshness (±5 min)
    const now = Math.floor(Date.now() / 1000);
    const age = now - (payload.iat || 0);
    (age >= -60 && age <= 300)
      ? pass('iat is recent (≤ 300s)', `Age: ${age}s`)
      : fail('iat is recent (≤ 300s)', `Age: ${age}s — proof is stale or from the future`);

    // 10. jti
    payload.jti ? pass('jti present (replay protection)', payload.jti) : fail('jti present', 'Missing');

    // 11. ath (required when using token at resource server)
    if (accessToken) {
      if (!payload.ath) {
        fail('ath claim present', 'Required for resource access — must equal BASE64URL(SHA256(access_token))');
      } else {
        const expectedAth = crypto.createHash('sha256').update(accessToken, 'ascii').digest().toString('base64url');
        payload.ath === expectedAth
          ? pass('ath = BASE64URL(SHA256(access_token))')
          : fail('ath = BASE64URL(SHA256(access_token))', 'Hash mismatch — token and ath do not match');
      }
    }

  } catch (e) {
    fail('Parse DPoP proof JWT', e.message);
  }

  return { valid, results };
}

module.exports = { generateDpopKeyPair, generateDpopProof, validateDpopProof };
