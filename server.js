'use strict';
const express = require('express');
const axios = require('axios');
const path = require('path');
const { generateKeyPair, generateAssertion, decodeAssertionBase64 } = require('./src/saml');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/generate-keypair', async (req, res) => {
  try {
    const result = await generateKeyPair();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/generate-assertion', (req, res) => {
  try {
    const result = generateAssertion(req.body);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message, detail: err.stack });
  }
});

app.post('/api/decode-assertion', (req, res) => {
  try {
    const { encoded } = req.body;
    if (!encoded) return res.status(400).json({ error: 'encoded is required' });
    const xml = decodeAssertionBase64(encoded);
    res.json({ xml });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, scope, assertion } = req.body;

  const tokenEndpoint = authServerId && authServerId.trim() && authServerId.trim() !== 'org'
    ? `https://${oktaDomain}/oauth2/${authServerId.trim()}/v1/token`
    : `https://${oktaDomain}/oauth2/v1/token`;

  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;

  const params = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
    assertion,
    scope: scopes
  });

  const requestDetails = {
    url: tokenEndpoint,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials.substring(0, 8)}...`
    },
    body: {
      grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
      scope: scopes,
      assertion: assertion.substring(0, 40) + '...'
    }
  };

  const startTime = Date.now();

  try {
    const response = await axios.post(tokenEndpoint, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
        'Accept': 'application/json'
      },
      validateStatus: () => true
    });

    res.json({
      success: response.status >= 200 && response.status < 300,
      statusCode: response.status,
      durationMs: Date.now() - startTime,
      tokenEndpoint,
      requestDetails,
      response: response.data
    });
  } catch (err) {
    res.json({
      success: false,
      statusCode: 0,
      durationMs: Date.now() - startTime,
      tokenEndpoint,
      requestDetails,
      error: { message: err.message, code: err.code }
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nSAML Bearer Token Tester running at http://localhost:${PORT}\n`);
});
