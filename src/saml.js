'use strict';
const { SignedXml } = require('xml-crypto');
const { v4: uuidv4 } = require('uuid');
const forge = require('node-forge');

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function generateKeyPair() {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048 }, (err, keypair) => {
      if (err) return reject(err);

      const cert = forge.pki.createCertificate();
      cert.publicKey = keypair.publicKey;
      cert.serialNumber = Date.now().toString(16);
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000);

      const attrs = [
        { name: 'commonName', value: 'SAML Test IdP' },
        { name: 'organizationName', value: 'Test Organization' },
        { name: 'countryName', value: 'US' }
      ];
      cert.setSubject(attrs);
      cert.setIssuer(attrs);
      cert.sign(keypair.privateKey, forge.md.sha256.create());

      resolve({
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
        certificate: forge.pki.certificateToPem(cert)
      });
    });
  });
}

function generateAssertion({
  issuer,
  subject,
  nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  recipient,
  audience,
  validityMinutes = 60,
  clockSkewMinutes = 5,
  authnContextClass = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  privateKey,
  certificate,
  attributes = {}
}) {
  const required = { issuer, subject, recipient, audience, privateKey, certificate };
  const missing = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) throw new Error(`Missing required fields: ${missing.join(', ')}`);
  const now = new Date();
  const notBefore = new Date(now.getTime() - clockSkewMinutes * 60000);
  const notOnOrAfter = new Date(now.getTime() + validityMinutes * 60000);
  const assertionId = '_' + uuidv4().replace(/-/g, '');

  const fmt = d => new Date(d).toISOString().replace(/\.\d+Z$/, 'Z');

  const attrLines = Object.entries(attributes)
    .filter(([k, v]) => k && v !== undefined && v !== '')
    .map(([name, value]) => `
        <saml:Attribute Name="${escapeXml(name)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xsi:type="xs:string">${escapeXml(String(value))}</saml:AttributeValue>
        </saml:Attribute>`).join('');

  const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="${assertionId}" Version="2.0" IssueInstant="${fmt(now)}">
    <saml:Issuer>${escapeXml(issuer)}</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="${escapeXml(nameIdFormat)}">${escapeXml(subject)}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="${fmt(notOnOrAfter)}" Recipient="${escapeXml(recipient)}"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${fmt(notBefore)}" NotOnOrAfter="${fmt(notOnOrAfter)}">
        <saml:AudienceRestriction>
            <saml:Audience>${escapeXml(audience)}</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${fmt(now)}" SessionIndex="${assertionId}">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>${escapeXml(authnContextClass)}</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>${attrLines ? `
    <saml:AttributeStatement>${attrLines}
    </saml:AttributeStatement>` : ''}
</saml:Assertion>`;

  const cleanCert = certificate
    .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');

  const sig = new SignedXml();
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.signingKey = Buffer.from(privateKey);

  sig.keyInfoProvider = {
    getKeyInfo: () => `<X509Data><X509Certificate>${cleanCert}</X509Certificate></X509Data>`,
    getKey: () => Buffer.from(privateKey)
  };

  sig.addReference(
    `//*[@ID='${assertionId}']`,
    [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    'http://www.w3.org/2001/04/xmlenc#sha256'
  );

  sig.computeSignature(assertionXml, {
    location: {
      reference: `//*[local-name(.)='Issuer']`,
      action: 'after'
    }
  });

  const signedXml = sig.getSignedXml();

  // Base64URL encode (RFC 4648, no padding)
  const base64url = Buffer.from(signedXml)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return { assertionId, xml: signedXml, base64url };
}

function decodeAssertionBase64(encoded) {
  // Accept both base64 and base64url
  const normalized = encoded
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/\s/g, '');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

module.exports = { generateKeyPair, generateAssertion, decodeAssertionBase64 };
