'use strict';
// Tenant CRUD on top of the KV store, with secrets encrypted at rest.

const store = require('./store');
const { encrypt, decrypt, decryptJson } = require('./crypto');

const TENANT_INDEX = 'tenants:index';
const tenantKey = (id) => `tenant:${id}`;

function slugify(name) {
  return String(name || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'tenant';
}

function encryptForStorage(tenant) {
  const t = JSON.parse(JSON.stringify(tenant));
  if (t.oidcConfiguration?.client_secret) {
    t.oidcConfiguration.client_secret = encrypt(t.oidcConfiguration.client_secret);
  }
  if (t.managementCredentials?.clientSecret) {
    t.managementCredentials.clientSecret = encrypt(t.managementCredentials.clientSecret);
  }
  if (t.managementCredentials?.clientJWKS) {
    t.managementCredentials.clientJWKS = encrypt(t.managementCredentials.clientJWKS);
  }
  return t;
}

function decryptFromStorage(t) {
  if (!t) return t;
  const out = JSON.parse(JSON.stringify(t));
  if (out.oidcConfiguration?.client_secret) {
    out.oidcConfiguration.client_secret = decrypt(out.oidcConfiguration.client_secret);
  }
  if (out.managementCredentials?.clientSecret) {
    out.managementCredentials.clientSecret = decrypt(out.managementCredentials.clientSecret);
  }
  if (out.managementCredentials?.clientJWKS) {
    out.managementCredentials.clientJWKS = decryptJson(out.managementCredentials.clientJWKS);
  }
  return out;
}

async function getTenant(id) {
  if (!id) return null;
  const raw = await store.get(tenantKey(id));
  return decryptFromStorage(raw);
}

async function upsertTenant(tenant) {
  const now = new Date().toISOString();
  const existing = await store.get(tenantKey(tenant.id));
  const merged = { ...decryptFromStorage(existing), ...tenant, updatedAt: now, createdAt: existing?.createdAt || now };
  await store.set(tenantKey(tenant.id), encryptForStorage(merged));
  await store.sadd(TENANT_INDEX, tenant.id);
  return merged;
}

async function deleteTenant(id) {
  await store.del(tenantKey(id));
  await store.del(`tenant:${id}:settings`);
  await store.srem(TENANT_INDEX, id);
}

async function listTenantIds() {
  return store.smembers(TENANT_INDEX);
}

module.exports = { slugify, getTenant, upsertTenant, deleteTenant, listTenantIds };
