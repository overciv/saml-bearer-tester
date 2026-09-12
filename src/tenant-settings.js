'use strict';
// Per-tenant, per-page settings (replaces per-browser localStorage as the
// source of truth) — e.g. tenant:acme:settings -> { global: {...}, dpop: {...}, ... }

const store = require('./store');

const settingsKey = (tenantId) => `tenant:${tenantId}:settings`;

async function getPageSettings(tenantId, page) {
  const all = (await store.get(settingsKey(tenantId))) || {};
  return all[page] || {};
}

async function savePageSettings(tenantId, page, data) {
  const all = (await store.get(settingsKey(tenantId))) || {};
  all[page] = { ...all[page], ...data };
  await store.set(settingsKey(tenantId), all);
  return all[page];
}

module.exports = { getPageSettings, savePageSettings };
