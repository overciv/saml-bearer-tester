'use strict';
// Resolves which tenant a request belongs to: ?tenant=<id> query param wins
// and is remembered in a cookie so subsequent navigation (and the OIDC
// callback, which Okta hits with no query params of ours) still knows it.

const { getTenant } = require('./tenant-store');

const COOKIE = 'tenant_id';
const COOKIE_MAX_AGE = 180 * 24 * 60 * 60 * 1000; // 180 days

async function resolveTenant(req, res, next) {
  try {
    const queryTenantId = typeof req.query.tenant === 'string' ? req.query.tenant : null;
    const cookieTenantId = req.cookies?.[COOKIE] || null;
    const id = queryTenantId || cookieTenantId;

    if (id) {
      const tenant = await getTenant(id);
      if (tenant) {
        req.tenant = tenant;
        if (queryTenantId && queryTenantId !== cookieTenantId) {
          res.cookie(COOKIE, tenant.id, { httpOnly: true, sameSite: 'lax', secure: !!process.env.VERCEL, maxAge: COOKIE_MAX_AGE });
        }
      }
    }
  } catch (e) {
    console.error('resolveTenant error:', e.message);
  }
  next();
}

module.exports = { resolveTenant, COOKIE };
