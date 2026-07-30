const { createHmac, timingSafeEqual } = require('node:crypto');

/**
 * Creates a signed JWT-like token string for SSO session verification.
 */
function createSessionToken(user, secret, expiresInSeconds = 86400) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({
      email: user.email,
      org: user.org,
      name: user.name || user.email,
      iat: now,
      exp: now + expiresInSeconds,
    })
  ).toString('base64url');

  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');

  return `${header}.${payload}.${signature}`;
}

/**
 * Verifies a signed session token string.
 */
function verifySessionToken(token, secret) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const expectedSignature = createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url');

  const sigBuffer = Buffer.from(signature);
  const expBuffer = Buffer.from(expectedSignature);
  if (sigBuffer.length !== expBuffer.length || !timingSafeEqual(sigBuffer, expBuffer)) {
    return null;
  }

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (data.exp && data.exp < now) {
      return null; // Expired
    }
    return data;
  } catch {
    return null;
  }
}

/**
 * Gets organization SSO configuration if registered.
 */
function getOrgConfig(org, config) {
  if (!org || !config) return null;
  const orgLower = org.toLowerCase().trim();
  if (config.ssoStore && typeof config.ssoStore.getOrg === 'function') {
    const found = config.ssoStore.getOrg(orgLower);
    if (found) return found;
  }
  if (config.ssoMandatoryOrgs) {
    return config.ssoMandatoryOrgs[orgLower] || null;
  }
  return null;
}

/**
 * Checks if an organization domain is configured as requiring mandatory SSO.
 */
function isSsoMandatoryOrg(org, config) {
  if (!config || !config.ssoEnabled || !org || typeof org !== 'string') {
    return false;
  }
  const entry = getOrgConfig(org, config);
  if (entry) {
    return entry.requireSso !== false;
  }
  return false;
}

let defaultSecretWarned = false;

function getSsoSecret(config) {
  const secret = (config && config.ssoSecret) || 'psitransfer-sso-secret-key-change-me';
  if (secret === 'psitransfer-sso-secret-key-change-me' && !defaultSecretWarned) {
    console.warn(
      '[SECURITY WARNING] Using default SSO secret! Please set `ssoSecret` in config.js for production deployment.'
    );
    defaultSecretWarned = true;
  }
  return secret;
}

/**
 * Extracts authenticated SSO user details from request (cookies or Authorization header).
 */
function getSsoUser(req, config) {
  const secret = getSsoSecret(config);

  // 1. Try Cookie
  let token = req.cookies ? req.cookies.psitransfer_sso : null;

  // 2. Try Authorization Bearer header
  if (!token && req.headers && req.headers.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    }
  }

  if (!token) return null;
  return verifySessionToken(token, secret);
}

/**
 * Sets SSO session cookie on HTTP response.
 */
function setSsoCookie(res, user, config, req) {
  const secret = getSsoSecret(config);
  const token = createSessionToken(user, secret);
  const requestObj = req || res.req;
  const isSecure = Boolean(
    (requestObj &&
      (requestObj.secure ||
        (requestObj.headers && requestObj.headers['x-forwarded-proto'] === 'https'))) ||
    (config && config.ssl)
  );

  res.cookie('psitransfer_sso', token, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
    maxAge: 24 * 3600 * 1000, // 24 hours
  });
  return token;
}

/**
 * Clears SSO session cookie on HTTP response.
 */
function clearSsoCookie(res) {
  res.clearCookie('psitransfer_sso');
}

/**
 * Middleware enforcing SSO for buckets where metadata.ssoEnforced is true.
 */
function authorizeBucketSso(db, config) {
  return function (req, res, next) {
    const fid = req.params.sid || (req.params.fid ? req.params.fid.split('++')[0] : null);
    if (!fid) return next();

    const bucket = db.get(fid);
    if (!bucket || bucket.length === 0) return next();

    const meta = bucket[0].metadata || {};

    // If bucket does not enforce SSO, bypass SSO check entirely!
    if (!meta.ssoEnforced || !meta.org) {
      return next();
    }

    // SSO is enforced for this high-security Org bucket
    const user = getSsoUser(req, config);

    // 1. Check if downloader has an active SSO session
    if (!user) {
      const orgConfig = getOrgConfig(meta.org, config);
      const orgName = orgConfig && orgConfig.name ? orgConfig.name : meta.org;
      const baseUrl = config.baseUrl || '/';

      res.header('Cache-control', 'private, max-age=0, no-cache, no-store, must-revalidate');
      return res.status(401).json({
        error: 'SSO_REQUIRED',
        org: meta.org,
        orgName,
        message: `High-Security Transfer: You must authenticate via ${orgName} SSO to access these files.`,
        loginUrl: `${baseUrl}auth/sso/login/${encodeURIComponent(meta.org)}?returnTo=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    // 2. Check if downloader's Org matches the required Org
    const userOrg = (user.org || '').toLowerCase().trim();
    const requiredOrg = meta.org.toLowerCase().trim();

    if (userOrg !== requiredOrg) {
      res.header('Cache-control', 'private, max-age=0, no-cache, no-store, must-revalidate');
      return res.status(403).json({
        error: 'ORG_DENIED',
        message: `Access Denied: Your SSO account (${user.email}) belongs to '${userOrg}', but this file transfer is restricted to members of '${requiredOrg}'.`,
      });
    }

    // SSO and Org claims verified! Store user in request object and proceed to password check layer.
    req.ssoUser = user;
    next();
  };
}

module.exports = {
  createSessionToken,
  verifySessionToken,
  isSsoMandatoryOrg,
  getOrgConfig,
  getSsoUser,
  setSsoCookie,
  clearSsoCookie,
  authorizeBucketSso,
};
