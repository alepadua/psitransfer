const { createHash, randomBytes } = require('node:crypto');

/**
 * Generates a PKCE code_verifier string (43-128 chars).
 */
function generateCodeVerifier() {
  return randomBytes(32).toString('base64url');
}

/**
 * Generates a PKCE code_challenge (S256) from code_verifier.
 */
function generateCodeChallenge(verifier) {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Generates a random cryptographic state token for anti-CSRF binding.
 */
function generateStateToken() {
  return randomBytes(24).toString('base64url');
}

/**
 * Constructs an OIDC authorization login URL with PKCE and state protection.
 */
function buildAuthorizationUrl(orgConfig, options = {}) {
  const { redirectUri, state, codeChallenge, scope = 'openid profile email' } = options;
  const baseUrl =
    orgConfig.authorizationEndpoint ||
    `${orgConfig.issuerUrl.replace(/\/$/, '')}/protocol/openid-connect/auth`;

  const url = new URL(baseUrl);
  url.searchParams.set('client_id', orgConfig.clientId || 'psitransfer');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scope);
  if (redirectUri) url.searchParams.set('redirect_uri', redirectUri);
  if (state) url.searchParams.set('state', state);
  if (codeChallenge) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }

  return url.toString();
}

/**
 * Validates OIDC ID Token payload structure and standard claims.
 */
function parseAndValidateIdToken(idToken, expectedNonce = null) {
  if (!idToken || typeof idToken !== 'string') return null;
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;

  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) return null; // Expired
    if (expectedNonce && payload.nonce !== expectedNonce) return null;

    return {
      sub: payload.sub,
      email: payload.email || `${payload.sub}@oidc.user`,
      name: payload.name || payload.preferred_username || payload.email,
      org: payload.org || payload.hd || (payload.email ? payload.email.split('@')[1] : null),
    };
  } catch {
    return null;
  }
}

module.exports = {
  generateCodeVerifier,
  generateCodeChallenge,
  generateStateToken,
  buildAuthorizationUrl,
  parseAndValidateIdToken,
};
