const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const sso = require('../../lib/sso');

test('Open Redirect Protection (sso.sanitizeReturnTo)', () => {
  const defaultUrl = '/';

  // Valid relative URLs
  assert.equal(sso.sanitizeReturnTo('/abc123xyz', defaultUrl), '/abc123xyz');
  assert.equal(sso.sanitizeReturnTo('/files/123++456', defaultUrl), '/files/123++456');

  // Open Redirect Attack attempts -> Fallback to defaultUrl
  assert.equal(sso.sanitizeReturnTo('https://evil.com', defaultUrl), '/');
  assert.equal(sso.sanitizeReturnTo('//evil.com', defaultUrl), '/');
  assert.equal(sso.sanitizeReturnTo('/\\evil.com', defaultUrl), '/');
  assert.equal(sso.sanitizeReturnTo('http://evil.com/phishing', defaultUrl), '/');
  assert.equal(sso.sanitizeReturnTo('javascript:alert(1)', defaultUrl), '/');
  assert.equal(sso.sanitizeReturnTo(null, defaultUrl), '/');
  assert.equal(sso.sanitizeReturnTo('', defaultUrl), '/');
});

test('authorizeBucketSso Open Redirect Sanitization & User Email Payload', () => {
  const fakeDb = {
    get(sid) {
      if (sid === 'sec123') {
        return [
          {
            metadata: {
              ssoEnforced: true,
              org: 'bank.com',
              password: 'hashed-secret-pass',
            },
          },
        ];
      }
      return [];
    },
  };

  const config = {
    ssoEnabled: true,
    ssoSecret: 'test-secret-key-32-chars-long-security',
  };

  const middleware = sso.authorizeBucketSso(fakeDb, config);

  // 1. Unauthenticated request with suspicious returnTo URL
  const reqUnauth = {
    params: { sid: 'sec123' },
    originalUrl: '//attacker.com/steal-creds',
    headers: {},
  };

  let statusSent = 0;
  let jsonPayload = null;
  const resUnauth = {
    header() {},
    status(code) {
      statusSent = code;
      return this;
    },
    json(payload) {
      jsonPayload = payload;
      return this;
    },
  };

  middleware(reqUnauth, resUnauth, () => {});

  assert.equal(statusSent, 401);
  assert.equal(jsonPayload.error, 'SSO_REQUIRED');
  assert.equal(jsonPayload.hasPassword, true);
  // Ensure returnTo in loginUrl was sanitized to '/'
  assert.ok(jsonPayload.loginUrl.includes('returnTo=%2F'));
  assert.ok(!jsonPayload.loginUrl.includes('attacker.com'));

  // 2. Authenticated request with mismatched Org
  const token = sso.createSessionToken(
    { email: 'alice@other.com', org: 'other.com' },
    config.ssoSecret
  );

  const reqMismatch = {
    params: { sid: 'sec123' },
    originalUrl: '/sec123',
    cookies: { psitransfer_sso: token },
    headers: {},
  };

  middleware(reqMismatch, resUnauth, () => {});

  assert.equal(statusSent, 403);
  assert.equal(jsonPayload.error, 'ORG_DENIED');
  assert.equal(jsonPayload.userEmail, 'alice@other.com');
  assert.equal(jsonPayload.userOrg, 'other.com');
  assert.equal(jsonPayload.requiredOrg, 'bank.com');
});
