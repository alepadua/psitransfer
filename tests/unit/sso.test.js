const test = require('node:test');
const assert = require('node:assert/strict');
const sso = require('../../lib/sso');

const testSecret = 'test-sso-secret-key-12345';

const mockConfig = {
  ssoEnabled: true,
  ssoSecret: testSecret,
  ssoMandatoryOrgs: {
    'bank.com': {
      name: 'Bank Corp',
      requireSso: true,
      allowedDomains: ['bank.com'],
    },
    'health.org': {
      name: 'Health Org',
      requireSso: true,
      allowedDomains: ['health.org'],
    },
    'optional.com': {
      name: 'Optional Inc',
      requireSso: false,
    },
  },
};

test('createSessionToken and verifySessionToken should generate and validate valid tokens', () => {
  const user = { email: 'alice@bank.com', org: 'bank.com', name: 'Alice Smith' };
  const token = sso.createSessionToken(user, testSecret);

  assert.equal(typeof token, 'string');
  assert.equal(token.split('.').length, 3);

  const verified = sso.verifySessionToken(token, testSecret);
  assert.notEqual(verified, null);
  assert.equal(verified.email, 'alice@bank.com');
  assert.equal(verified.org, 'bank.com');
  assert.equal(verified.name, 'Alice Smith');
});

test('verifySessionToken should reject invalid signatures or modified tokens', () => {
  const user = { email: 'alice@bank.com', org: 'bank.com' };
  const token = sso.createSessionToken(user, testSecret);

  // Wrong secret
  assert.equal(sso.verifySessionToken(token, 'wrong-secret'), null);

  // Tampered payload
  const parts = token.split('.');
  const tamperedToken = `${parts[0]}.tampered.${parts[2]}`;
  assert.equal(sso.verifySessionToken(tamperedToken, testSecret), null);
});

test('isSsoMandatoryOrg correctly identifies high-security Orgs requiring SSO', () => {
  assert.equal(sso.isSsoMandatoryOrg('bank.com', mockConfig), true);
  assert.equal(sso.isSsoMandatoryOrg('HEALTH.ORG', mockConfig), true); // Case insensitive
  assert.equal(sso.isSsoMandatoryOrg('optional.com', mockConfig), false); // requireSso is false
  assert.equal(sso.isSsoMandatoryOrg('standard.com', mockConfig), false); // Not listed
  assert.equal(sso.isSsoMandatoryOrg(null, mockConfig), false);
});

test('isSsoMandatoryOrg returns false when ssoEnabled is false', () => {
  const disabledConfig = { ...mockConfig, ssoEnabled: false };
  assert.equal(sso.isSsoMandatoryOrg('bank.com', disabledConfig), false);
});

test('authorizeBucketSso allows access if bucket does not enforce SSO', (t, done) => {
  const mockDb = {
    get: () => [{ metadata: { ssoEnforced: false, org: 'standard.com' } }],
  };
  const middleware = sso.authorizeBucketSso(mockDb, mockConfig);
  const req = { params: { sid: 'bucket123' } };
  const res = {};

  middleware(req, res, () => {
    // next() called successfully
    done();
  });
});

test('authorizeBucketSso returns 401 SSO_REQUIRED when user is not authenticated', (t, done) => {
  const mockDb = {
    get: () => [{ metadata: { ssoEnforced: 'true', org: 'bank.com' } }],
  };
  const middleware = sso.authorizeBucketSso(mockDb, mockConfig);
  const req = { params: { sid: 'sec123' }, cookies: {}, headers: {} };
  const res = {
    header: () => res,
    status: (code) => {
      assert.equal(code, 401);
      return {
        json: (data) => {
          assert.equal(data.error, 'SSO_REQUIRED');
          assert.equal(data.org, 'bank.com');
          done();
        },
      };
    },
  };

  middleware(req, res, () => {
    assert.fail('next() should not have been called');
  });
});

test('authorizeBucketSso returns 403 ORG_DENIED when authenticated user belongs to wrong Org', (t, done) => {
  const mockDb = {
    get: () => [{ metadata: { ssoEnforced: 'true', org: 'bank.com' } }],
  };
  const wrongUserToken = sso.createSessionToken({ email: 'bob@other.com', org: 'other.com' }, testSecret);
  const middleware = sso.authorizeBucketSso(mockDb, mockConfig);
  const req = { params: { sid: 'sec123' }, cookies: { psitransfer_sso: wrongUserToken }, headers: {} };
  const res = {
    header: () => res,
    status: (code) => {
      assert.equal(code, 403);
      return {
        json: (data) => {
          assert.equal(data.error, 'ORG_DENIED');
          done();
        },
      };
    },
  };

  middleware(req, res, () => {
    assert.fail('next() should not have been called');
  });
});

test('authorizeBucketSso passes when authenticated user belongs to required Org', (t, done) => {
  const mockDb = {
    get: () => [{ metadata: { ssoEnforced: 'true', org: 'bank.com' } }],
  };
  const validUserToken = sso.createSessionToken({ email: 'alice@bank.com', org: 'bank.com' }, testSecret);
  const middleware = sso.authorizeBucketSso(mockDb, mockConfig);
  const req = { params: { sid: 'sec123' }, cookies: { psitransfer_sso: validUserToken }, headers: {} };
  const res = {};

  middleware(req, res, () => {
    assert.equal(req.ssoUser.email, 'alice@bank.com');
    assert.equal(req.ssoUser.org, 'bank.com');
    done();
  });
});
