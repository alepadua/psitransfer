const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs/promises');
const express = require('express');

const config = {
  uploadDir: path.join(__dirname, '../tmp/sso-admin-test-uploads'),
  adminPass: 'admin-secret-pass-123',
  ssoEnabled: true,
  ssoSecret: 'test-sso-secret',
  ssoMandatoryOrgs: {
    'static-bank.com': {
      name: 'Static Bank',
      requireSso: true,
    },
  },
  retentions: { '3600': '1 Hour' },
  defaultRetention: '3600',
  baseUrl: '/',
};

// Ensure clean test directory
test.before(async () => {
  await fs.mkdir(config.uploadDir, { recursive: true });
});

test.after(async () => {
  await fs.rm(path.join(__dirname, '../tmp'), { recursive: true, force: true });
});

test('SSO Admin Management APIs (GET, POST, DELETE /admin/sso-orgs.json)', async () => {
  const appConfig = require('../../config');
  appConfig.adminPass = 'admin-secret-pass-123';
  appConfig.ssoEnabled = true;
  appConfig.ssoMandatoryOrgs = {
    'static-bank.com': {
      name: 'Static Bank',
      requireSso: true,
    },
  };

  const app = require('../../lib/endpoints');

  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. GET /config.json should include static-bank.com in availableOrgs
    const cfgRes = await fetch(`${baseUrl}/config.json`);
    const cfgData = await cfgRes.json();
    assert.equal(cfgRes.status, 200);
    assert.equal(cfgData.ssoEnabled, true);
    assert.ok(Array.isArray(cfgData.availableOrgs));
    const staticOrgFound = cfgData.availableOrgs.some((o) => o.domain === 'static-bank.com');
    assert.equal(staticOrgFound, true);

    // 2. GET /admin/sso-orgs.json without admin password header -> 403 Forbidden
    const unauthRes = await fetch(`${baseUrl}/admin/sso-orgs.json`);
    assert.equal(unauthRes.status, 403);

    // 3. GET /admin/sso-orgs.json with valid x-passwd -> 200 OK
    const authRes = await fetch(`${baseUrl}/admin/sso-orgs.json`, {
      headers: { 'x-passwd': 'admin-secret-pass-123' },
    });
    assert.equal(authRes.status, 200);
    const orgsData = await authRes.json();
    assert.ok(orgsData['static-bank.com']);

    // 4. POST /admin/sso-orgs.json to add a new Org (new-corp.com)
    const postRes = await fetch(`${baseUrl}/admin/sso-orgs.json`, {
      method: 'POST',
      headers: {
        'x-passwd': 'admin-secret-pass-123',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        domain: 'new-corp.com',
        name: 'New Enterprise Corp',
        requireSso: true,
        issuerUrl: 'https://auth.new-corp.com',
        clientId: 'psitransfer-client',
      }),
    });
    assert.equal(postRes.status, 200);
    const createdOrg = await postRes.json();
    assert.equal(createdOrg.domain, 'new-corp.com');
    assert.equal(createdOrg.name, 'New Enterprise Corp');

    // 5. GET /config.json should now include new-corp.com
    const cfgRes2 = await fetch(`${baseUrl}/config.json`);
    const cfgData2 = await cfgRes2.json();
    const newOrgFound = cfgData2.availableOrgs.some((o) => o.domain === 'new-corp.com');
    assert.equal(newOrgFound, true);

    // 6. DELETE /admin/sso-orgs/new-corp.com -> 204 No Content
    const delRes = await fetch(`${baseUrl}/admin/sso-orgs/new-corp.com`, {
      method: 'DELETE',
      headers: { 'x-passwd': 'admin-secret-pass-123' },
    });
    assert.equal(delRes.status, 204);

    // 7. GET /config.json should no longer include new-corp.com
    const cfgRes3 = await fetch(`${baseUrl}/config.json`);
    const cfgData3 = await cfgRes3.json();
    const removedOrgFound = cfgData3.availableOrgs.some((o) => o.domain === 'new-corp.com');
    assert.equal(removedOrgFound, false);
  } finally {
    server.close();
  }
});
