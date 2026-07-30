const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs/promises');

const SsoStore = require('../../lib/ssoStore');
const sso = require('../../lib/sso');
const oidc = require('../../lib/oidc');
const cryptoStore = require('../../lib/cryptoStore');

test('Domain Validation (ssoStore.isValidDomain)', () => {
  const store = new SsoStore(path.join(__dirname, '../tmp/sso-test-domain'));

  assert.equal(store.isValidDomain('bank.com'), true);
  assert.equal(store.isValidDomain('sub.domain.company.com.br'), true);

  assert.equal(store.isValidDomain('invalid_domain'), false);
  assert.equal(store.isValidDomain('http://bank.com'), false);
  assert.equal(store.isValidDomain(''), false);
  assert.equal(store.isValidDomain(null), false);
});

test('OIDC PKCE and State Token Helpers', () => {
  const verifier = oidc.generateCodeVerifier();
  assert.ok(verifier.length >= 43);

  const challenge = oidc.generateCodeChallenge(verifier);
  assert.ok(challenge && typeof challenge === 'string');

  const state = oidc.generateStateToken();
  assert.ok(state && state.length >= 20);

  const authUrl = oidc.buildAuthorizationUrl(
    {
      issuerUrl: 'https://auth.company.com',
      clientId: 'psi-app',
    },
    {
      redirectUri: 'https://psi.company.com/auth/sso/callback',
      state,
      codeChallenge: challenge,
    }
  );

  assert.ok(authUrl.includes('response_type=code'));
  assert.ok(authUrl.includes('client_id=psi-app'));
  assert.ok(authUrl.includes('code_challenge_method=S256'));
});

test('AES-256-GCM Storage Encryption & Decryption Stream Helper', () => {
  const password = 'my-super-secret-key-123';
  const { cipher, salt, iv } = cryptoStore.createEncryptionStream(password);

  const inputBuffer = Buffer.from('PsiTransfer Encrypted File Payload Sample');
  const encryptedChunk = cipher.update(inputBuffer);
  const finalChunk = cipher.final();
  const encrypted = Buffer.concat([encryptedChunk, finalChunk]);
  const authTag = cipher.getAuthTag();

  const decipher = cryptoStore.createDecryptionStream(password, salt, iv, authTag);
  const decryptedChunk = decipher.update(encrypted);
  const decryptedFinal = decipher.final();
  const decrypted = Buffer.concat([decryptedChunk, decryptedFinal]);

  assert.equal(decrypted.toString('utf8'), 'PsiTransfer Encrypted File Payload Sample');
});
