const { createCipheriv, createDecipheriv, randomBytes, scryptSync } = require('node:crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV for GCM

/**
 * Derives a 32-byte cryptographic key from a secret or password and salt.
 */
function deriveKey(password, salt) {
  return scryptSync(password, salt, 32);
}

/**
 * Creates an AES-256-GCM cipher stream with randomly generated salt and IV.
 */
function createEncryptionStream(password) {
  const salt = randomBytes(16);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  return {
    cipher,
    salt,
    iv,
    getAuthTag: () => cipher.getAuthTag(),
  };
}

/**
 * Creates an AES-256-GCM decipher stream given key parameters.
 */
function createDecryptionStream(password, salt, iv, authTag) {
  const key = deriveKey(password, salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return decipher;
}

module.exports = {
  deriveKey,
  createEncryptionStream,
  createDecryptionStream,
};
