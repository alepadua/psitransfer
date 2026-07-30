const path = require('path');

// Control chars incl. NUL. Keep it strict and cross-platform.
const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/g;

function toSafeBasename(input, fallback = 'file', opts = {}) {
  const maxLength = Number.isInteger(opts.maxLength) ? opts.maxLength : 255;

  let name = '';
  if (typeof input === 'string') name = input;
  else if (input == null) name = '';
  else name = String(input);

  // Remove NUL/control chars early (these can truncate paths in some tooling).
  name = name.replace(CONTROL_CHARS_RE, '');

  // Normalize separators to POSIX then force basename (flat archives).
  name = name.replace(/\\/g, '/');
  name = path.posix.basename(name);

  // Trim to avoid whitespace-only names; keep the caller’s original if they need strict equality.
  name = name.trim();

  // Disallow dot/dotdot and empty.
  if (!name || name === '.' || name === '..') name = '';

  // Length cap.
  if (name.length > maxLength) name = name.slice(0, maxLength);

  if (!name) {
    const fb = (fallback == null ? '' : String(fallback)).replace(CONTROL_CHARS_RE, '').trim();
    return fb ? fb.slice(0, maxLength) : 'file';
  }

  return name;
}

function isSafeBasename(name, opts = {}) {
  if (typeof name !== 'string') return false;
  return toSafeBasename(name, '', opts) === name;
}

// Node randomUUID() v4 shape (case-insensitive).
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Tus resume URL id: exactly one "++", safe bucket sid, UUID key.
 */
function isSafeTusUploadId(uploadId) {
  if (typeof uploadId !== 'string' || uploadId.includes('\0')) return false;
  const parts = uploadId.split('++');
  if (parts.length !== 2) return false;
  const [sid, key] = parts;
  if (!sid || !key) return false;
  return isSafeBasename(sid) && UUID_V4_RE.test(key);
}

/**
 * Bucket-only id (lock PATCH, middleware checks without "++").
 */
function isSafeBucketFid(fid) {
  if (typeof fid !== 'string' || fid.includes('++') || fid.includes('\0')) return false;
  return isSafeBasename(fid);
}

const { createHash, timingSafeEqual } = require('node:crypto');

/**
 * Timing-safe string comparison to prevent timing attacks on password checks.
 * Compares SHA-256 hashes of the inputs so that the comparison is constant-time
 * regardless of input lengths.
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const hashA = createHash('sha256').update(a).digest();
  const hashB = createHash('sha256').update(b).digest();
  return timingSafeEqual(hashA, hashB);
}

function toAsciiFallbackFilename(name, fallback = 'file') {
  const safe = toSafeBasename(name, fallback);
  const normalized = safe.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
  const ascii = normalized.replace(/[^\x20-\x7E]+/g, '').trim();
  const cleaned = ascii.replace(/["\\]/g, '_');
  if (cleaned) return cleaned;
  const fallbackSafe = toSafeBasename(fallback, 'file');
  return fallbackSafe.replace(/[^\x20-\x7E]+/g, '').trim() || 'file';
}

function contentDispositionUtf8Filename(name, fallback = 'file') {
  const safe = toSafeBasename(name, fallback);
  const asciiFallback = toAsciiFallbackFilename(safe, fallback);
  const encoded = encodeURIComponent(safe)
    .replace(/['()]/g, c => `%${ c.charCodeAt(0).toString(16).toUpperCase() }`)
    .replace(/\*/g, '%2A');
  return `attachment; filename="${ asciiFallback }"; filename*=UTF-8''${ encoded }`;
}

function md5Hex(input) {
  return createHash('md5').update(input).digest('hex');
}

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

module.exports = {
  toSafeBasename,
  isSafeBasename,
  isSafeTusUploadId,
  isSafeBucketFid,
  UUID_V4_RE,
  safeCompare,
  toAsciiFallbackFilename,
  contentDispositionUtf8Filename,
  md5Hex,
  sha256Hex,
};


