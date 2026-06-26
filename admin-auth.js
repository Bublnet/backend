import crypto from 'crypto';

export const ADMIN_TOKEN_PREFIX = 'asdf_';
export const ADMIN_TOKEN_PATTERN = /^asdf_[A-Za-z0-9_-]{43}$/;

export function normalizeAdminIdentifier(value) {
  return String(value || '').trim().toLowerCase();
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  if (leftBuffer.length !== rightBuffer.length) {
    crypto.timingSafeEqual(leftBuffer, leftBuffer);
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function isAdminIdentifier(identifier, configuredIdentifier) {
  const candidate = normalizeAdminIdentifier(identifier);
  const configured = normalizeAdminIdentifier(configuredIdentifier);
  return Boolean(candidate && configured && safeEqual(candidate, configured));
}

export async function verifyAdminPassword(password, { passwordHash, passwordPlain } = {}) {
  const candidate = String(password || '');

  if (passwordHash) {
    const [scheme, saltEncoded, expectedEncoded] = String(passwordHash).split('$');
    if (scheme !== 'scrypt' || !saltEncoded || !expectedEncoded) return false;

    try {
      const salt = Buffer.from(saltEncoded, 'base64url');
      const expected = Buffer.from(expectedEncoded, 'base64url');
      if (expected.length < 32 || expected.length > 128) return false;
      const actual = await new Promise((resolve, reject) => {
        crypto.scrypt(candidate, salt, expected.length, (error, key) => {
          if (error) reject(error);
          else resolve(key);
        });
      });
      return crypto.timingSafeEqual(actual, expected);
    } catch (_) {
      return false;
    }
  }

  return Boolean(passwordPlain && safeEqual(candidate, passwordPlain));
}

export function createAdminToken() {
  return `${ADMIN_TOKEN_PREFIX}${crypto.randomBytes(32).toString('base64url')}`;
}

export function hashAdminToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

export function extractTokenizedApiPath(pathname) {
  const match = String(pathname || '').match(/^\/api\/(asdf_[A-Za-z0-9_-]{43})(\/.*)$/);
  if (!match) return null;
  return { token: match[1], rewrittenPath: `/api${match[2]}` };
}

export function createScryptPasswordHash(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}
