import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ADMIN_TOKEN_PATTERN,
  createAdminToken,
  createScryptPasswordHash,
  extractTokenizedApiPath,
  hashAdminToken,
  isAdminIdentifier,
  verifyAdminPassword,
} from '../admin-auth.js';

test('admin identifiers are normalized and compared safely', () => {
  assert.equal(isAdminIdentifier(' Admin@Dvenue.com ', 'admin@dvenue.com'), true);
  assert.equal(isAdminIdentifier('attacker@dvenue.com', 'admin@dvenue.com'), false);
});

test('scrypt admin password hashes verify without storing the password', async () => {
  const hash = createScryptPasswordHash('correct horse battery staple');
  assert.equal(await verifyAdminPassword('correct horse battery staple', { passwordHash: hash }), true);
  assert.equal(await verifyAdminPassword('wrong', { passwordHash: hash }), false);
});

test('admin tokens are unique, URL safe, and hashed deterministically', () => {
  const first = createAdminToken();
  const second = createAdminToken();
  assert.match(first, ADMIN_TOKEN_PATTERN);
  assert.notEqual(first, second);
  assert.equal(hashAdminToken(first), hashAdminToken(first));
  assert.notEqual(hashAdminToken(first), hashAdminToken(second));
});

test('tokenized API paths are rewritten without accepting malformed tokens', () => {
  const token = createAdminToken();
  assert.deepEqual(extractTokenizedApiPath(`/api/${token}/admin/listings`), {
    token,
    rewrittenPath: '/api/admin/listings',
  });
  assert.equal(extractTokenizedApiPath('/api/asdf_short/admin/listings'), null);
});
