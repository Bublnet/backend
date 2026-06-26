import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeRole, validRoles } from '../supabase.client.js';

test('Supabase roles are limited to the five supported application roles', () => {
  assert.deepEqual(
    [...validRoles].sort(),
    ['admin', 'client', 'host', 'hoststaff', 'staff'],
  );
  assert.equal(normalizeRole('HOST'), 'host');
  assert.equal(normalizeRole('manager'), 'client');
  assert.equal(normalizeRole(null), 'client');
});
