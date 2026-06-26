import { createScryptPasswordHash } from '../admin-auth.js';

const password = process.argv[2];
if (!password) {
  console.error('Usage: npm run admin:hash-password -- "your strong password"');
  process.exit(1);
}

console.log(createScryptPasswordHash(password));
