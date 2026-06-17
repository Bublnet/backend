import fs from 'fs';
import path from 'path';
import { applicationDefault, cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const localServiceAccountPath = path.join(__dirname, 'inventory-management-ce97e-firebase-adminsdk-r6egv-3376080a19.json');
const hasLocalServiceAccount = fs.existsSync(localServiceAccountPath);

const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const base64Json = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

let credential;
if (rawJson || base64Json) {
  credential = cert(JSON.parse(rawJson || Buffer.from(base64Json, 'base64').toString('utf8')));
} else if (hasLocalServiceAccount) {
  const parsed = JSON.parse(fs.readFileSync(localServiceAccountPath, 'utf8'));
  credential = cert(parsed);
} else {
  credential = applicationDefault();
}

const appConfig = {
  credential,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
};
if (!rawJson && !base64Json && !hasLocalServiceAccount && process.env.FIREBASE_PROJECT_ID) {
  appConfig.projectId = process.env.FIREBASE_PROJECT_ID;
}

const app = getApps()[0] || initializeApp(appConfig);

export const db = getFirestore(app);
export const auth = getAuth(app);
export const storage = getStorage(app);

export default app;
