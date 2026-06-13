import { applicationDefault, cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';
import dotenv from 'dotenv';

dotenv.config();

const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const base64Json = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

const app = getApps()[0] || initializeApp({
  credential: rawJson || base64Json
    ? cert(JSON.parse(rawJson || Buffer.from(base64Json, 'base64').toString('utf8')))
    : applicationDefault(),
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
});

export const db = getFirestore(app);
export const auth = getAuth(app);
export const storage = getStorage(app);

export default app;
