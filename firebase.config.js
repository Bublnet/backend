import { initializeApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';
import { getStorage } from 'firebase/storage';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Your web app's Firebase configuration loaded from environment variables
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
};

// Validate that required config values are present
const requiredKeys = ['apiKey', 'authDomain', 'projectId', 'appId'];
const missingKeys = requiredKeys.filter((key) => !firebaseConfig[key]);

if (missingKeys.length > 0) {
  const envVarNames = missingKeys.map((k) => {
    // Convert camelCase like 'authDomain' -> 'AUTH_DOMAIN'
    const upper = k.replace(/([A-Z])/g, '_$1').toUpperCase();
    return `FIREBASE_${upper}`;
  });
  throw new Error(
    `Missing required Firebase environment variables: ${envVarNames.join(', ')}. ` +
      'Copy .env.example to .env and fill in the values.'
  );
}

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize and export common Firebase services for easy import
export const db = getFirestore(app);
export const auth = getAuth(app);
export const storage = getStorage(app);

// Default export the initialized app
export default app;
