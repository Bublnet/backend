import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { applicationDefault, cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { FieldValue, getFirestore } from 'firebase-admin/firestore';
import helmet from 'helmet';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const localServiceAccountPath = path.join(__dirname, 'inventory-management-ce97e-firebase-adminsdk-r6egv-3376080a19.json');
const hasLocalServiceAccount = fs.existsSync(localServiceAccountPath);

const app = express();
const PORT = process.env.PORT || 4000;
const PAYMENTS_URL = process.env.PAYMENTS_SERVICE_URL || 'http://localhost:4001';
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY;
const DEFAULT_ADMIN_EMAIL = process.env.DEFAULT_ADMIN_EMAIL;
const AUTH_OTP_TTL_MS = Number(process.env.AUTH_OTP_TTL_MS || 10 * 60 * 1000);
const authBaseUrl = `https://identitytoolkit.googleapis.com/v1/accounts`;

// Defaults set for current "simulate OTP, google removed" mode. Override via .env
const ENABLE_OTP_VERIFY = (process.env.ENABLE_OTP_VERIFY || 'false').toLowerCase() === 'true';
const ENABLE_GOOGLE_SIGNIN = (process.env.ENABLE_GOOGLE_SIGNIN || 'false').toLowerCase() === 'true';

const hasFirebaseServerCredentials = Boolean(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    || process.env.FIREBASE_SERVICE_ACCOUNT_BASE64
    || process.env.GOOGLE_APPLICATION_CREDENTIALS
    || process.env.K_SERVICE
    || hasLocalServiceAccount,
);

function initFirebaseAdmin() {
  if (getApps().length) return getApps()[0];

  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const base64Json = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

  let credential;
  if (rawJson || base64Json) {
    const parsed = JSON.parse(
      rawJson || Buffer.from(base64Json, 'base64').toString('utf8'),
    );
    credential = cert(parsed);
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

  return initializeApp(appConfig);
}

initFirebaseAdmin();

const db = getFirestore();
const auth = getAuth();

function assertFirebaseServerConfigured() {
  if (hasFirebaseServerCredentials) return;
  const error = new Error(
    'Firebase server credentials are required. Set GOOGLE_APPLICATION_CREDENTIALS (path to your service-account.json), FIREBASE_SERVICE_ACCOUNT_JSON, or FIREBASE_SERVICE_ACCOUNT_BASE64.',
  );
  error.status = 503;
  throw error;
}

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.set('trust proxy', 1);

// CORS early (before helmet/json) so that preflight for authenticated cross-origin calls
// (Flutter web on :8080 talking to either backend) receive ACAO + credentials headers.
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    // Robust localhost support for Flutter web dev (any port like 8080)
    if (/^https?:\/\/(localhost|127\.0\.0\.1|::1)(:\d+)?$/.test(origin) || origin.includes('localhost')) {
      return callback(null, true);
    }

    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
  optionsSuccessStatus: 200,
}));
app.options('*', cors());

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '2mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT || 30),
  standardHeaders: true,
  legacyHeaders: false,
});

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.WRITE_RATE_LIMIT || 120),
  standardHeaders: true,
  legacyHeaders: false,
});

function nowIso() {
  return new Date().toISOString();
}

function normalizeIdentifier(value) {
  return String(value || '').trim().toLowerCase();
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function requireString(value, field) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    const error = new Error(`${field} is required.`);
    error.status = 400;
    throw error;
  }
  return normalized;
}

function clampInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function publicUser(profile) {
  return {
    id: profile.id,
    name: profile.name || 'Dvenue User',
    identifier: profile.identifier || profile.email || '',
    role: profile.role || 'client',
    isPremium: profile.isPremium === true || profile.is_premium === true,
    adAccessUntil: profile.adAccessUntil || profile.ad_access_until || null,
  };
}

function isStaffRole(role) {
  return ['admin', 'manager', 'support', 'reviewer'].includes(role);
}

async function getUserProfile(uid) {
  assertFirebaseServerConfigured();
  const snap = await db.collection('users').doc(uid).get();
  if (!snap.exists) return null;
  return { id: uid, ...snap.data() };
}

async function ensureUserProfile(uid, fallback = {}) {
  assertFirebaseServerConfigured();
  const ref = db.collection('users').doc(uid);
  const snap = await ref.get();
  const existing = snap.exists ? snap.data() : {};
  const email = fallback.email || existing.email || '';
  const role = existing.role || (email && email === DEFAULT_ADMIN_EMAIL ? 'admin' : 'client');
  const profile = {
    name: existing.name || fallback.name || (email ? email.split('@')[0] : 'Dvenue User'),
    identifier: existing.identifier || fallback.identifier || email,
    email,
    role,
    isPremium: existing.isPremium === true || existing.is_premium === true,
    adAccessUntil: existing.adAccessUntil || existing.ad_access_until || null,
    updatedAt: nowIso(),
    ...(snap.exists ? {} : { createdAt: nowIso() }),
  };
  await ref.set(profile, { merge: true });
  return { id: uid, ...existing, ...profile };
}

async function requireAuth(req, res, next) {
  try {
    assertFirebaseServerConfigured();
    const header = req.get('authorization') || '';
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return res.status(401).json({ ok: false, message: 'Missing bearer token.' });
    }

    const decoded = await auth.verifyIdToken(match[1], true);
    const profile = await ensureUserProfile(decoded.uid, {
      email: decoded.email,
      identifier: decoded.email || decoded.phone_number,
      name: decoded.name,
    });
    req.auth = { token: match[1], decoded, user: publicUser(profile), profile };
    return next();
  } catch (error) {
    if (error.status) {
      return res.status(error.status).json({ ok: false, message: error.message });
    }
    console.error('Auth verification failed:', error.message);
    return res.status(401).json({ ok: false, message: 'Session expired. Please login again.' });
  }
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.user.role)) {
      return res.status(403).json({ ok: false, message: 'You do not have access to this action.' });
    }
    return next();
  };
}

const requireStaff = requireRole(['admin', 'manager', 'support', 'reviewer']);
const requireAdmin = requireRole(['admin']);

async function requireAccess(req, res, next) {
  try {
    // Must be after requireAuth
    if (!req.auth || !req.auth.user) {
      return res.status(401).json({ ok: false, message: 'Authentication required.' });
    }
    const profile = req.auth.profile || {};
    const isPremium = profile.isPremium === true || profile.is_premium === true;
    const adRaw = profile.adAccessUntil || profile.ad_access_until;
    let hasAd = false;
    if (adRaw) {
      const until = typeof adRaw === 'string' ? new Date(adRaw) : (adRaw && adRaw.toDate ? adRaw.toDate() : new Date(adRaw));
      hasAd = until instanceof Date && !Number.isNaN(until.getTime()) && until.getTime() > Date.now();
    }
    const role = req.auth.user.role;
    const isPrivileged = ['admin', 'manager', 'support', 'reviewer'].includes(role);
    if (!isPremium && !hasAd && !isPrivileged) {
      return res.status(402).json({
        ok: false,
        message: 'Premium subscription or ad-supported access required. Watch a short ad to continue or upgrade.',
        code: 'ACCESS_REQUIRED',
        isPremium: false,
        hasAdAccess: false,
      });
    }
    req.access = { isPremium: !!isPremium, hasAdAccess: !!hasAd };
    return next();
  } catch (e) {
    console.error('Access check error', e);
    return res.status(403).json({ ok: false, message: 'Access check failed.' });
  }
}

const requirePremiumOrAd = [requireAuth, requireAccess];

function toListing(doc) {
  const data = doc.data ? doc.data() : doc;
  const id = doc.id || data.id;
  const basePrice = Number(data.basePrice || 0);
  const gstRate = Number(data.gstRate ?? 18);
  const gstAmount = data.gstAmount ?? Math.round(basePrice * (gstRate / 100));
  const priceWithGst = data.priceWithGst ?? basePrice + gstAmount;
  return {
    id,
    name: data.name || '',
    legalBusinessName: data.legalBusinessName || '',
    gstin: data.gstin || null,
    category: data.category || 'venue',
    type: data.type || 'Event Venue',
    location: data.location || '',
    address: data.address || '',
    pincode: data.pincode || '',
    state: data.state || '',
    country: data.country || 'India',
    lat: Number(data.lat || 0),
    lng: Number(data.lng || 0),
    capacity: data.capacity ?? null,
    priceUnit: data.priceUnit || 'daily',
    basePrice,
    gstRate,
    gstAmount,
    priceWithGst,
    priceRange: data.priceRange || formatPriceRange(priceWithGst, data.priceUnit),
    rating: Number(data.rating || 0),
    imageEmoji: data.imageEmoji || 'pin',
    images: Array.isArray(data.images) ? data.images : [],
    thumbnails: Array.isArray(data.thumbnails) ? data.thumbnails : [],
    specTable: data.specTable || { rows: [] },
    status: data.status || 'pending',
    ownerId: data.ownerId || null,
    ownerName: data.ownerName || null,
    submittedAt: data.submittedAt || null,
    verified: data.verified === true,
    verificationStatus: data.verificationStatus || 'pending_contact',
    verificationNotes: data.verificationNotes || null,
    contactedAt: data.contactedAt || null,
    rejectionReason: data.rejectionReason || null,
    approvedAt: data.approvedAt || null,
    updatedAt: data.updatedAt || null,
  };
}

function toBooking(doc) {
  const data = doc.data ? doc.data() : doc;
  return {
    id: doc.id || data.id,
    venueId: data.venueId || null,
    venueName: data.venueName || '',
    customerName: data.customerName || '',
    userId: data.userId || null,
    customerPhone: data.customerPhone || null,
    ownerId: data.ownerId || null,
    ownerName: data.ownerName || null,
    ownerPhone: data.ownerPhone || null,
    venueAddress: data.venueAddress || null,
    amount: Number(data.amount || 0),
    guests: data.guests ?? null,
    status: data.status || 'pending',
    paymentStatus: data.paymentStatus || 'unpaid',
    ticketCode: data.ticketCode || null,
    ticketImage: data.ticketImage || null,
    verificationToken: data.verificationToken || null,
    qrPayload: data.qrPayload || null,
    ownerVerifiedAt: data.ownerVerifiedAt || null,
    bookedAt: data.bookedAt || '',
    eventDate: data.eventDate || '',
    paidAt: data.paidAt || null,
    confirmedAt: data.confirmedAt || null,
  };
}

function formatPriceRange(value, unit = 'daily') {
  if (!value) return '';
  const suffix = unit === 'hourly' ? 'hour' : 'day';
  return `Rs ${Math.round(value)}/${suffix}`;
}

function distanceKm(aLat, aLng, bLat, bLng) {
  const toRad = (degrees) => degrees * Math.PI / 180;
  const earthKm = 6371;
  const dLat = toRad(bLat - aLat);
  const dLng = toRad(bLng - aLng);
  const lat1 = toRad(aLat);
  const lat2 = toRad(bLat);
  const hav = Math.sin(dLat / 2) ** 2
    + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 2 * earthKm * Math.asin(Math.sqrt(hav));
}

async function listVenues({ includeAll = false } = {}) {
  assertFirebaseServerConfigured();
  let query = db.collection('venues');
  if (!includeAll) query = query.where('status', '==', 'approved');
  const snap = await query.get();
  return snap.docs.map(toListing);
}

function filterVenues(venues, params) {
  const lat = Number(params.lat || 0);
  const lng = Number(params.lng || 0);
  const radiusKm = Number(params.radiusKm || 50);
  const minRating = Number(params.minRating || 0);
  const q = String(params.q || '').trim().toLowerCase();
  const category = String(params.category || '').trim();
  const verifiedOnly = params.verifiedOnly === 'true';

  let results = venues.map((venue) => ({
    ...venue,
    distanceKm: lat && lng ? Number(distanceKm(lat, lng, venue.lat, venue.lng).toFixed(1)) : 0,
  }));

  results = results.filter((venue) => {
    if (lat && lng && venue.distanceKm > radiusKm) return false;
    if (venue.rating < minRating) return false;
    if (category && venue.category !== category) return false;
    if (verifiedOnly && !venue.verified) return false;
    if (q) {
      const haystack = `${venue.name} ${venue.type} ${venue.address} ${venue.location}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });

  switch (params.sortBy) {
    case 'rating':
      results.sort((a, b) => b.rating - a.rating);
      break;
    case 'price':
      results.sort((a, b) => a.priceWithGst - b.priceWithGst);
      break;
    default:
      results.sort((a, b) => a.distanceKm - b.distanceKm);
  }

  return results;
}

async function firebasePasswordRequest(action, payload) {
  if (!FIREBASE_API_KEY) {
    const error = new Error('Firebase API key is not configured.');
    error.status = 500;
    throw error;
  }
  const response = await fetch(`${authBaseUrl}:${action}?key=${FIREBASE_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(mapFirebaseAuthError(data?.error?.message));
    error.status = 400;
    throw error;
  }
  return data;
}

function mapFirebaseAuthError(code) {
  switch (code) {
    case 'EMAIL_EXISTS':
      return 'An account already exists for this email.';
    case 'EMAIL_NOT_FOUND':
    case 'INVALID_PASSWORD':
    case 'INVALID_LOGIN_CREDENTIALS':
      return 'Invalid login credentials.';
    case 'WEAK_PASSWORD : Password should be at least 6 characters':
    case 'WEAK_PASSWORD':
      return 'Password must be at least 6 characters.';
    default:
      return 'Authentication failed.';
  }
}

async function googleIdentityToolkit(idToken) {
  if (!FIREBASE_API_KEY) {
    const error = new Error('Firebase API key is not configured.');
    error.status = 500;
    throw error;
  }
  const response = await fetch(`${authBaseUrl}:signInWithIdp?key=${FIREBASE_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      postBody: `id_token=${encodeURIComponent(idToken)}&providerId=google.com`,
      requestUri: 'http://localhost',
      returnSecureToken: true,
    }),
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(mapFirebaseAuthError(data?.error?.message) || 'Google sign-in failed.');
    error.status = 400;
    throw error;
  }
  return data;
}

async function handleError(res, error) {
  console.error(error);
  return res.status(error.status || 500).json({
    ok: false,
    message: error.status ? error.message : 'Internal server error.',
  });
}

app.get('/health', async (req, res) => {
  let paymentsHealth = 'unknown';
  try {
    const response = await fetch(`${PAYMENTS_URL}/health`, { signal: AbortSignal.timeout(3000) });
    paymentsHealth = response.ok ? 'ok' : 'unhealthy';
  } catch (_) {
    paymentsHealth = 'unreachable';
  }

  res.json({
    status: 'ok',
    service: 'dvenue-backend',
    firebaseProject: process.env.FIREBASE_PROJECT_ID || 'not-configured',
    paymentsService: PAYMENTS_URL,
    paymentsHealth,
  });
});

app.get('/api/config/public', (req, res) => {
  res.json({
    ok: true,
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || null,
    enableOtpVerify: ENABLE_OTP_VERIFY,
    enableGoogleSignin: ENABLE_GOOGLE_SIGNIN,
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const profile = req.auth.profile || {};
  const isPremium = profile.isPremium === true || profile.is_premium === true;
  const adRaw = profile.adAccessUntil || profile.ad_access_until;
  let adAccessUntil = null;
  if (adRaw) {
    const d = typeof adRaw === 'string' ? new Date(adRaw) : (adRaw && adRaw.toDate ? adRaw.toDate() : new Date(adRaw));
    if (d instanceof Date && !Number.isNaN(d.getTime())) adAccessUntil = d.toISOString();
  }
  const role = req.auth.user.role;
  const hasAccess = isPremium || ['admin', 'manager', 'support', 'reviewer'].includes(role) || (adAccessUntil && new Date(adAccessUntil).getTime() > Date.now());
  res.json({
    ok: true,
    data: {
      token: req.auth.token,
      user: req.auth.user,
      access: {
        isPremium: !!isPremium,
        adAccessUntil,
        hasAccess: !!hasAccess,
      },
    },
  });
});

// Profiles (support SessionStore.getManualLocation + saveManualLocation + other profile reads)
app.get('/api/profiles/me', requireAuth, async (req, res) => {
  try {
    const profile = req.auth.profile || {};
    const manualLoc = profile.manualLocation || profile.manual_location || null;
    res.json({
      ok: true,
      data: {
        user: publicUser(profile),
        manual_location: manualLoc,
      },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.patch('/api/profiles/me/location', requireAuth, async (req, res) => {
  try {
    const loc = req.body && (req.body.manual_location || req.body.manualLocation || null);
    const ref = db.collection('users').doc(req.auth.user.id);
    await ref.set({
      manualLocation: loc,
      manual_location: loc,
      updatedAt: nowIso(),
    }, { merge: true });
    res.json({ ok: true, message: 'Location preference saved.' });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    const password = requireString(req.body.password, 'Password');
    if (!isEmail(identifier)) {
      return res.status(400).json({ ok: false, message: 'Email login is required for Firebase auth.' });
    }

    const login = await firebasePasswordRequest('signInWithPassword', {
      email: identifier,
      password,
      returnSecureToken: true,
    });
    const profile = await ensureUserProfile(login.localId, {
      email: login.email,
      identifier: login.email,
    });

    res.json({
      ok: true,
      message: 'Welcome to Dvenue.',
      data: { token: login.idToken, user: publicUser(profile) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/google', authLimiter, async (req, res) => {
  if (!ENABLE_GOOGLE_SIGNIN) {
    return res.status(400).json({ ok: false, message: 'Google sign-in is currently disabled.' });
  }
  try {
    const idToken = requireString(req.body.idToken, 'Google ID token');
    const signIn = await googleIdentityToolkit(idToken);
    const profile = await ensureUserProfile(signIn.localId, {
      email: signIn.email,
      identifier: signIn.email,
      name: signIn.displayName || (signIn.email ? signIn.email.split('@')[0] : 'Google User'),
    });
    res.json({
      ok: true,
      message: 'Signed in with Google.',
      data: { token: signIn.idToken, user: publicUser(profile) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  if (ENABLE_OTP_VERIFY) {
    return res.status(400).json({ ok: false, message: 'OTP verification is enabled. Use signup start and complete endpoints.' });
  }
  try {
    assertFirebaseServerConfigured();
    const identifier = normalizeIdentifier(req.body.identifier);
    if (!isEmail(identifier)) {
      return res.status(400).json({ ok: false, message: 'Email signup is required.' });
    }
    const password = requireString(req.body.password, 'Password');

    const signup = await firebasePasswordRequest('signUp', {
      email: identifier,
      password,
      returnSecureToken: true,
    });
    const profile = await ensureUserProfile(signup.localId, {
      email: signup.email,
      identifier: signup.email,
    });

    res.json({
      ok: true,
      message: 'Account created.',
      data: { token: signup.idToken, user: publicUser(profile) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/signup/start', authLimiter, async (req, res) => {
  if (!ENABLE_OTP_VERIFY) {
    return res.status(400).json({ ok: false, message: 'OTP verification is disabled. Use direct signup.' });
  }
  try {
    assertFirebaseServerConfigured();
    const identifier = normalizeIdentifier(req.body.identifier);
    if (!isEmail(identifier)) {
      return res.status(400).json({ ok: false, message: 'Email signup is required.' });
    }

    const otp = process.env.AUTH_DEV_OTP || String(crypto.randomInt(100000, 999999));
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
    await db.collection('authOtps').doc(identifier).set({
      identifier,
      otpHash,
      purpose: 'signup',
      expiresAt: Date.now() + AUTH_OTP_TTL_MS,
      attempts: 0,
      createdAt: nowIso(),
    });

    res.json({
      ok: true,
      message: 'Verification code generated.',
      data: process.env.AUTH_RETURN_OTP === 'true' ? { otp } : {},
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/signup/complete', authLimiter, async (req, res) => {
  try {
    assertFirebaseServerConfigured();
    const identifier = normalizeIdentifier(req.body.identifier);
    const otp = requireString(req.body.otp, 'OTP');
    const password = requireString(req.body.password, 'Password');
    const ref = db.collection('authOtps').doc(identifier);
    const snap = await ref.get();
    const record = snap.data();
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

    if (!snap.exists || record.purpose !== 'signup' || record.expiresAt < Date.now() || record.otpHash !== otpHash) {
      return res.status(400).json({ ok: false, message: 'Invalid or expired OTP.' });
    }

    const signup = await firebasePasswordRequest('signUp', {
      email: identifier,
      password,
      returnSecureToken: true,
    });
    await ref.delete();
    const profile = await ensureUserProfile(signup.localId, {
      email: signup.email,
      identifier: signup.email,
    });

    res.json({
      ok: true,
      message: 'Account created.',
      data: { token: signup.idToken, user: publicUser(profile) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/password-reset/start', authLimiter, async (req, res) => {
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    await firebasePasswordRequest('sendOobCode', {
      requestType: 'PASSWORD_RESET',
      email: identifier,
    });
    res.json({ ok: true, message: 'Password reset email sent.' });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/password-reset/verify', authLimiter, (req, res) => {
  res.json({ ok: true, message: 'Use the Firebase reset email to complete password reset.' });
});

app.post('/api/auth/password-reset/complete', authLimiter, (req, res) => {
  res.status(400).json({ ok: false, message: 'Password reset must be completed from the Firebase reset email.' });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.json({ ok: true, message: 'Logged out.' });
});

// Validate existing session token (if not expired/revoked, serve the profile + token back).
// Used by clients that have a stored token from previous login.
app.post('/api/auth/validate', authLimiter, async (req, res) => {
  try {
    const token = (req.body && req.body.token) || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) {
      return res.status(400).json({ ok: false, message: 'Token required.' });
    }
    const decoded = await auth.verifyIdToken(token, true);
    const profile = await getUserProfile(decoded.uid);
    res.json({
      ok: true,
      message: 'Session valid.',
      data: {
        token,
        user: publicUser(profile),
        expiresAt: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null,
      },
    });
  } catch (error) {
    return res.status(401).json({ ok: false, message: 'Session token expired or invalid. Please sign in again.' });
  }
});

app.get('/api/venues/explore', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    const venues = filterVenues(await listVenues(), req.query);
    res.json({
      ok: true,
      message: 'Venues loaded.',
      region: 'Your Region',
      venues: venues.slice(0, 6),
      nearby: venues,
      all: venues,
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/search', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 8, 1, 50);
    const results = filterVenues(await listVenues(), req.query).slice(0, limit);
    res.json({ ok: true, message: 'Search complete.', results });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/mine', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    const snap = await db.collection('venues').where('ownerId', '==', req.auth.user.id).get();
    res.json({ ok: true, message: 'Listings loaded.', listings: snap.docs.map(toListing) });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/admin/pending', requireAuth, requireStaff, async (req, res) => {
  try {
    // Admin backend fetches pending data from clientbackend (as per architecture:
    // clients submit only to clientbackend for pending; admin verifies then "pushes"
    // by status update in shared store, or in future separate project).
    // This ensures client data for verification is isolated at write time.
    const clientResp = await fetch('http://localhost:4002/api/venues/admin/pending', {
      headers: {
        'Authorization': req.headers.authorization || '',
        'Content-Type': 'application/json',
      },
    });
    const data = await clientResp.json();
    if (!clientResp.ok || data.ok === false) {
      return res.status(502).json({ ok: false, message: data.message || 'Failed to fetch pending from clientbackend.' });
    }
    res.json(data);
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/:venueId/availability', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    assertFirebaseServerConfigured();
    const year = clampInt(req.query.year, new Date().getFullYear(), 2020, 2100);
    const month = clampInt(req.query.month, new Date().getMonth() + 1, 1, 12);
    const prefix = `${year}-${String(month).padStart(2, '0')}`;
    const snap = await db.collection('bookings')
      .where('venueId', '==', req.params.venueId)
      .where('eventDate', '>=', `${prefix}-01`)
      .where('eventDate', '<=', `${prefix}-31`)
      .get();
    const booked = new Set(snap.docs
      .map((doc) => toBooking(doc))
      .filter((booking) => ['pending', 'confirmed'].includes(booking.status))
      .map((booking) => booking.eventDate));
    const daysInMonth = new Date(year, month, 0).getDate();
    const days = Array.from({ length: daysInMonth }, (_, i) => {
      const date = `${prefix}-${String(i + 1).padStart(2, '0')}`;
      return { date, booked: booked.has(date), available: !booked.has(date) };
    });
    res.json({ ok: true, venueId: req.params.venueId, year, month, days });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/:id', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    const snap = await db.collection('venues').doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ ok: false, message: 'Listing not found.' });
    const listing = toListing(snap);
    if (listing.status !== 'approved') {
      return res.status(404).json({ ok: false, message: 'Listing not found.' });
    }
    return res.json({ ok: true, listing });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/venues', requireAuth, writeLimiter, async (req, res) => {
  try {
    // Legacy/internal. Normal client submissions go exclusively to clientbackend (pending writes).
    // Admin fetches pending from clientbackend (see /api/venues/admin/pending proxy), verifies,
    // then status update here promotes to the main backend store (only admin writes).
    const payload = listingPayload(req.body, req.auth.user, true);
    const ref = await db.collection('venues').add(payload);
    const snap = await ref.get();
    res.status(201).json({ ok: true, message: 'Listing submitted for admin review.', listing: toListing(snap) });
  } catch (error) {
    return handleError(res, error);
  }
});

app.put('/api/venues/:id', requireAuth, requirePremiumOrAd, writeLimiter, async (req, res) => {
  try {
    const ref = db.collection('venues').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ ok: false, message: 'Listing not found.' });
    const existing = snap.data();
    if (existing.ownerId !== req.auth.user.id && !isStaffRole(req.auth.user.role)) {
      return res.status(403).json({ ok: false, message: 'You do not own this listing.' });
    }
    await ref.set(listingPayload(req.body, req.auth.user, false), { merge: true });
    const updated = await ref.get();
    res.json({ ok: true, message: 'Listing updated and sent for review again.', listing: toListing(updated) });
  } catch (error) {
    return handleError(res, error);
  }
});

app.delete('/api/venues/:id', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    const ref = db.collection('venues').doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ ok: false, message: 'Listing not found.' });
    const existing = snap.data();
    if (existing.ownerId !== req.auth.user.id && req.auth.user.role !== 'admin') {
      return res.status(403).json({ ok: false, message: 'You do not own this listing.' });
    }
    await ref.delete();
    res.json({ ok: true, message: 'Listing removed.' });
  } catch (error) {
    return handleError(res, error);
  }
});

function listingPayload(body, user, isCreate) {
  const basePrice = Number(body.basePrice || 0);
  const gstRate = Number(body.gstRate ?? 18);
  const gstAmount = Math.round(basePrice * (gstRate / 100));
  return {
    name: requireString(body.name, 'Listing name'),
    legalBusinessName: String(body.legalBusinessName || '').trim(),
    gstin: body.gstin ? String(body.gstin).trim() : null,
    category: String(body.category || 'venue').trim(),
    type: String(body.type || 'Event Venue').trim(),
    location: String(body.location || '').trim(),
    address: requireString(body.address, 'Address'),
    pincode: String(body.pincode || '').trim(),
    state: String(body.state || '').trim(),
    country: String(body.country || 'India').trim(),
    lat: Number(body.lat || 0),
    lng: Number(body.lng || 0),
    capacity: body.capacity == null ? null : Number(body.capacity),
    priceUnit: String(body.priceUnit || 'daily').trim(),
    basePrice,
    gstRate,
    gstAmount,
    priceWithGst: basePrice + gstAmount,
    priceRange: formatPriceRange(basePrice + gstAmount, body.priceUnit),
    rating: Number(body.rating || 0),
    imageEmoji: String(body.imageEmoji || 'pin'),
    images: Array.isArray(body.images) ? body.images.slice(0, 12).map(String) : [],
    thumbnails: Array.isArray(body.thumbnails) ? body.thumbnails.slice(0, 12).map(String) : [],
    specTable: body.specTable || { rows: [] },
    status: 'pending',
    verified: false,
    verificationStatus: 'pending_contact',
    submittedAt: body.submittedAt || undefined,
    updatedAt: nowIso(),
    ...(isCreate ? { ownerId: user.id, ownerName: user.name, createdAt: nowIso() } : {}),
  };
}

app.post('/api/venues/admin/:id/approve', requireAuth, requireStaff, async (req, res) => {
  await reviewListing(req, res, true);
});

app.post('/api/venues/admin/:id/reject', requireAuth, requireStaff, async (req, res) => {
  await reviewListing(req, res, false);
});

async function reviewListing(req, res, approve) {
  try {
    const ref = db.collection('venues').doc(req.params.id);
    const update = approve
      ? { status: 'approved', verified: true, verificationStatus: 'approved', approvedAt: nowIso() }
      : { status: 'rejected', verified: false, verificationStatus: 'rejected', rejectionReason: req.body.reason || 'Rejected' };
    await ref.set({ ...update, reviewedBy: req.auth.user.id, updatedAt: nowIso() }, { merge: true });
    const snap = await ref.get();
    // Per architecture: client submitted full data (incl. CDN URLs, per-space pricing/specs) ONLY to clientbackend.
    // Admin backend fetched the pending from clientbackend. On approve we update status here (shared store)
    // so the verified data is now in "backend" (approved for reads by premium/ad users).
    // Only admin/staff can write approved data this way. Clients cannot modify it.
    res.json({ ok: true, message: approve ? 'Listing approved.' : 'Listing rejected.', listing: toListing(snap) });
  } catch (error) {
    return handleError(res, error);
  }
}

app.post('/api/admin/listings/:id/mark-contacted', requireAuth, requireStaff, async (req, res) => {
  await updateListingVerification(req, res, 'contacted', 'Listing marked as contacted.');
});

app.post('/api/admin/listings/:id/verify-details', requireAuth, requireStaff, async (req, res) => {
  await updateListingVerification(req, res, 'details_verified', 'Business details verified.');
});

async function updateListingVerification(req, res, status, message) {
  try {
    const ref = db.collection('venues').doc(req.params.id);
    await ref.set({
      verificationStatus: status,
      verificationNotes: req.body.notes || null,
      contactedAt: status === 'contacted' ? nowIso() : FieldValue.delete(),
      updatedAt: nowIso(),
    }, { merge: true });
    const snap = await ref.get();
    res.json({ ok: true, message, listing: toListing(snap) });
  } catch (error) {
    return handleError(res, error);
  }
}

app.get('/api/bookings/mine', requireAuth, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 12, 1, 50);
    const snap = await db.collection('bookings')
      .where('userId', '==', req.auth.user.id)
      .limit(limit)
      .get();

    // Sort client-side to avoid needing composite index for where+orderBy in all envs
    const bookings = snap.docs
      .map((d) => ({ doc: d, data: toBooking(d) }))
      .sort((a, b) => {
        const ta = a.data.bookedAt ? new Date(a.data.bookedAt).getTime() : 0;
        const tb = b.data.bookedAt ? new Date(b.data.bookedAt).getTime() : 0;
        return tb - ta;
      })
      .slice(0, limit)
      .map((x) => x.data);

    res.json({ ok: true, message: 'Bookings loaded.', bookings });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/bookings', requireAuth, requirePremiumOrAd, writeLimiter, async (req, res) => {
  try {
    const venueId = requireString(req.body.venueId, 'Venue');
    const eventDate = requireString(req.body.eventDate, 'Event date');
    const venueSnap = await db.collection('venues').doc(venueId).get();
    if (!venueSnap.exists) return res.status(404).json({ ok: false, message: 'Venue not found.' });
    const venue = toListing(venueSnap);
    if (venue.status !== 'approved') return res.status(400).json({ ok: false, message: 'Venue is not bookable yet.' });

    const duplicate = await db.collection('bookings')
      .where('venueId', '==', venueId)
      .where('eventDate', '==', eventDate)
      .where('status', 'in', ['pending', 'confirmed'])
      .limit(1)
      .get();
    if (!duplicate.empty) {
      return res.status(409).json({ ok: false, message: 'This date is already reserved.' });
    }

    // Restrict more than 5 bookings a day per user (to prevent abuse)
    const now = new Date();
    const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
    const todayCount = await db.collection('bookings')
      .where('userId', '==', req.auth.user.id)
      .where('bookedAt', '>=', dayStart.toISOString())
      .where('bookedAt', '<', dayEnd.toISOString())
      .get();
    if (todayCount.size >= 5) {
      return res.status(429).json({ ok: false, message: 'You cannot create more than 5 bookings per day.' });
    }

    const ref = await db.collection('bookings').add({
      venueId,
      venueName: venue.name,
      customerName: req.auth.user.name,
      userId: req.auth.user.id,
      customerPhone: req.body.customerPhone || null,
      ownerId: venue.ownerId,
      ownerName: venue.ownerName,
      venueAddress: venue.address,
      amount: venue.priceWithGst || venue.basePrice || 0,
      guests: req.body.guests == null ? null : Number(req.body.guests),
      status: 'pending',
      paymentStatus: 'unpaid',
      bookedAt: nowIso(),
      eventDate,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    });
    const snap = await ref.get();
    res.status(201).json({
      ok: true,
      message: 'Booking enquiry created. Complete payment to reserve your date.',
      booking: toBooking(snap),
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/bookings/:bookingId/send-whatsapp', requireAuth, async (req, res) => {
  try {
    const booking = await getOwnedBooking(req.params.bookingId, req.auth.user);
    res.json({ ok: true, message: 'Ticket is ready. Use Share on your pass to send via WhatsApp.', booking });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/venues/owner/bookings/verify-scan', requireAuth, requireStaff, async (req, res) => {
  try {
    const bookingId = req.body.bookingId || parseQrPayload(req.body.qrPayload)?.bookingId;
    const suppliedToken = req.body.verificationToken || parseQrPayload(req.body.qrPayload)?.verificationToken;
    if (!bookingId) return res.status(400).json({ ok: false, message: 'Booking ID is required.' });
    const ref = db.collection('bookings').doc(bookingId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ ok: false, message: 'Booking not found.' });
    const booking = toBooking(snap);
    if (booking.verificationToken && suppliedToken !== booking.verificationToken && req.auth.user.role !== 'admin') {
      return res.status(403).json({ ok: false, message: 'Invalid ticket verification token.' });
    }
    await ref.set({ ownerVerifiedAt: nowIso(), updatedAt: nowIso() }, { merge: true });
    const updated = await ref.get();
    res.json({ ok: true, message: 'Guest checked in successfully.', booking: toBooking(updated) });
  } catch (error) {
    return handleError(res, error);
  }
});

function parseQrPayload(payload) {
  try {
    return payload ? JSON.parse(payload) : null;
  } catch (_) {
    return null;
  }
}

async function getOwnedBooking(bookingId, user) {
  const snap = await db.collection('bookings').doc(bookingId).get();
  if (!snap.exists) {
    const error = new Error('Booking not found.');
    error.status = 404;
    throw error;
  }
  const booking = toBooking(snap);
  if (booking.userId !== user.id && booking.ownerId !== user.id && !isStaffRole(user.role)) {
    const error = new Error('You do not have access to this booking.');
    error.status = 403;
    throw error;
  }
  return booking;
}

app.post('/bookings/:bookingId/pay', requireAuth, requirePremiumOrAd, async (req, res) => {
  try {
    const booking = await getOwnedBooking(req.params.bookingId, req.auth.user);
    const orderResp = await fetch(`${PAYMENTS_URL}/api/create-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'booking', id: booking.id, userId: req.auth.user.id }),
    });
    const orderData = await orderResp.json();
    if (!orderResp.ok || !orderData.ok) {
      return res.status(400).json({ ok: false, message: orderData.message || 'Could not create payment order' });
    }
    res.json({ ok: true, message: 'Payment order created.', order: orderData.order, booking });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/payments/create-order', requireAuth, requirePremiumOrAd, async (req, res) => {
  const result = await proxyPayment(req, res, '/api/create-order');
  res.status(result.status).json(result.data);
});

app.post('/api/payments/verify', requireAuth, requirePremiumOrAd, async (req, res) => {
  const paymentType = String((req.body && (req.body.type || req.body['type'])) || '').toLowerCase();
  const result = await proxyPayment(req, res, '/api/verify-payment');
  if (result.data && result.data.ok === true && (paymentType === 'premium' || paymentType === 'subscription' || paymentType === 'premium_listing')) {
    try {
      await db.collection('users').doc(req.auth.user.id).set({
        isPremium: true,
        premiumSince: nowIso(),
        lastPremiumPaymentId: result.data.paymentId || (req.body && req.body.razorpay_payment_id) || null,
        updatedAt: nowIso(),
      }, { merge: true });
    } catch (e) {
      console.error('Failed to auto-activate premium flag after verify:', e.message);
    }
  }
  res.status(result.status).json(result.data);
});

async function proxyPayment(req, res, path) {
  try {
    const response = await fetch(`${PAYMENTS_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...req.body, userId: req.auth.user.id }),
    });
    const data = await response.json();
    return { status: response.status, data };
  } catch (error) {
    console.error('Payment proxy failed:', error);
    return { status: 502, data: { ok: false, message: 'Payment service unavailable' } };
  }
}

app.get('/api/admin/listings/recent', requireAuth, requireStaff, async (req, res) => {
  const limit = clampInt(req.query.limit, 12, 1, 50);
  const snap = await db.collection('venues').orderBy('updatedAt', 'desc').limit(limit).get();
  res.json({ ok: true, message: 'Listings loaded.', listings: snap.docs.map(toListing) });
});

app.get('/api/admin/listings', requireAuth, requireStaff, async (req, res) => {
  const page = clampInt(req.query.page, 1, 1, 10000);
  const limit = clampInt(req.query.limit, 40, 1, 100);
  const status = String(req.query.status || 'all');
  const q = String(req.query.q || '').toLowerCase();
  const listings = (await listVenues({ includeAll: true }))
    .filter((listing) => status === 'all' || listing.status === status)
    .filter((listing) => !q || `${listing.name} ${listing.address}`.toLowerCase().includes(q));
  const start = (page - 1) * limit;
  res.json({
    ok: true,
    message: 'Listings loaded.',
    listings: listings.slice(start, start + limit),
    page,
    total: listings.length,
    hasMore: start + limit < listings.length,
  });
});

app.get('/api/admin/bookings', requireAuth, requireStaff, async (req, res) => {
  const page = clampInt(req.query.page, 1, 1, 10000);
  const limit = clampInt(req.query.limit, 40, 1, 100);
  const status = String(req.query.status || 'all');
  const q = String(req.query.q || '').toLowerCase();
  const snap = await db.collection('bookings').orderBy('bookedAt', 'desc').get();
  const bookings = snap.docs.map(toBooking)
    .filter((booking) => status === 'all' || booking.status === status || booking.paymentStatus === status)
    .filter((booking) => !q || `${booking.venueName} ${booking.customerName}`.toLowerCase().includes(q));
  const start = (page - 1) * limit;
  res.json({
    ok: true,
    message: 'Bookings loaded.',
    bookings: bookings.slice(start, start + limit),
    page,
    total: bookings.length,
    hasMore: start + limit < bookings.length,
  });
});

app.get('/api/admin/bookings/calendar', requireAuth, requireStaff, async (req, res) => {
  const year = clampInt(req.query.year, new Date().getFullYear(), 2020, 2100);
  const month = clampInt(req.query.month, new Date().getMonth() + 1, 1, 12);
  const prefix = `${year}-${String(month).padStart(2, '0')}`;
  const snap = await db.collection('bookings')
    .where('eventDate', '>=', `${prefix}-01`)
    .where('eventDate', '<=', `${prefix}-31`)
    .get();
  const grouped = new Map();
  for (const doc of snap.docs) {
    const booking = toBooking(doc);
    if (req.query.venueId && booking.venueId !== req.query.venueId) continue;
    grouped.set(booking.eventDate, [...(grouped.get(booking.eventDate) || []), booking]);
  }
  const days = [...grouped.entries()].map(([date, bookings]) => ({ date, count: bookings.length, bookings }));
  res.json({ ok: true, message: 'Calendar loaded.', year, month, days });
});

app.get('/api/admin/analytics/bookings', requireAuth, requireStaff, async (req, res) => {
  const period = String(req.query.period || '1w');
  const snap = await db.collection('bookings').get();
  const bookings = snap.docs.map(toBooking);
  const totalRevenue = bookings.reduce((sum, booking) => sum + (booking.paymentStatus === 'paid' ? booking.amount : 0), 0);
  const byDate = new Map();
  for (const booking of bookings) {
    const label = booking.eventDate || booking.bookedAt.slice(0, 10);
    const current = byDate.get(label) || { label, revenue: 0, bookings: 0 };
    current.revenue += booking.paymentStatus === 'paid' ? booking.amount : 0;
    current.bookings += 1;
    byDate.set(label, current);
  }
  res.json({
    ok: true,
    message: 'Analytics loaded.',
    period,
    summary: { totalRevenue, totalBookings: bookings.length },
    points: [...byDate.values()].sort((a, b) => a.label.localeCompare(b.label)).slice(-14),
  });
});

app.post('/api/admin/bookings/:bookingId/confirm', requireAuth, requireStaff, async (req, res) => {
  try {
    const ref = db.collection('bookings').doc(req.params.bookingId);
    const ticketCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    const verificationToken = crypto.randomBytes(24).toString('hex');
    await ref.set({
      status: 'confirmed',
      ticketCode,
      verificationToken,
      qrPayload: JSON.stringify({ bookingId: req.params.bookingId, verificationToken }),
      confirmedAt: nowIso(),
      updatedAt: nowIso(),
    }, { merge: true });
    const snap = await ref.get();
    res.json({ ok: true, message: 'Booking confirmed. Ticket generated.', booking: toBooking(snap) });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/admin/bookings/:bookingId/ticket', requireAuth, requireStaff, async (req, res) => {
  try {
    const ref = db.collection('bookings').doc(req.params.bookingId);
    await ref.set({ ticketImage: req.body.ticketImage || null, status: 'confirmed', confirmedAt: nowIso() }, { merge: true });
    const snap = await ref.get();
    res.json({ ok: true, message: 'Ticket uploaded and booking approved.', booking: toBooking(snap) });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/settings', requireAuth, requireAdmin, async (req, res) => {
  const snap = await db.collection('settings').doc('app').get();
  res.json({ ok: true, message: 'Settings loaded.', data: { settings: snap.exists ? snap.data() : {} } });
});

app.put('/api/settings', requireAuth, requireAdmin, async (req, res) => {
  const settings = {
    autoApproveListings: req.body.autoApproveListings === true,
    autoApproveBookings: req.body.autoApproveBookings === true,
    updatedAt: nowIso(),
  };
  await db.collection('settings').doc('app').set(settings, { merge: true });
  res.json({ ok: true, message: 'Settings updated.', data: { settings } });
});

app.get('/api/dashboard/client', requireAuth, requirePremiumOrAd, async (req, res) => {
  const bookings = await db.collection('bookings').where('userId', '==', req.auth.user.id).get();
  res.json({
    ok: true,
    message: 'Dashboard loaded.',
    role: req.auth.user.role,
    metrics: { bookings: bookings.size, enquiries: bookings.size },
  });
});

app.get('/api/dashboard/admin', requireAuth, requireStaff, async (req, res) => {
  const [venues, bookings] = await Promise.all([
    db.collection('venues').get(),
    db.collection('bookings').get(),
  ]);
  res.json({
    ok: true,
    message: 'Dashboard loaded.',
    role: req.auth.user.role,
    metrics: { listings: venues.size, bookings: bookings.size },
  });
});

app.get('/api/staff', requireAuth, requireAdmin, async (req, res) => {
  const snap = await db.collection('users').where('role', 'in', ['admin', 'manager', 'support', 'reviewer']).get();
  res.json({ ok: true, message: 'Staff loaded.', data: { staff: snap.docs.map((doc) => publicUser({ id: doc.id, ...doc.data() })) } });
});

app.post('/api/staff', requireAuth, requireAdmin, async (req, res) => {
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    const password = requireString(req.body.password, 'Password');
    const name = requireString(req.body.name, 'Name');
    const role = requireString(req.body.role, 'Role');
    if (!['manager', 'support', 'reviewer', 'admin'].includes(role)) {
      return res.status(400).json({ ok: false, message: 'Invalid staff role.' });
    }
    const created = await auth.createUser({ email: identifier, password, displayName: name });
    const profile = await ensureUserProfile(created.uid, { email: identifier, identifier, name });
    await db.collection('users').doc(created.uid).set({ role, createdBy: req.auth.user.id }, { merge: true });
    res.status(201).json({ ok: true, message: 'Staff member added.', data: { staff: publicUser({ ...profile, role }) } });
  } catch (error) {
    return handleError(res, error);
  }
});

app.put('/api/staff/:staffId/role', requireAuth, requireAdmin, async (req, res) => {
  const role = requireString(req.body.role, 'Role');
  await db.collection('users').doc(req.params.staffId).set({ role, updatedAt: nowIso() }, { merge: true });
  const profile = await getUserProfile(req.params.staffId);
  res.json({ ok: true, message: 'Staff role updated.', data: { staff: publicUser(profile) } });
});

app.delete('/api/staff/:staffId', requireAuth, requireAdmin, async (req, res) => {
  await db.collection('users').doc(req.params.staffId).set({ role: 'client', disabledAt: nowIso() }, { merge: true });
  await auth.updateUser(req.params.staffId, { disabled: true }).catch(() => {});
  res.json({ ok: true, message: 'Staff member removed.' });
});

// === Access Control (Premium or Ad-tokenized soft access) ===
// These enforce that only authenticated + (premium OR recent ad grant) can read protected data.
// Admin/staff bypass for ops. Writes are owner+access or staff.
app.get('/api/access/status', requireAuth, async (req, res) => {
  try {
    const profile = req.auth.profile || {};
    const isPremium = profile.isPremium === true || profile.is_premium === true;
    const adRaw = profile.adAccessUntil || profile.ad_access_until;
    let adAccessUntil = null;
    if (adRaw) {
      const d = typeof adRaw === 'string' ? new Date(adRaw) : (adRaw && adRaw.toDate ? adRaw.toDate() : new Date(adRaw));
      if (d instanceof Date && !Number.isNaN(d.getTime())) adAccessUntil = d.toISOString();
    }
    const role = req.auth.user.role;
    const hasAccess = isPremium || ['admin', 'manager', 'support', 'reviewer'].includes(role) || (adAccessUntil && new Date(adAccessUntil).getTime() > Date.now());
    res.json({
      ok: true,
      message: hasAccess ? 'Access active.' : 'Access required.',
      data: {
        isPremium: !!isPremium,
        adAccessUntil,
        hasAccess: !!hasAccess,
        role,
      },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/access/grant-ad', requireAuth, writeLimiter, async (req, res) => {
  try {
    // 30s ad in frontend succeeded -> grant soft timeout access (default 45 minutes)
    const TTL_MS = Number(process.env.AD_ACCESS_TTL_MS || 45 * 60 * 1000);
    const until = new Date(Date.now() + TTL_MS);
    const ref = db.collection('users').doc(req.auth.user.id);
    await ref.set({
      adAccessUntil: until.toISOString(),
      adAccessGrantedAt: nowIso(),
      updatedAt: nowIso(),
    }, { merge: true });
    const updated = await ref.get();
    const profile = updated.exists ? updated.data() : {};
    res.json({
      ok: true,
      message: 'Ad access granted. Enjoy 45 minutes of full access.',
      data: {
        isPremium: profile.isPremium === true,
        adAccessUntil: profile.adAccessUntil || until.toISOString(),
        hasAccess: true,
      },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

// On successful premium payment verify (via proxy), the caller (frontend after verify) can hit this
// or we auto-upgrade in verify path. This allows explicit refresh too.
app.post('/api/access/activate-premium', requireAuth, async (req, res) => {
  try {
    await db.collection('users').doc(req.auth.user.id).set({
      isPremium: true,
      premiumSince: nowIso(),
      updatedAt: nowIso(),
    }, { merge: true });
    res.json({ ok: true, message: 'Premium activated.', data: { isPremium: true, hasAccess: true } });
  } catch (error) {
    return handleError(res, error);
  }
});

app.use((req, res) => {
  res.status(404).json({ ok: false, message: 'Route not found.' });
});

if (!process.env.VERCEL) {
  const server = app.listen(PORT, () => {
    console.log(`Dvenue backend running on http://localhost:${PORT}`);
    console.log(`Payments service expected at: ${PAYMENTS_URL}`);
    console.log(`Firebase project: ${process.env.FIREBASE_PROJECT_ID}`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use. Run kill-servers.bat, then start again.`);
      process.exit(1);
    }
    console.error('Server error:', err);
    process.exit(1);
  });
}

export default app;
