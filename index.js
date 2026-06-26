import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { FieldValue } from 'firebase-admin/firestore';
import { db, auth, hasFirebaseServerCredentials, firebaseConfig } from './firebase.config.js';
import {
  getSupabaseIdentity,
  normalizeRole,
  supabaseAdmin,
} from './supabase.client.js';
import helmet from 'helmet';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import {
  ADMIN_TOKEN_PATTERN,
  createAdminToken,
  extractTokenizedApiPath,
  hashAdminToken,
  isAdminIdentifier,
  normalizeAdminIdentifier,
  verifyAdminPassword,
} from './admin-auth.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Local service account path is handled in firebase.config.js

const app = express();
const PORT = process.env.PORT || 4000;
const PAYMENTS_URL = process.env.PAYMENTS_SERVICE_URL || 'http://localhost:4001';
const CLIENT_BACKEND_URL = process.env.CLIENT_BACKEND_URL || 'http://localhost:4002';
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || firebaseConfig?.apiKey;

function cleanForFirestore(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .map(cleanForFirestore)
      .filter((v) => v !== undefined);
  }
  const result = {};
  for (const [key, val] of Object.entries(value)) {
    let cleaned = cleanForFirestore(val);
    if (cleaned !== undefined) {
      if (key === 'specTable' && cleaned && typeof cleaned === 'object') {
        const table = sanitizeSpecTable(cleaned);
        // Firestore rejects arrays nested directly inside arrays. Preserve the
        // table shape by wrapping every row in a map and decode it on reads.
        cleaned = {
          columns: table.columns,
          rows: table.rows.map((cells) => ({ cells })),
        };
      }
      result[key] = cleaned;
    }
  }
  return result;
}

function decodeFirestoreSpecTable(raw) {
  if (!raw || typeof raw !== 'object') return { columns: [], rows: [] };
  return {
    columns: Array.isArray(raw.columns) ? raw.columns.map(String) : [],
    rows: Array.isArray(raw.rows)
      ? raw.rows.map((row) => Array.isArray(row)
        ? row.map(String)
        : (Array.isArray(row?.cells) ? row.cells.map(String) : []))
      : [],
  };
}

function sanitizeSpecTable(raw) {
  if (!raw || typeof raw !== 'object') {
    return { columns: ["Specification", "Details"], rows: [["Area", ""], ["Parking", ""]] };
  }
  return {
    columns: Array.isArray(raw.columns)
      ? raw.columns.map(c => (typeof c === 'string' ? c : String(c || ''))).filter(Boolean)
      : ["Specification", "Details"],
    rows: Array.isArray(raw.rows)
      ? raw.rows.map(row =>
          Array.isArray(row)
            ? row.map(cell => (typeof cell === 'string' ? cell : String(cell || '')))
            : []
        )
      : [["Area", ""], ["Parking", ""]]
  };
}
const DEFAULT_ADMIN_EMAIL = process.env.DEFAULT_ADMIN_EMAIL;
const ADMIN_LOGIN_IDENTIFIER = process.env.ADMIN_LOGIN_IDENTIFIER;
const ADMIN_LOGIN_PASSWORD = process.env.ADMIN_LOGIN_PASSWORD;
const ADMIN_LOGIN_PASSWORD_HASH = process.env.ADMIN_LOGIN_PASSWORD_HASH;
const ADMIN_DISPLAY_NAME = process.env.ADMIN_DISPLAY_NAME || 'Dvenue Administrator';
const parsedAdminSessionTtlMinutes = Number(process.env.ADMIN_SESSION_TTL_MINUTES || 480);
const ADMIN_SESSION_TTL_MS = Math.min(
  7 * 24 * 60 * 60 * 1000,
  Math.max(
    5 * 60 * 1000,
    (Number.isFinite(parsedAdminSessionTtlMinutes) ? parsedAdminSessionTtlMinutes : 480) * 60 * 1000,
  ),
);
const AUTH_OTP_TTL_MS = Number(process.env.AUTH_OTP_TTL_MS || 10 * 60 * 1000);
const authBaseUrl = `https://identitytoolkit.googleapis.com/v1/accounts`;

// Defaults set for current "simulate OTP, google removed" mode. Override via .env
const ENABLE_OTP_VERIFY = (process.env.ENABLE_OTP_VERIFY || 'false').toLowerCase() === 'true';
const ENABLE_GOOGLE_SIGNIN = (process.env.ENABLE_GOOGLE_SIGNIN || 'false').toLowerCase() === 'true';

// Firebase admin is initialized and exported from firebase.config.js

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
// Listing photos currently arrive as one compressed data URL per request and
// are forwarded to the private media service. Keep this aligned with that
// service until direct signed uploads replace the proxy flow.
app.use(express.json({ limit: '15mb' }));

// Global Data Logging Middleware
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    res.set('Referrer-Policy', 'no-referrer');
  }
  next();
});

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
    parentId: profile.parentId || profile.parent_id || null,
    permissions: profile.permissions || {},
    isPremium: profile.isPremium === true || profile.is_premium === true,
    adAccessUntil: profile.adAccessUntil || profile.ad_access_until || null,
  };
}

function isStaffRole(role) {
  return ['admin', 'staff'].includes(role);
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

function envAdminProfile() {
  return {
    id: 'env-admin',
    name: ADMIN_DISPLAY_NAME,
    identifier: normalizeAdminIdentifier(ADMIN_LOGIN_IDENTIFIER),
    email: isEmail(normalizeAdminIdentifier(ADMIN_LOGIN_IDENTIFIER))
      ? normalizeAdminIdentifier(ADMIN_LOGIN_IDENTIFIER)
      : '',
    role: 'admin',
    isPremium: true,
    adAccessUntil: null,
  };
}

function assertEnvAdminConfigured() {
  if (!ADMIN_LOGIN_IDENTIFIER || (!ADMIN_LOGIN_PASSWORD_HASH && !ADMIN_LOGIN_PASSWORD)) {
    const error = new Error('Environment administrator login is not configured.');
    error.status = 503;
    throw error;
  }
}

async function createEnvAdminSession(req) {
  assertFirebaseServerConfigured();
  assertEnvAdminConfigured();
  const token = createAdminToken();
  const tokenHash = hashAdminToken(token);
  const now = Date.now();
  const expiresAt = now + ADMIN_SESSION_TTL_MS;
  await db.collection('adminSessions').doc(tokenHash).set({
    subject: 'env-admin',
    role: 'admin',
    createdAt: now,
    expiresAt,
    lastSeenAt: now,
    userAgent: String(req.get('user-agent') || '').slice(0, 300),
  });
  return { token, expiresAt };
}

async function resolveEnvAdminSession(token, { touch = true } = {}) {
  if (!ADMIN_TOKEN_PATTERN.test(String(token || ''))) return null;
  assertFirebaseServerConfigured();
  const tokenHash = hashAdminToken(token);
  const ref = db.collection('adminSessions').doc(tokenHash);
  const snap = await ref.get();
  if (!snap.exists) return null;

  const session = snap.data();
  if (session.subject !== 'env-admin' || session.role !== 'admin' || Number(session.expiresAt) <= Date.now()) {
    await ref.delete().catch(() => {});
    return null;
  }

  if (touch && Date.now() - Number(session.lastSeenAt || 0) > 5 * 60 * 1000) {
    await ref.set({ lastSeenAt: Date.now() }, { merge: true });
  }
  return { tokenHash, session, profile: envAdminProfile() };
}

async function authenticateEnvAdminToken(token, req) {
  const resolved = await resolveEnvAdminSession(token);
  if (!resolved) return false;
  req.auth = {
    source: 'env-admin',
    token,
    decoded: { uid: 'env-admin', exp: Math.floor(Number(resolved.session.expiresAt) / 1000) },
    user: publicUser(resolved.profile),
    profile: resolved.profile,
    sessionTokenHash: resolved.tokenHash,
  };
  return true;
}

// Supports the requested /api/<asdf-token>/<route> shape while preserving the
// existing route handlers and their role checks.
app.use(async (req, res, next) => {
  const tokenized = extractTokenizedApiPath(req.path);
  if (!tokenized) return next();
  try {
    if (!await authenticateEnvAdminToken(tokenized.token, req)) {
      return res.status(401).json({ ok: false, message: 'Admin session expired or invalid.' });
    }
    if (!req.headers.authorization) {
      req.headers.authorization = `Bearer ${tokenized.token}`;
    }
    req.url = req.url.replace(`/api/${tokenized.token}`, '/api');
    return next();
  } catch (error) {
    return handleError(res, error);
  }
});

async function requireAuth(req, res, next) {
  try {
    if (req.auth?.source === 'env-admin') return next();
    const header = req.get('authorization') || '';
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return res.status(401).json({ ok: false, message: 'Missing bearer token.' });
    }

    if (ADMIN_TOKEN_PATTERN.test(match[1])) {
      if (await authenticateEnvAdminToken(match[1], req)) return next();
      return res.status(401).json({ ok: false, message: 'Admin session expired or invalid.' });
    }

    const identity = await getSupabaseIdentity(match[1]);
    const decoded = {
      uid: identity.authUser.id,
      sub: identity.authUser.id,
      email: identity.authUser.email,
    };
    req.auth = {
      source: 'supabase',
      token: match[1],
      decoded,
      user: publicUser(identity.profile),
      profile: identity.profile,
    };
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

const requireStaff = requireRole(['admin', 'staff']);
const requireAdmin = requireRole(['admin']);
const requireHost = requireRole(['host']);
const requireHostOperator = requireRole(['host', 'hoststaff']);
const requireBookingOperator = requireRole(['admin', 'staff', 'host', 'hoststaff']);

function operationalOwnerId(req) {
  return req.auth.user.role === 'hoststaff'
    ? req.auth.user.parentId
    : req.auth.user.id;
}

function canAccessOperationalBooking(req, booking) {
  if (['admin', 'staff'].includes(req.auth.user.role)) return true;
  return booking.ownerId === operationalOwnerId(req);
}

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
    const isPrivileged = ['admin', 'staff', 'host', 'hoststaff'].includes(role);
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

function accessSnapshot(req) {
  const profile = req.auth?.profile || {};
  const isPremium = profile.isPremium === true || profile.is_premium === true;
  const adRaw = profile.adAccessUntil || profile.ad_access_until;
  let hasAdAccess = false;
  if (adRaw) {
    const until = typeof adRaw === 'string'
      ? new Date(adRaw)
      : (adRaw?.toDate ? adRaw.toDate() : new Date(adRaw));
    hasAdAccess = until instanceof Date
      && !Number.isNaN(until.getTime())
      && until.getTime() > Date.now();
  }
  const isPrivileged = ['admin', 'staff', 'host', 'hoststaff']
    .includes(req.auth?.user?.role);
  return {
    isPremium,
    hasAdAccess,
    hasAccess: isPremium || hasAdAccess || isPrivileged,
  };
}

function venueForViewer(listing, req) {
  const access = accessSnapshot(req);
  if (access.hasAccess) {
    return { ...listing, detailsLocked: false };
  }
  const spaces = Array.isArray(listing.spaces)
    ? listing.spaces.map((space) => {
      const {
        dayPrice: _dayPrice,
        nightPrice: _nightPrice,
        hourlyPrices: _hourlyPrices,
        price: _price,
        ...safeSpace
      } = space || {};
      return safeSpace;
    })
    : [];
  return {
    ...listing,
    detailsLocked: true,
    basePrice: null,
    gstAmount: null,
    priceWithGst: null,
    priceRange: '',
    spaces,
  };
}

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
    specTable: decodeFirestoreSpecTable(data.specTable),
    spaces: Array.isArray(data.spaces)
      ? data.spaces.map((space) => ({
          ...space,
          specTable: decodeFirestoreSpecTable(space?.specTable),
        }))
      : [],
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
      const haystack = `${venue.name} ${venue.type} ${venue.address} ${venue.location} ${venue.pincode || ''} ${venue.gstin || ''}`.toLowerCase();
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
  if (action === 'signInWithPassword') {
    const { data, error } = await supabaseAdmin.auth.signInWithPassword({ email: payload.email, password: payload.password });
    if (error) throw { status: 400, message: error.message };
    return { idToken: data.session.access_token, localId: data.user.id, email: data.user.email };
  }
  if (action === 'signUp') {
    const { data, error } = await supabaseAdmin.auth.signUp({ email: payload.email, password: payload.password });
    if (error) throw { status: 400, message: error.message };
    return { idToken: data.session?.access_token || '', localId: data.user.id, email: data.user.email };
  }
  if (action === 'sendOobCode') {
    const { error } = await supabaseAdmin.auth.resetPasswordForEmail(payload.email);
    if (error) throw { status: 400, message: error.message };
    return {};
  }
  throw new Error(`Unsupported auth action: ${action}`);
}

function mapFirebaseAuthError(code) {
  return code;
}

async function googleIdentityToolkit(idToken) {
  const { data, error } = await supabaseAdmin.auth.signInWithIdToken({ provider: 'google', token: idToken });
  if (error) throw { status: 400, message: error.message };
  return { idToken: data.session.access_token, localId: data.user.id, email: data.user.email };
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
    firebaseProject: process.env.FIREBASE_PROJECT_ID || firebaseConfig?.projectId || 'not-configured',
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
  const hasAccess = isPremium || ['admin', 'staff', 'host', 'hoststaff'].includes(role) || (adAccessUntil && new Date(adAccessUntil).getTime() > Date.now());
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
    const { error } = await supabaseAdmin.from('profiles')
      .update({ manual_location: loc, updated_at: nowIso() })
      .eq('id', req.auth.user.id);
    if (error) throw error;
    res.json({ ok: true, message: 'Location preference saved.' });
  } catch (error) {
    return handleError(res, error);
  }
});

app.patch('/api/profiles/me', requireAuth, async (req, res) => {
  try {
    const name = req.body?.name == null
      ? null
      : requireString(req.body.name, 'Name');
    if (!name) {
      return res.status(400).json({ ok: false, message: 'No profile changes supplied.' });
    }
    const { data: updated, error } = await supabaseAdmin.from('profiles')
      .update({ display_name: name, updated_at: nowIso() })
      .eq('id', req.auth.user.id).select().single();
    if (error) throw error;
    const profile = {
      ...updated,
      name: updated.display_name,
      identifier: updated.email,
      parentId: updated.parent_id,
    };
    return res.json({
      ok: true,
      message: 'Profile updated.',
      data: { user: publicUser(profile) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    const password = requireString(req.body.password, 'Password');
    if (isAdminIdentifier(identifier, ADMIN_LOGIN_IDENTIFIER)) {
      assertEnvAdminConfigured();
      const validPassword = await verifyAdminPassword(password, {
        passwordHash: ADMIN_LOGIN_PASSWORD_HASH,
        passwordPlain: ADMIN_LOGIN_PASSWORD,
      });
      if (!validPassword) {
        return res.status(401).json({ ok: false, message: 'Invalid login credentials.' });
      }
      const session = await createEnvAdminSession(req);
      return res.json({
        ok: true,
        message: 'Welcome to the Dvenue admin portal.',
        data: {
          token: session.token,
          expiresAt: new Date(session.expiresAt).toISOString(),
          user: publicUser(envAdminProfile()),
        },
      });
    }
    if (!isEmail(identifier)) {
      return res.status(400).json({ ok: false, message: 'Email login is required.' });
    }
    const { data: login, error: loginError } = await supabaseAdmin.auth
      .signInWithPassword({ email: identifier, password });
    if (loginError || !login.session) {
      return res.status(401).json({ ok: false, message: loginError?.message || 'Invalid login credentials.' });
    }
    const identity = await getSupabaseIdentity(login.session.access_token);

    res.json({
      ok: true,
      message: 'Welcome to Dvenue.',
      data: { token: login.session.access_token, user: publicUser(identity.profile) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/google', authLimiter, async (req, res) => {
  res.status(400).json({
    ok: false,
    message: 'Start Google OAuth from Supabase Auth in the Flutter client.',
  });
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  if (ENABLE_OTP_VERIFY) {
    return res.status(400).json({ ok: false, message: 'OTP verification is enabled. Use signup start and complete endpoints.' });
  }
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    if (!isEmail(identifier)) {
      return res.status(400).json({ ok: false, message: 'Email signup is required.' });
    }
    const password = requireString(req.body.password, 'Password');

    const { data: signup, error: signupError } = await supabaseAdmin.auth.signUp({
      email: identifier,
      password,
    });
    if (signupError) throw signupError;
    const token = signup.session?.access_token || null;

    res.json({
      ok: true,
      message: token ? 'Account created.' : 'Check your email to confirm your account.',
      data: { token, user: token ? publicUser((await getSupabaseIdentity(token)).profile) : null },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/auth/signup/start', authLimiter, async (req, res) => {
  res.status(410).json({ ok: false, message: 'Use Supabase email confirmation signup.' });
});

app.post('/api/auth/signup/complete', authLimiter, async (req, res) => {
  res.status(410).json({ ok: false, message: 'Use Supabase email confirmation signup.' });
});

app.post('/api/auth/password-reset/start', authLimiter, async (req, res) => {
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    const { error } = await supabaseAdmin.auth.resetPasswordForEmail(identifier);
    if (error) throw error;
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

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  if (req.auth.source === 'env-admin' && req.auth.sessionTokenHash) {
    await db.collection('adminSessions').doc(req.auth.sessionTokenHash).delete();
  }
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
    if (ADMIN_TOKEN_PATTERN.test(token)) {
      const resolved = await resolveEnvAdminSession(token);
      if (!resolved) {
        return res.status(401).json({ ok: false, message: 'Admin session expired or invalid.' });
      }
      return res.json({
        ok: true,
        message: 'Session valid.',
        data: {
          token,
          user: publicUser(resolved.profile),
          expiresAt: new Date(Number(resolved.session.expiresAt)).toISOString(),
        },
      });
    }
    const identity = await getSupabaseIdentity(token);
    res.json({
      ok: true,
      message: 'Session valid.',
      data: {
        token,
        user: publicUser(identity.profile),
        expiresAt: null,
      },
    });
  } catch (error) {
    return res.status(401).json({ ok: false, message: 'Session token expired or invalid. Please sign in again.' });
  }
});

app.get('/api/venues/explore', requireAuth, async (req, res) => {
  try {
    const venues = filterVenues(await listVenues(), req.query)
      .map((listing) => venueForViewer(listing, req));
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

app.get('/api/venues/search', requireAuth, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 8, 1, 50);
    const results = filterVenues(await listVenues(), req.query)
      .slice(0, limit)
      .map((listing) => venueForViewer(listing, req));
    res.json({ ok: true, message: 'Search complete.', results });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/mine', requireAuth, async (req, res) => {
  try {
    const [snap, clientResponse] = await Promise.all([
      db.collection('venues').where('ownerId', '==', req.auth.user.id).get(),
      fetch(`${CLIENT_BACKEND_URL}/api/venues/mine`, {
        headers: {
          Authorization: req.headers.authorization || '',
          Accept: 'application/json',
        },
      }),
    ]);
    const clientData = await clientResponse.json();
    if (!clientResponse.ok || clientData.ok === false) {
      return res.status(502).json({ ok: false, message: clientData.message || 'Could not load submitted listings.' });
    }
    const byId = new Map();
    for (const listing of snap.docs.map(toListing)) byId.set(listing.id, listing);
    for (const listing of (clientData.listings || []).map(toListing)) {
      byId.set(listing.id, { ...(byId.get(listing.id) || {}), ...listing });
    }
    res.json({ ok: true, message: 'Listings loaded.', listings: [...byId.values()] });
  } catch (error) {
    return handleError(res, error);
  }
});

async function proxyClientData(req, path = req.path) {
  try {
    const response = await fetch(`${CLIENT_BACKEND_URL}${path}`, {
      method: req.method,
      headers: {
        Authorization: req.headers.authorization || '',
        Accept: 'application/json',
        ...(req.method === 'GET' || req.method === 'HEAD'
          ? {}
          : { 'Content-Type': 'application/json' }),
      },
      body: req.method === 'GET' || req.method === 'HEAD'
        ? undefined
        : JSON.stringify(req.body || {}),
    });
    const data = await response.json();
    return { status: response.status, data };
  } catch (error) {
    console.error('Client-data proxy failed:', error);
    return {
      status: 502,
      data: { ok: false, message: 'Listing and media service unavailable.' },
    };
  }
}

function pricingChanges(before, after) {
  const changes = [];
  const add = (field, label, oldValue, newValue) => {
    if (JSON.stringify(oldValue ?? null) === JSON.stringify(newValue ?? null)) return;
    changes.push({ field, label, oldValue: oldValue ?? null, newValue: newValue ?? null });
  };
  add('basePrice', 'Base price', before?.basePrice, after?.basePrice);
  add('gstRate', 'GST rate', before?.gstRate, after?.gstRate);
  add('priceWithGst', 'Customer total', before?.priceWithGst, after?.priceWithGst);

  const beforeSpaces = Array.isArray(before?.spaces) ? before.spaces : [];
  const afterSpaces = Array.isArray(after?.spaces) ? after.spaces : [];
  const count = Math.max(beforeSpaces.length, afterSpaces.length);
  for (let index = 0; index < count; index += 1) {
    const oldSpace = beforeSpaces[index] || {};
    const newSpace = afterSpaces[index] || {};
    const spaceName = newSpace.name || oldSpace.name || `Space ${index + 1}`;
    add(`spaces.${index}.dayPrice`, `${spaceName} day price`, oldSpace.dayPrice, newSpace.dayPrice);
    add(`spaces.${index}.nightPrice`, `${spaceName} night price`, oldSpace.nightPrice, newSpace.nightPrice);
    add(
      `spaces.${index}.hourlyPrices`,
      `${spaceName} hourly prices`,
      oldSpace.hourlyPrices || {},
      newSpace.hourlyPrices || {},
    );
    const oldCalendar = oldSpace.calendarOverrides || {};
    const newCalendar = newSpace.calendarOverrides || {};
    const dates = new Set([...Object.keys(oldCalendar), ...Object.keys(newCalendar)]);
    for (const date of [...dates].sort()) {
      add(
        `spaces.${index}.calendarOverrides.${date}`,
        `${spaceName} · ${date}`,
        oldCalendar[date] || { status: 'available', discountPercent: 0 },
        newCalendar[date] || { status: 'available', discountPercent: 0 },
      );
    }
  }
  return changes;
}

async function writeVenueWithHistory({ venueId, before, after, actor, source }) {
  const venueRef = db.collection('venues').doc(venueId);
  const changes = pricingChanges(before, after);
  const batch = db.batch();
  batch.set(venueRef, cleanForFirestore(after), { merge: true });
  if (changes.length > 0) {
    const historyRef = venueRef.collection('priceHistory').doc();
    batch.set(historyRef, cleanForFirestore({
      venueId,
      source,
      actorId: actor?.id || null,
      actorName: actor?.name || actor?.identifier || 'Unknown',
      changedAt: nowIso(),
      changes,
    }));
  }
  await batch.commit();
  return changes;
}

app.post('/api/cdn/upload', requireAuth, writeLimiter, async (req, res) => {
  const result = await proxyClientData(req);
  res.status(result.status).json(result.data);
});

app.get('/api/venues/pincode/:prefix', requireAuth, async (req, res) => {
  const prefix = String(req.params.prefix || '').trim();
  if (!/^\d{3}$/.test(prefix)) {
    return res.status(400).json({ ok: false, message: 'A valid 3-digit pincode prefix is required.' });
  }
  try {
    const response = await fetch(
      `${CLIENT_BACKEND_URL}/public/pincodes/${encodeURIComponent(prefix)}.json`,
      { headers: { Accept: 'application/json' } },
    );
    if (response.status === 404) {
      return res.json({ ok: true, venues: [] });
    }
    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (error) {
    console.error('Pincode cache proxy failed:', error);
    return res.status(502).json({
      ok: false,
      message: 'Pincode venue search is temporarily unavailable.',
    });
  }
});

app.get('/api/venues/admin/pending', requireAuth, requireStaff, async (req, res) => {
  try {
    // Admin backend fetches pending data from clientbackend (as per architecture:
    // clients submit only to clientbackend for pending; admin verifies then "pushes"
    // by status update in shared store, or in future separate project).
    // This ensures client data for verification is isolated at write time.
    const clientResp = await fetch(`${CLIENT_BACKEND_URL}/api/venues/admin/pending`, {
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

app.get('/api/venues/:venueId/availability', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    let uid = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const decodedToken = await admin.auth().verifyIdToken(authHeader.split('Bearer ')[1]);
        uid = decodedToken.uid;
      } catch(e) {}
    }

    const { year, month } = req.query;
    if (!year || !month) return res.status(400).json({ ok: false, message: 'Missing year/month' });

    const prefix = `${year}-${String(month).padStart(2, '0')}`;
    const snap = await db.collection('bookings')
      .where('venueId', '==', req.params.venueId)
      .get();
      
    const bookedByMe = new Set();
    const booked = new Set();
    
    snap.docs.forEach((doc) => {
      const booking = toBooking(doc);
      if (['pending', 'confirmed'].includes(booking.status) && booking.eventDate.startsWith(prefix)) {
        booked.add(booking.eventDate);
        if (uid && booking.userId === uid) {
          bookedByMe.add(booking.eventDate);
        }
      }
    });
    const venueSnap = await db.collection('venues').doc(req.params.venueId).get();
    if (!venueSnap.exists) {
      return res.status(404).json({ ok: false, message: 'Listing not found.' });
    }
    const venue = toListing(venueSnap);
    const primarySpace = venue.spaces?.[0] || {};
    const overrides = primarySpace.calendarOverrides || {};
    const originalRate = Number(primarySpace.dayPrice || primarySpace.nightPrice || venue.priceWithGst || venue.basePrice || 0);
    const originalDayRate = primarySpace.dayPrice ? Number(primarySpace.dayPrice) : null;
    const originalNightRate = primarySpace.nightPrice ? Number(primarySpace.nightPrice) : null;
    const daysInMonth = new Date(year, month, 0).getDate();
    const today = new Date();
    const todayKey = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
    const days = Array.from({ length: daysInMonth }, (_, i) => {
      const date = `${prefix}-${String(i + 1).padStart(2, '0')}`;
      const override = overrides[date] || {};
      
      const isFullyBookedByHost = override.status === 'booked';
      const isDayBookedByHost = override.status === 'day_booked';
      const isNightBookedByHost = override.status === 'night_booked';
      
      const isPast = date < todayKey;
      const isFullyBooked = booked.has(date) || isFullyBookedByHost;

      const discountPercent = Math.max(0, Math.min(100, Number(override.discountPercent || 0)));
      const applyDiscount = (val) => val ? Math.round(val * (1 - discountPercent / 100)) : null;
      
      const rate = applyDiscount(originalRate);
      let dayRate = applyDiscount(originalDayRate);
      let nightRate = applyDiscount(originalNightRate);

      if (booked.has(`${date}|day`) || isDayBookedByHost) dayRate = null;
      if (booked.has(`${date}|night`) || isNightBookedByHost) nightRate = null;

      const isEffectivelyBooked = isFullyBooked || 
        ((originalDayRate != null || originalNightRate != null) && dayRate == null && nightRate == null);

      let finalStatus = 'available';
      if (isPast) finalStatus = 'past';
      else if (isEffectivelyBooked) finalStatus = 'booked';

      const isBookedByMe = bookedByMe.has(date) || bookedByMe.has(`${date}|day`) || bookedByMe.has(`${date}|night`);

      return {
        date,
        booked: isEffectivelyBooked || isPast,
        available: !isEffectivelyBooked && !isPast,
        status: finalStatus,
        bookedByMe: isBookedByMe,
        originalRate: originalRate || null,
        rate,
        dayRate,
        nightRate,
        discountPercent,
      };
    });
    res.json({ ok: true, venueId: req.params.venueId, year, month, days });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/venues/:id', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('venues').doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ ok: false, message: 'Listing not found.' });
    const listing = toListing(snap);
    if (listing.status !== 'approved') {
      return res.status(404).json({ ok: false, message: 'Listing not found.' });
    }
    return res.json({ ok: true, listing: venueForViewer(listing, req) });
  } catch (error) {
    return handleError(res, error);
  }
});

app.post('/api/venues', requireAuth, writeLimiter, async (req, res) => {
  const result = await proxyClientData(req);
  res.status(result.status).json(result.data);
});

app.put('/api/venues/:id', requireAuth, writeLimiter, async (req, res) => {
  const isCalendarUpdate = req.body?.calendarOnly === true;
  
  // If only updating calendar, don't rely on the proxy to preserve the complex calendarOverrides JSON
  // We sync directly to Firebase first.
  if (isCalendarUpdate) {
    try {
      const venueRef = db.collection('venues').doc(req.params.id);
      const currentSnap = await venueRef.get();
      if (currentSnap.exists) {
        const before = toListing(currentSnap);
        const updatedSpaces = Array.isArray(req.body.spaces) ? req.body.spaces : before.spaces;
        const after = cleanForFirestore({ ...before, spaces: updatedSpaces, updatedAt: nowIso() });
        await writeVenueWithHistory({
          venueId: req.params.id,
          before,
          after,
          actor: req.auth.user,
          source: 'owner_calendar',
        });
        await syncVenueToPayments(after);
        
        // Optionally notify the proxy asynchronously, but don't depend on its response for the spaces data
        proxyClientData(req).catch(console.error);
        
        return res.json({ ok: true, message: 'Calendar updated and published successfully.' });
      }
    } catch (error) {
      console.error('Approved calendar synchronization failed:', error);
      return res.status(502).json({
        ok: false,
        message: 'Calendar was saved, but could not be published. Please retry.',
      });
    }
  }

  // Normal full listing update
  const result = await proxyClientData(req);
  if (result.status < 300 && result.data?.ok === true) {
    // If it was a normal update that somehow got here, we don't need to do anything special 
    // unless there's a specific requirement to sync it immediately to venues.
  }
  res.status(result.status).json(result.data);
});

app.delete('/api/venues/:id', requireAuth, writeLimiter, async (req, res) => {
  const result = await proxyClientData(req);
  res.status(result.status).json(result.data);
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
    const clientResponse = await fetch(`${CLIENT_BACKEND_URL}/api/venues/admin/${req.params.id}/review`, {
      method: 'PATCH',
      headers: {
        Authorization: req.headers.authorization || '',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ approve, reason: req.body.reason || null }),
    });
    const clientData = await clientResponse.json();
    if (!clientResponse.ok || clientData.ok === false || !clientData.listing) {
      return res.status(502).json({
        ok: false,
        message: clientData.message || 'Could not update the submitted listing.',
      });
    }
    const update = approve
      ? { status: 'approved', verified: true, verificationStatus: 'approved', approvedAt: nowIso() }
      : { status: 'rejected', verified: false, verificationStatus: 'rejected', rejectionReason: req.body.reason || 'Rejected' };

    const finalListing = {
      ...clientData.listing,
      ...update,
      reviewedBy: req.auth.user.id,
      updatedAt: nowIso(),
    };
    const existingSnap = await db.collection('venues').doc(req.params.id).get();
    const previousListing = existingSnap.exists ? toListing(existingSnap) : null;
    const firestoreListing = cleanForFirestore(finalListing);
    await writeVenueWithHistory({
      venueId: req.params.id,
      before: previousListing,
      after: firestoreListing,
      actor: req.auth.user,
      source: approve ? 'admin_approval' : 'admin_rejection',
    });
    await syncVenueToPayments(firestoreListing);

    res.json({ ok: true, message: approve ? 'Listing approved.' : 'Listing rejected.', listing: finalListing });
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

app.get('/api/admin/listings/:id/price-history', requireAuth, requireStaff, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 100, 1, 250);
    const snap = await db.collection('venues')
      .doc(req.params.id)
      .collection('priceHistory')
      .orderBy('changedAt', 'desc')
      .limit(limit)
      .get();
    const history = snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    return res.json({ ok: true, message: 'Price history loaded.', history });
  } catch (error) {
    return handleError(res, error);
  }
});

async function updateListingVerification(req, res, status, message) {
  try {
    const clientResponse = await fetch(`${CLIENT_BACKEND_URL}/api/venues/admin/${req.params.id}/verification`, {
      method: 'PATCH',
      headers: {
        Authorization: req.headers.authorization || '',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status, notes: req.body.notes || null }),
    });
    const clientData = await clientResponse.json();
    if (!clientResponse.ok || clientData.ok === false || !clientData.listing) {
      return res.status(502).json({
        ok: false,
        message: clientData.message || 'Could not update verification status.',
      });
    }
    const finalListing = {
      ...clientData.listing,
      verificationStatus: status,
      verificationNotes: req.body.notes || null,
      updatedAt: nowIso(),
    };
    const firestoreListing = cleanForFirestore(finalListing);
    await db.collection('venues').doc(req.params.id).set(firestoreListing, { merge: true });
    await syncVenueToPayments(firestoreListing);

    res.json({ ok: true, message, listing: finalListing });
  } catch (error) {
    return handleError(res, error);
  }
}

async function syncVenueToPayments(listing) {
  try {
    const response = await fetch(`${PAYMENTS_URL}/api/venues/sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.INTERNAL_SERVICE_TOKEN
          ? { 'X-Internal-Service-Token': process.env.INTERNAL_SERVICE_TOKEN }
          : {}),
      },
      body: JSON.stringify(listing),
    });
    if (!response.ok) {
      const body = await response.text();
      console.warn('[venue-sync] Payments mirror skipped:', response.status, body);
    }
  } catch (error) {
    // Approval is authoritative in Supabase + the main Firestore. A reporting
    // mirror must never turn a completed approval into an HTTP 500.
    console.warn('[venue-sync] Payments mirror unavailable:', error.message);
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

app.post('/api/bookings', requireAuth, writeLimiter, async (req, res) => {
  try {
    const venueId = requireString(req.body.venueId, 'Venue');
    const eventDateRaw = requireString(req.body.eventDate, 'Event date');
    const venueSnap = await db.collection('venues').doc(venueId).get();
    if (!venueSnap.exists) return res.status(404).json({ ok: false, message: 'Venue not found.' });
    const venue = toListing(venueSnap);
    if (venue.status !== 'approved') return res.status(400).json({ ok: false, message: 'Venue is not bookable yet.' });

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

    // Parse eventDate string like "YYYY-MM-DD|day" or "YYYY-MM-DD|night" or "YYYY-MM-DD|00:00-00:59|Main Space"
    const [dateString, slotString, spaceName] = eventDateRaw.split('|');
    const primarySpace = (spaceName ? venue.spaces?.find(s => s.name === spaceName) : venue.spaces?.[0]) || venue.spaces?.[0] || {};
    const overrides = primarySpace.calendarOverrides || {};
    const override = overrides[dateString] || {};
    const discountPercent = Math.max(0, Math.min(100, Number(override.discountPercent || 0)));
    
    let baseAmount = venue.priceWithGst || venue.basePrice || 0;
    if (slotString === 'day' && primarySpace.dayPrice) {
      baseAmount = Number(primarySpace.dayPrice);
    } else if (slotString === 'night' && primarySpace.nightPrice) {
      baseAmount = Number(primarySpace.nightPrice);
    } else if (slotString && primarySpace.hourlyPrices && primarySpace.hourlyPrices[slotString]) {
      baseAmount = Number(primarySpace.hourlyPrices[slotString]);
    } else if (slotString && slotString.startsWith('hour_') && primarySpace.hourlyPrices) {
      const hourKey = slotString.replace('hour_', '');
      if (primarySpace.hourlyPrices[hourKey]) {
        baseAmount = Number(primarySpace.hourlyPrices[hourKey]);
      }
    } else if (primarySpace.dayPrice || primarySpace.nightPrice) {
      // If it's a split cell but they somehow booked the whole day, just use priceWithGst
      baseAmount = venue.priceWithGst || venue.basePrice || 0;
    }

    const finalAmount = Math.round(baseAmount * (1 - discountPercent / 100));

    const duplicate = await db.collection('bookings')
      .where('venueId', '==', venueId)
      .where('eventDate', '==', eventDateRaw)
      .where('status', 'in', ['pending', 'confirmed'])
      .limit(1)
      .get();
    if (!duplicate.empty) {
      const dup = duplicate.docs[0];
      const dupData = typeof dup.data === 'function' ? dup.data() : dup;
      if (dupData.status === 'pending' && dupData.userId === req.auth.user.id) {
        if (dupData.amount === 0 && finalAmount > 0) {
          await db.collection('bookings').doc(dup.id).set({ amount: finalAmount }, { merge: true });
          dupData.amount = finalAmount;
        }
        return res.status(200).json({ 
          ok: true, 
          message: 'Resuming existing booking for payment.', 
          booking: { id: dup.id, ...dupData } 
        });
      }
      return res.status(409).json({ ok: false, message: 'This date/slot is already reserved.' });
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
      amount: finalAmount,
      guests: req.body.guests == null ? null : Number(req.body.guests),
      status: 'pending',
      paymentStatus: 'unpaid',
      bookedAt: nowIso(),
      eventDate: eventDateRaw,
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

app.post('/api/venues/owner/bookings/verify-scan', requireAuth, requireBookingOperator, async (req, res) => {
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
  if (!canAccessOperationalBooking(req, booking) && booking.userId !== user.id) {
    const error = new Error('You do not have access to this booking.');
    error.status = 403;
    throw error;
  }
  return booking;
}

app.post('/api/bookings/:bookingId/pay', requireAuth, requirePremiumOrAd, async (req, res) => {
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

app.post('/api/payments/create-order', requireAuth, async (req, res) => {
  const result = await proxyPayment(req, res, '/api/create-order');
  res.status(result.status).json(result.data);
});

app.post('/api/payments/verify', requireAuth, async (req, res) => {
  const paymentType = String((req.body && (req.body.type || req.body['type'])) || '').toLowerCase();
  const result = await proxyPayment(req, res, '/api/verify-payment');
  if (result.data && result.data.ok === true && (paymentType === 'premium' || paymentType === 'subscription' || paymentType === 'premium_listing')) {
    try {
      await supabaseAdmin.from('profiles').update({
        is_premium: true,
        premium_since: nowIso(),
        last_payment_id: result.data.paymentId || (req.body && req.body.razorpay_payment_id) || null,
        updated_at: nowIso(),
      }).eq('id', req.auth.user.id);
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
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.INTERNAL_SERVICE_TOKEN
          ? { 'X-Internal-Service-Token': process.env.INTERNAL_SERVICE_TOKEN }
          : {}),
      },
      body: JSON.stringify({ ...req.body, userId: req.auth.user.id }),
    });
    const data = await response.json();
    return { status: response.status, data };
  } catch (error) {
    console.error('Payment proxy failed:', error);
    return { status: 502, data: { ok: false, message: 'Payment service unavailable' } };
  }
}

async function fetchClientAdminListings(req) {
  const response = await fetch(`${CLIENT_BACKEND_URL}/api/venues/admin/all`, {
    headers: {
      Authorization: req.headers.authorization || '',
      Accept: 'application/json',
    },
  });
  const data = await response.json();
  if (!response.ok || data.ok === false) {
    const error = new Error(data.message || 'Failed to load client-submitted listings.');
    error.status = 502;
    throw error;
  }
  return Array.isArray(data.listings) ? data.listings.map(toListing) : [];
}

async function listAllAdminListings(req) {
  const [firestoreListings, clientListings] = await Promise.all([
    listVenues({ includeAll: true }),
    fetchClientAdminListings(req),
  ]);
  const byId = new Map();
  for (const listing of firestoreListings) byId.set(listing.id, listing);
  for (const listing of clientListings) {
    byId.set(listing.id, { ...(byId.get(listing.id) || {}), ...listing });
  }
  return [...byId.values()];
}

app.get('/api/admin/listings/recent', requireAuth, requireStaff, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 12, 1, 50);
    const listings = (await listAllAdminListings(req))
      .sort((a, b) => String(b.updatedAt || b.submittedAt || '').localeCompare(String(a.updatedAt || a.submittedAt || '')))
      .slice(0, limit);
    res.json({ ok: true, message: 'Listings loaded.', listings });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/admin/listings', requireAuth, requireStaff, async (req, res) => {
  const page = clampInt(req.query.page, 1, 1, 10000);
  const limit = clampInt(req.query.limit, 40, 1, 100);
  const status = String(req.query.status || 'all');
  const q = String(req.query.q || '').toLowerCase();
  try {
    const listings = (await listAllAdminListings(req))
      .filter((listing) => status === 'all' || listing.status === status)
      .filter((listing) => !q || `${listing.name} ${listing.address} ${listing.ownerEmail || ''}`.toLowerCase().includes(q));
    const start = (page - 1) * limit;
    res.json({
      ok: true,
      message: 'Listings loaded.',
      listings: listings.slice(start, start + limit),
      page,
      total: listings.length,
      hasMore: start + limit < listings.length,
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.get('/api/admin/bookings', requireAuth, requireBookingOperator, async (req, res) => {
  const page = clampInt(req.query.page, 1, 1, 10000);
  const limit = clampInt(req.query.limit, 40, 1, 100);
  const status = String(req.query.status || 'all');
  const q = String(req.query.q || '').toLowerCase();
  const snap = await db.collection('bookings').orderBy('bookedAt', 'desc').get();
  const bookings = snap.docs.map(toBooking)
    .filter((booking) => canAccessOperationalBooking(req, booking))
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

app.get('/api/admin/bookings/calendar', requireAuth, requireBookingOperator, async (req, res) => {
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
    if (!canAccessOperationalBooking(req, booking)) continue;
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

app.post('/api/admin/bookings/:bookingId/confirm', requireAuth, requireBookingOperator, async (req, res) => {
  try {
    const ref = db.collection('bookings').doc(req.params.bookingId);
    const current = await ref.get();
    if (!current.exists || !canAccessOperationalBooking(req, toBooking(current))) {
      return res.status(404).json({ ok: false, message: 'Booking not found.' });
    }
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

app.post('/api/admin/bookings/:bookingId/ticket', requireAuth, requireBookingOperator, async (req, res) => {
  try {
    const ref = db.collection('bookings').doc(req.params.bookingId);
    const current = await ref.get();
    if (!current.exists || !canAccessOperationalBooking(req, toBooking(current))) {
      return res.status(404).json({ ok: false, message: 'Booking not found.' });
    }
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

function requireStaffManager(req, res, next) {
  if (!['admin', 'host'].includes(req.auth?.user?.role)) {
    return res.status(403).json({ ok: false, message: 'Only admins and hosts can manage staff.' });
  }
  return next();
}

app.get('/api/staff', requireAuth, requireStaffManager, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('profiles')
    .select('*')
    .eq('parent_id', req.auth.user.id)
    .eq('active', true)
    .order('created_at', { ascending: false });
  if (error) return handleError(res, error);
  const staff = (data || []).map((profile) => publicUser({
    ...profile,
    name: profile.display_name,
    identifier: profile.email,
  }));
  res.json({ ok: true, message: 'Staff loaded.', data: { staff } });
});

app.post('/api/staff', requireAuth, requireStaffManager, async (req, res) => {
  try {
    const identifier = normalizeIdentifier(req.body.identifier);
    const password = requireString(req.body.password, 'Password');
    const name = requireString(req.body.name, 'Name');
    const role = req.auth.user.role === 'admin' ? 'staff' : 'hoststaff';
    const permissions = role === 'staff'
      ? { elevated: true }
      : { bookings: true, pricing: true, calendar: true, listings: false, staff: false };
    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email: identifier,
      password,
      email_confirm: true,
      user_metadata: { name },
    });
    if (createError) throw createError;
    const profile = {
      id: created.user.id,
      email: identifier,
      display_name: name,
      role,
      parent_id: req.auth.user.id,
      permissions,
      active: true,
      updated_at: nowIso(),
    };
    const { error: profileError } = await supabaseAdmin.from('profiles').upsert(profile);
    if (profileError) throw profileError;
    res.status(201).json({
      ok: true,
      message: role === 'staff' ? 'Admin staff member added.' : 'Host staff member added.',
      data: { staff: publicUser({ ...profile, name, identifier }) },
    });
  } catch (error) {
    return handleError(res, error);
  }
});

app.put('/api/staff/:staffId/role', requireAuth, requireStaffManager, async (req, res) => {
  const expectedRole = req.auth.user.role === 'admin' ? 'staff' : 'hoststaff';
  const { data: existing, error: readError } = await supabaseAdmin
    .from('profiles').select('*').eq('id', req.params.staffId)
    .eq('parent_id', req.auth.user.id).maybeSingle();
  if (readError) return handleError(res, readError);
  if (!existing) return res.status(404).json({ ok: false, message: 'Staff member not found.' });
  const permissions = req.body.permissions && typeof req.body.permissions === 'object'
    ? req.body.permissions
    : existing.permissions;
  const { data: profile, error } = await supabaseAdmin.from('profiles')
    .update({ role: expectedRole, permissions, updated_at: nowIso() })
    .eq('id', req.params.staffId).select().single();
  if (error) return handleError(res, error);
  res.json({
    ok: true,
    message: 'Staff permissions updated.',
    data: { staff: publicUser({ ...profile, name: profile.display_name, identifier: profile.email }) },
  });
});

app.delete('/api/staff/:staffId', requireAuth, requireStaffManager, async (req, res) => {
  const { data: existing } = await supabaseAdmin.from('profiles').select('id')
    .eq('id', req.params.staffId).eq('parent_id', req.auth.user.id).maybeSingle();
  if (!existing) return res.status(404).json({ ok: false, message: 'Staff member not found.' });
  const { error } = await supabaseAdmin.from('profiles')
    .update({ active: false, updated_at: nowIso() }).eq('id', req.params.staffId);
  if (error) return handleError(res, error);
  await supabaseAdmin.auth.admin.updateUserById(req.params.staffId, { ban_duration: '876000h' });
  res.json({ ok: true, message: 'Staff member removed.' });
});

app.put('/api/admin/users/:userId/role', requireAuth, requireAdmin, async (req, res) => {
  const role = normalizeRole(req.body.role);
  if (!['host', 'client'].includes(role)) {
    return res.status(400).json({ ok: false, message: 'Admins may assign host or client roles here.' });
  }
  const { data: profile, error } = await supabaseAdmin.from('profiles')
    .update({ role, parent_id: null, permissions: {}, updated_at: nowIso() })
    .eq('id', req.params.userId).select().single();
  if (error) return handleError(res, error);
  res.json({ ok: true, message: `User role changed to ${role}.`, data: { user: publicUser(profile) } });
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
    const hasAccess = isPremium || ['admin', 'staff', 'host', 'hoststaff'].includes(role) || (adAccessUntil && new Date(adAccessUntil).getTime() > Date.now());
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
    const { data: profile, error } = await supabaseAdmin.from('profiles').update({
      ad_access_until: until.toISOString(),
      updated_at: nowIso(),
    }).eq('id', req.auth.user.id).select().single();
    if (error) throw error;
    res.json({
      ok: true,
      message: 'Ad access granted. Enjoy 45 minutes of full access.',
      data: {
        isPremium: profile.is_premium === true,
        adAccessUntil: profile.ad_access_until || until.toISOString(),
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
    const { error } = await supabaseAdmin.from('profiles').update({
      is_premium: true,
      premium_since: nowIso(),
      updated_at: nowIso(),
    }).eq('id', req.auth.user.id);
    if (error) throw error;
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
    console.log(`Firebase project: ${process.env.FIREBASE_PROJECT_ID || firebaseConfig?.projectId || 'undefined'}`);
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
