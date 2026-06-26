# Dvenue Backend

Node.js / Express backend for the Dvenue Flutter app.

The Flutter client uses Supabase Auth directly and sends its Supabase access
token to this backend. The backend verifies that token with Supabase, reads the
protected `profiles` row, and enforces role, parent-account, venue ownership,
booking, and staff-management boundaries. Firebase remains only as a legacy
operational datastore for approved venue mirrors and bookings.

Roles:

- `admin`: full platform access; creates elevated `staff` accounts.
- `staff`: elevated admin operations, excluding staff creation and app settings.
- `host`: owns venues and creates scoped `hoststaff` accounts.
- `hoststaff`: operates its parent host's bookings, rates, discounts, and calendar.
- `client`: customer discovery and booking access.

The role is read only from `public.profiles`; user metadata and request bodies
cannot elevate privileges. Apply `clientbackend/supabase-schema.sql` before
starting the services.

## Setup

1. Copy the environment template:

   ```bash
   cp .env.example .env
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Run the service:

   ```bash
   npm run dev
   ```

The default port is `4000`. Set `PAYMENTS_SERVICE_URL=http://localhost:4001` when the payments service is running locally.

## Firebase

The public Firebase web settings are required:

- `FIREBASE_API_KEY`
- `FIREBASE_AUTH_DOMAIN`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_STORAGE_BUCKET`
- `FIREBASE_MESSAGING_SENDER_ID`
- `FIREBASE_APP_ID`

The secured API also requires Firebase Admin credentials:

- `FIREBASE_SERVICE_ACCOUNT_BASE64` preferred for hosted environments
- `FIREBASE_SERVICE_ACCOUNT_JSON` for local JSON strings

Without one of those Admin credential variables, Firestore/auth-backed routes return `503` and do not fall back to insecure access.

Create a base64 value from a Firebase service account JSON file:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("firebase-service-account.json"))
```

Never commit `.env`, service account JSON files, or private keys.

## Auth Model

- Login uses Firebase Identity Toolkit email/password auth and returns a Firebase ID token.
- Protected routes require `Authorization: Bearer <Firebase ID token>`.
- The backend verifies tokens with Firebase Admin and reads the user role from `users/{uid}`.
- `DEFAULT_ADMIN_EMAIL` promotes the matching first profile to `admin`.

### Dedicated admin portal login

The main backend also supports an environment-defined administrator. Configure
`ADMIN_LOGIN_IDENTIFIER` and either `ADMIN_LOGIN_PASSWORD_HASH` (preferred) or
`ADMIN_LOGIN_PASSWORD`. Generate a scrypt password hash with:

```bash
npm run admin:hash-password -- "a-long-unique-password"
```

Successful login through `POST /api/auth/login` returns a random, opaque token
with an `asdf_` prefix. Only the SHA-256 hash of that token is stored in
Firestore (`adminSessions`), and sessions expire after
`ADMIN_SESSION_TTL_MINUTES` (8 hours by default). Logout revokes the session.

The token works as a standard bearer credential and in the requested URL form:

```text
/api/<asdf-token>/admin/listings
/api/<asdf-token>/settings
```

Bearer headers are safer because URL tokens may be retained by browser history,
proxies, and hosting logs. The API marks authenticated responses `no-store` and
sets a `no-referrer` policy, but production logging should also redact paths
containing `asdf_` tokens.

## Main Routes

- `GET /health`
- `GET /api/config/public`
- `POST /api/auth/login` ...
- `GET /api/auth/me` (now also returns access snapshot)
- `GET /api/access/status`
- `POST /api/access/grant-ad` (after 30s frontend ad succeeds)
- `POST /api/access/activate-premium`
- `GET /api/venues/explore` (now requires valid token + (premium OR recent ad grant))
- `GET /api/venues/search`
- `GET /api/venues/:id`
- `GET /api/venues/:id/availability`
- `GET /api/venues/mine`
- `POST /api/venues`
- `PUT /api/venues/:id`
- `DELETE /api/venues/:id`
- `GET /api/bookings/mine`
- `POST /api/bookings`
- `POST /bookings/:bookingId/pay`
- `POST /api/payments/*`
- `GET /api/admin/listings`
- `GET /api/admin/bookings`
- `POST /api/venues/admin/:id/approve`
- `POST /api/venues/admin/:id/reject`
- `GET /api/staff`

## Access Model (Production Security)
- All DB read routes that surface venues, bookings, availability, dashboards now require:
  1. Valid Firebase ID token (Authorization: Bearer ...)
  2. User must be premium (isPremium flag) OR have a recent adAccessUntil (soft TTL, default 45min, granted by /grant-ad after frontend 30s ad completion).
- Staff/admin roles bypass the premium/ad requirement for operational access.
- Writes: protected by requireAuth + access (owner checks remain for self-owned listings/bookings). Admin-only review/approve routes use requireStaff/requireAdmin.
- Payments for premium: `type: 'premium'` on create/verify auto-activates isPremium on the user profile (Firebase) + Supabase.
- 402 "ACCESS_REQUIRED" returned when access missing. Frontend shows the 30s ad template or premium upsell.

## Production Notes

- Set `CORS_ORIGINS` to the deployed Flutter URL, for example `https://dvenueapp.vercel.app`.
- For **local testing**, copy `.env.example` → `.env` and ensure it includes your Flutter dev server:
  - Default Flutter web: `http://localhost:8080,http://127.0.0.1:8080`
  - Also add `http://localhost:5000` if your Flutter instance uses that port.
- Build Flutter with `--dart-define=API_BASE_URL=<backend-url>` when you are ready to connect the frontend to this backend.
- No service can be "unhackable"; this backend uses the practical baseline: Firebase Admin token verification, server-side Firestore writes, role checks, ownership checks, rate limits, Helmet headers, and fail-closed config guards.
