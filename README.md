# Dvenue Backend

Node.js / Express backend for the Dvenue Flutter app.

The Flutter client should talk only to this backend. The backend verifies Firebase ID tokens, owns Firestore writes, proxies payments, and enforces role/ownership checks for listings, booking enquiries, staff, and admin actions.

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

## Main Routes

- `GET /health`
- `POST /api/auth/login`
- `POST /api/auth/signup/start`
- `POST /api/auth/signup/complete`
- `GET /api/auth/me`
- `GET /api/venues/explore`
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
- `GET /api/admin/listings`
- `GET /api/admin/bookings`
- `POST /api/venues/admin/:id/approve`
- `POST /api/venues/admin/:id/reject`
- `GET /api/staff`

## Production Notes

- Set `CORS_ORIGINS` to the deployed Flutter URL, for example `https://dvenueapp.vercel.app`.
- Build Flutter with `--dart-define=API_BASE_URL=<backend-url>` when you are ready to connect the frontend to this backend.
- No service can be "unhackable"; this backend uses the practical baseline: Firebase Admin token verification, server-side Firestore writes, role checks, ownership checks, rate limits, Helmet headers, and fail-closed config guards.
