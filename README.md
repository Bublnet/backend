# Dvenue Backend (Gateway)

Node.js / Express backend for the Dvenue Flutter app.

This service is the **only** thing the Flutter client talks to. It proxies to Supabase (OTP etc.), Firebase, and the dedicated **payments** service.

## Setup

### Easiest way (recommended)

From the **project root** (Dvenue folder), just double-click:

```
start.bat
```

This does the following:
- Kills any old processes on ports 4000 and 4001 first (avoids `EADDRINUSE`)
- Launches both the backend (4000) and payments (4001) in separate titled PowerShell windows
- Shows live output and writes to `logs/backend.log` + `logs/payments.log`

You can also manually force-kill with:

```
kill-servers.bat
```

### Manual setup

1. Copy env (same Firebase keys as the payments service):
   ```bash
   cp .env.example .env
   ```

2. Install:
   ```bash
   npm install
   ```

3. Run (in its own terminal):
   ```bash
   npm run dev
   ```

Port 4000 (configure `PORT` and `PAYMENTS_SERVICE_URL=http://localhost:4001` if payments runs elsewhere).

> **Tip:** Always start the payments service before or at the same time as the backend in development.

## Payment Flow (new)

- `/api/payments/create-order` and `/api/payments/verify` are forwarded to the payments server.
- Legacy `/bookings/:id/pay` now creates a real Razorpay order (via proxy) and returns it so the client can open checkout.
- After the client completes payment in the Razorpay modal it must call verify (the Flutter code does this automatically).

See the payments/ folder (especially arch.md) for the full picture.

## Firebase Configuration

All Firebase settings are loaded from environment variables (never hardcoded).

See [.env.example](.env.example) for the required keys:

- `FIREBASE_API_KEY`
- `FIREBASE_AUTH_DOMAIN`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_STORAGE_BUCKET`
- `FIREBASE_MESSAGING_SENDER_ID`
- `FIREBASE_APP_ID`

These come from your Firebase project settings → Web app configuration.

**Security note:** The `.env` file is gitignored. Never commit real credentials.

## Usage in code

```js
import app, { db, auth, storage } from './firebase.config.js';

// Use Firestore, Auth, or Storage as needed
```

## API Routes

- `GET /health` – Health check + current Firebase project + payments service status
- `GET /api/example` – Sample protected-style route
- Payment proxy routes (forwarded to payments service):
  - `POST /api/payments/create-order`
  - `POST /api/payments/verify`
  - `POST /bookings/:bookingId/pay` (legacy compatibility)

Add your real routes under `/api` to match the Flutter client's `ApiConfig.apiRoot`.

## Next Steps (typical for this project)

- Add Supabase admin client for OTP / auth proxying
- Add payment provider integration (Stripe, etc.)
- Protect routes with proper auth middleware
- Add CORS for the Flutter app origins
