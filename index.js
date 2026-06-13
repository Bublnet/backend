import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';

// Import the initialized Firebase app (this loads .env + validates config)
import firebaseApp, { db, auth, storage } from './firebase.config.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Payments service location (can be same host or separate deployment)
const PAYMENTS_URL = process.env.PAYMENTS_SERVICE_URL || 'http://localhost:4001';

app.use(express.json());

// Basic health check (includes downstream services status)
app.get('/health', async (req, res) => {
  let paymentsHealth = 'unknown';
  try {
    const r = await fetch(`${PAYMENTS_URL}/health`, { timeout: 3000 });
    if (r.ok) paymentsHealth = 'ok';
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

// Example API route using Firebase (Firestore)
app.get('/api/example', async (req, res) => {
  try {
    res.json({
      message: 'Backend is running and Firebase is initialized.',
      projectId: process.env.FIREBASE_PROJECT_ID,
    });
  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* =====================================================
   PAYMENT PROXY / FORWARDING to dedicated payments server
   Flutter still only talks to this backend.
   ===================================================== */

// Proxy create-order to payments service
app.post('/api/payments/create-order', async (req, res) => {
  try {
    const r = await fetch(`${PAYMENTS_URL}/api/create-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (err) {
    console.error('Proxy create-order failed:', err);
    res.status(502).json({ ok: false, message: 'Payment service unavailable' });
  }
});

// Proxy verify-payment
app.post('/api/payments/verify', async (req, res) => {
  try {
    const r = await fetch(`${PAYMENTS_URL}/api/verify-payment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (err) {
    console.error('Proxy verify failed:', err);
    res.status(502).json({ ok: false, message: 'Payment service unavailable' });
  }
});

// Also support the old pay endpoint style for backward compat with existing BookingsApi.payBooking
// In a full impl you would first create the booking (write to Firebase), then here trigger the order.
app.post('/bookings/:bookingId/pay', async (req, res) => {
  // This is a simplified version. Real flow:
  // 1. Client already called createBooking which wrote an unpaid booking.
  // 2. Now we start the real payment by creating an order.
  const bookingId = req.params.bookingId;
  const userId = req.body?.userId || 'demo-user'; // in real life extract from auth token

  try {
    // Forward to payments to create Razorpay order (amount fetched server-side from Firebase)
    const orderResp = await fetch(`${PAYMENTS_URL}/api/create-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'booking', id: bookingId, userId }),
    });
    const orderData = await orderResp.json();

    if (!orderResp.ok || !orderData.ok) {
      return res.status(400).json({ ok: false, message: orderData.message || 'Could not create payment order' });
    }

    // Return the order to the client so it can open the Razorpay modal.
    // After client gets success from modal, it must call the verify endpoint.
    res.json({
      ok: true,
      message: 'Payment order created. Open Razorpay checkout with this order.',
      order: orderData.order,
      // The old client expected a 'booking' back. In real usage the verify step will return the final booking.
      booking: { id: bookingId, paymentStatus: 'processing' },
    });
  } catch (err) {
    console.error('bookings pay proxy error:', err);
    res.status(500).json({ ok: false, message: 'Payment initiation failed' });
  }
});

// Public config for frontend (only safe values)
app.get('/api/config/public', (req, res) => {
  res.json({
    ok: true,
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || null, // public key only — safe
    // Add other public flags here (feature flags etc.)
  });
});

// Start server with friendly port conflict handling
const server = app.listen(PORT, () => {
  console.log(`🚀 Dvenue backend (gateway) running on http://localhost:${PORT}`);
  console.log(`   Payments service expected at: ${PAYMENTS_URL}`);
  console.log(`📦 Firebase project: ${process.env.FIREBASE_PROJECT_ID}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌ Port ${PORT} is already in use.`);
    console.error('   Run "kill-servers.bat" (or double-click it) from the Dvenue root folder,');
    console.error('   then run "start.bat" again.\n');
    process.exit(1);
  } else {
    console.error('Server error:', err);
    process.exit(1);
  }
});
