# Stripe Keys Implementation Guide

## Overview

This document explains where and how Stripe keys are implemented in the XIX Restaurant payment system using **Stripe Checkout** (hosted page).

---

## 🔑 Where Stripe Keys Are Stored

### Environment Variables (.env file)

Stripe keys are stored in the `.env` file on your server (NOT in the code):

```env
# Stripe Payment Configuration
STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxx  # Secret key (starts with sk_live_ or sk_test_)
STRIPE_PUBLISHABLE_KEY=pk_live_xxxxxxxxxxxxx  # Publishable key (starts with pk_live_ or pk_test_)
STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxx  # Webhook secret (starts with whsec_)
```

⚠️ **Important**: 
- Never commit `.env` file to GitHub (it's in `.gitignore`)
- Use `sk_live_` and `pk_live_` keys in production
- Use `sk_test_` and `pk_test_` keys for testing

---

## 📍 Where Keys Are Loaded (Backend)

### File: `server.js`

#### 1. Environment Variables Loaded First
```javascript
// Line 15: Load environment variables BEFORE using them
dotenv.config();
```

#### 2. Secret Key Initialization
```javascript
// Lines 24-31: Initialize Stripe with Secret Key
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not set. Payment functionality will not work.');
  stripe = null;
}
```

**What happens:**
- Reads `STRIPE_SECRET_KEY` from `.env` file
- Initializes Stripe SDK with the secret key
- If missing, payment functionality is disabled (graceful failure)

---

## 🔐 How Secret Key Is Used (Backend Only)

### Secret Key Usage Locations:

#### 1. **Create Checkout Session** (Line 1221)
```javascript
app.post('/api/create-checkout-session', async (req, res) => {
  // Check if Stripe is initialized (uses secret key)
  if (!stripe) {
    return res.status(500).json({ error: 'Payment system not configured.' });
  }

  // Create Checkout Session using secret key
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [/* ... */],
    mode: 'payment',
    // ... other config
  });

  res.json({ sessionId: session.id, url: session.url });
});
```

**What it does:**
- Creates a Stripe Checkout session
- Returns a unique URL where customer will pay
- Uses secret key to authenticate with Stripe API

#### 2. **Verify Payment Success** (Line 1284)
```javascript
app.get('/payment-success', async (req, res) => {
  const { session_id } = req.query;
  
  // Retrieve Checkout Session using secret key
  const session = await stripe.checkout.sessions.retrieve(session_id);
  
  if (session.payment_status === 'paid') {
    // Update database with payment status
    // ...
  }
});
```

**What it does:**
- Verifies payment was successful
- Updates reservation status in database
- Uses secret key to retrieve session details

#### 3. **Webhook Verification** (Line 1391)
```javascript
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  // Verify webhook signature using webhook secret
  event = stripe.webhooks.constructEvent(
    req.body, 
    sig, 
    process.env.STRIPE_WEBHOOK_SECRET
  );
  
  // Handle webhook events
  switch (event.type) {
    case 'checkout.session.completed':
      // Payment succeeded - update database
      break;
  }
});
```

**What it does:**
- Verifies webhook is from Stripe (not fake)
- Uses `STRIPE_WEBHOOK_SECRET` to verify signature
- Handles payment events automatically

---

## 🌐 How Publishable Key Is Used (Currently Not Used)

### Note: With Stripe Checkout, publishable key is NOT needed on frontend!

**Why?** Because Stripe Checkout is a **hosted page** - the customer is redirected to Stripe's servers, which handle everything.

### Where Publishable Key Would Be Used (If Using Stripe Elements):

If you were using Stripe Elements (embedded form), the publishable key would be used like this:

```javascript
// Endpoint: /api/stripe-config (Line 303)
app.get('/api/stripe-config', (req, res) => {
  const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
  
  if (!publishableKey) {
    return res.status(500).json({ error: 'Stripe configuration missing.' });
  }
  
  // Return publishable key to frontend
  res.json({ publishableKey });
});
```

**Frontend would use it:**
```javascript
// In payment.html (if using Elements)
const { publishableKey } = await fetch('/api/stripe-config').then(r => r.json());
const stripe = Stripe(publishableKey); // Initialize Stripe.js
```

**But with Checkout:** We don't need this because Stripe handles everything on their servers.

---

## 🔄 Complete Payment Flow (Stripe Checkout)

### Step-by-Step Process:

```
1. Customer fills reservation form
   ↓
2. Customer clicks "Pay Now" → Redirected to /payment?amount=50&reservationId=123
   ↓
3. Frontend (payment-checkout.html):
   - Customer enters email
   - Clicks "Proceed to Secure Checkout"
   - Calls POST /api/create-checkout-session
   ↓
4. Backend (server.js):
   - Uses STRIPE_SECRET_KEY to create Checkout Session
   - Returns Checkout URL: https://checkout.stripe.com/c/pay/...
   ↓
5. Frontend redirects customer to Stripe Checkout URL
   ↓
6. Customer pays on Stripe's hosted page
   ↓
7. Stripe redirects to /payment-success?session_id=cs_xxx
   ↓
8. Backend verifies payment using STRIPE_SECRET_KEY
   - Calls stripe.checkout.sessions.retrieve(session_id)
   - Updates database: payment_status = "paid"
   ↓
9. Stripe sends webhook to /api/stripe-webhook
   - Uses STRIPE_WEBHOOK_SECRET to verify signature
   - Updates database again (backup confirmation)
   ↓
10. Customer sees success page
```

---

## 📋 Key Locations Summary

| Key Type | Location | Used For | File |
|----------|----------|----------|------|
| **Secret Key** | `.env` → `server.js` line 26 | Creating sessions, verifying payments | `server.js` |
| **Publishable Key** | `.env` → `server.js` line 304 | Not used with Checkout (kept for compatibility) | `server.js` |
| **Webhook Secret** | `.env` → `server.js` line 1391 | Verifying webhook signatures | `server.js` |

---

## 🔒 Security Best Practices

### ✅ DO:
- Store keys in `.env` file (never in code)
- Use `.gitignore` to exclude `.env` from Git
- Use `sk_live_` keys in production
- Use `sk_test_` keys for testing
- Verify webhook signatures

### ❌ DON'T:
- Commit `.env` file to GitHub
- Share secret keys publicly
- Use test keys in production
- Trust webhooks without signature verification

---

## 🧪 Testing the Implementation

### 1. Check if keys are loaded:
```bash
# On server, check if .env file exists and has keys
cat .env | grep STRIPE
```

### 2. Test Checkout Session creation:
```bash
# Make POST request to create session
curl -X POST http://localhost:3001/api/create-checkout-session \
  -H "Content-Type: application/json" \
  -d '{"amount": 50, "customerEmail": "test@example.com"}'
```

### 3. Check server logs:
```javascript
// Should see: "Checkout session created" or "Stripe is not initialized"
```

---

## 📝 Required Environment Variables

Make sure your `.env` file contains:

```env
# Required for Stripe Checkout
STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxx
STRIPE_PUBLISHABLE_KEY=pk_live_xxxxxxxxxxxxx  # Optional with Checkout
STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxx
```

---

## 🎯 Summary

**Current Implementation (Stripe Checkout):**
- ✅ **Secret Key**: Used on backend to create sessions and verify payments
- ✅ **Webhook Secret**: Used to verify webhook signatures
- ⚠️ **Publishable Key**: Not needed with Checkout (kept for compatibility)

**Why This Is Secure:**
- Secret key never leaves the server
- Customer never sees secret key
- All payment processing happens on Stripe's secure servers
- Webhooks are verified to prevent fake requests

