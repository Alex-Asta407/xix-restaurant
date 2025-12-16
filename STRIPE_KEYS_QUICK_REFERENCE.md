# Stripe Keys Quick Reference

## 🔑 Key Locations in Code

### 1. **Secret Key (Backend Only)**

**Location:** `server.js` lines 24-31

```javascript
// Load environment variables
dotenv.config();

// Initialize Stripe with Secret Key
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not set');
  stripe = null;
}
```

**Used in:**
- ✅ Creating Checkout Sessions (`/api/create-checkout-session` - line 1221)
- ✅ Verifying Payment Success (`/payment-success` - line 1284)
- ✅ Webhook Verification (`/api/stripe-webhook` - line 1391)

**Never exposed to frontend!**

---

### 2. **Publishable Key (Currently Not Used with Checkout)**

**Location:** `server.js` line 304

```javascript
// Endpoint: /api/stripe-config
app.get('/api/stripe-config', (req, res) => {
  const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
  res.json({ publishableKey });
});
```

**Status:** ⚠️ Not needed with Stripe Checkout (kept for compatibility)

**Why?** With Stripe Checkout, customer is redirected to Stripe's servers, so we don't need to initialize Stripe.js on frontend.

---

### 3. **Webhook Secret (Backend Only)**

**Location:** `server.js` line 1391

```javascript
// Webhook endpoint
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  // Verify webhook signature
  event = stripe.webhooks.constructEvent(
    req.body, 
    sig, 
    process.env.STRIPE_WEBHOOK_SECRET  // ← Used here
  );
});
```

**Used for:** Verifying webhook requests are from Stripe (not fake)

---

## 📊 Payment Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (payment-checkout.html)          │
│                                                              │
│  1. Customer enters email                                   │
│  2. Clicks "Proceed to Secure Checkout"                     │
│  3. Calls: POST /api/create-checkout-session              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (server.js)                      │
│                                                              │
│  Uses STRIPE_SECRET_KEY to create Checkout Session         │
│  Returns: { sessionId: "cs_xxx", url: "https://..." }     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    STRIPE SERVER (External)                  │
│                                                              │
│  Customer pays on Stripe's hosted page                     │
│  Stripe processes payment                                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (server.js)                       │
│                                                              │
│  /payment-success?session_id=cs_xxx                        │
│  Uses STRIPE_SECRET_KEY to verify payment                  │
│  Updates database: payment_status = "paid"                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    STRIPE WEBHOOK (External)                 │
│                                                              │
│  POST /api/stripe-webhook                                   │
│  Uses STRIPE_WEBHOOK_SECRET to verify signature            │
│  Updates database again (backup confirmation)              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    .env FILE (Server Only)                  │
│                                                              │
│  STRIPE_SECRET_KEY=sk_live_xxx  ← NEVER exposed            │
│  STRIPE_PUBLISHABLE_KEY=pk_live_xxx  ← Not used with Checkout│
│  STRIPE_WEBHOOK_SECRET=whsec_xxx  ← NEVER exposed          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (server.js)                       │
│                                                              │
│  ✅ Secret Key: Used to create sessions, verify payments   │
│  ✅ Webhook Secret: Used to verify webhook signatures      │
│  ⚠️  Publishable Key: Not used with Checkout              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (payment-checkout.html)         │
│                                                              │
│  ✅ No Stripe keys needed!                                 │
│  ✅ Just calls /api/create-checkout-session               │
│  ✅ Redirects to Stripe Checkout URL                       │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ Checklist

- [ ] **Secret Key** in `.env` file: `STRIPE_SECRET_KEY=sk_live_...`
- [ ] **Publishable Key** in `.env` file: `STRIPE_PUBLISHABLE_KEY=pk_live_...` (optional with Checkout)
- [ ] **Webhook Secret** in `.env` file: `STRIPE_WEBHOOK_SECRET=whsec_...`
- [ ] `.env` file is in `.gitignore` (never commit to Git)
- [ ] Use `sk_live_` and `pk_live_` keys in production
- [ ] Use `sk_test_` and `pk_test_` keys for testing
- [ ] Webhook endpoint configured in Stripe Dashboard: `https://yourdomain.com/api/stripe-webhook`

---

## 🎯 Key Takeaways

1. **Secret Key**: Only used on backend, never exposed to frontend
2. **Publishable Key**: Not needed with Stripe Checkout (kept for compatibility)
3. **Webhook Secret**: Used to verify webhook signatures (security)
4. **Security**: All keys stored in `.env` file, never in code
5. **Flow**: Frontend → Backend → Stripe → Backend → Database

