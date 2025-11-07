# XIX Restaurant - Links & Environment Verification Checklist

## ✅ Server Routes Verification

### Main Routes (All routes match server.js)
- ✅ `/` → `landing.html` or `index.html`
- ✅ `/xix` → `index.html`
- ✅ `/menu` → `menu.html`
- ✅ `/events` → `events.html`
- ✅ `/reservations` → `reservations.html`
- ✅ `/mirror` → `mirror/mirror.html`
- ✅ `/mirror/events` → `mirror/events.html`
- ✅ `/mirror/reservations` → `mirror/reservations.html`
- ✅ `/mirror/menu` → `mirror/menu.html`
- ✅ `/payment` → `payment-checkout.html` (UPDATED - now uses Stripe Checkout)
- ✅ `/payment-success` → Handled by server (Stripe Checkout success page)

### API Endpoints
- ✅ `/api/stripe-config` → Returns Stripe publishable key
- ✅ `/api/create-payment` → Creates Payment Intent (Stripe Elements - kept for compatibility)
- ✅ `/api/create-checkout-session` → Creates Checkout Session (Stripe Checkout - NEW)
- ✅ `/api/stripe-webhook` → Handles Stripe webhook events
- ✅ `/api/reservations` → GET all reservations
- ✅ `/api/reservations/:date` → GET reservations by date
- ✅ `/api/reservations/venue/:venue` → GET reservations by venue
- ✅ `/api/available-times` → GET available times for date/venue
- ✅ `/api/send-reservation-email` → POST to send reservation email

## ✅ HTML Links Verification

### Navigation Links (All pages)
- ✅ `/xix` - Home page
- ✅ `/menu` - Menu page
- ✅ `/events` - Events page
- ✅ `/reservations` - Reservations page
- ✅ `/mirror` - Mirror page

### Footer Links (All pages)
- ✅ `/menu` - Menu page
- ✅ `/events` - Events page
- ✅ `/reservations` - Reservations page
- ✅ `/mirror` - Mirror page
- ✅ Social media links (Instagram, Facebook, TikTok, UberEats) - External URLs

### Payment Flow Links
- ✅ `/payment` - Payment page (now uses Stripe Checkout)
- ✅ `/payment-success` - Success page (handled by server)

## ✅ CSS/JS File References

### CSS Files (All HTML files)
- ✅ `base.css` - Base styles and variables
- ✅ `navigation.css` - Navigation styles
- ✅ `main.css` - Main page styles (index.html)
- ✅ `menu.css` - Menu page styles (menu.html)
- ✅ `events.css` - Events page styles (events.html)
- ✅ `reservations.css` - Reservations page styles (reservations.html)
- ✅ `footer.css` - Footer styles
- ✅ `mirror.css` - Mirror page styles (mirror pages)

### JavaScript Files
- ✅ `script.js` - Main JavaScript (navigation, form handling)
- ✅ `offline.js` - Service worker offline functionality
- ✅ `sw.js` - Service worker

### External Resources
- ✅ Google Fonts (Gilda Display, Noto Sans)
- ✅ Font Awesome CDN
- ✅ Stripe.js CDN (for payment-checkout.html - if needed for future use)

## ✅ Image Paths Verification

### Favicon Paths (All HTML files)
- ✅ `photos/favicon.ico`
- ✅ `photos/favicon-32x32.png`
- ✅ `photos/favicon-16x16.png`
- ✅ `photos/apple-icon-180x180.png`

### Mirror Pages (Subdirectory)
- ✅ `../photos/favicon.ico` (relative path from mirror/)
- ✅ `../photos/favicon-32x32.png`
- ✅ `../photos/favicon-16x16.png`
- ✅ `../photos/apple-icon-180x180.png`

### Hero Images
- ✅ `photos/XIX_main.png` - Main page hero image
- ✅ `../photos/mirror_hero.jpg` - Mirror page hero image
- ✅ `../photos/mirror_interior.jpg` - Mirror interior image
- ✅ `../photos/mirror_cuisine.jpg` - Mirror cuisine image

## ✅ Environment Variables Required

### Server Configuration
- ✅ `PORT` - Server port (default: 3001)
- ✅ `NODE_ENV` - Environment mode (production/development)

### Email Configuration
- ✅ `SMTP_HOST` - SMTP server (e.g., smtp.gmail.com)
- ✅ `SMTP_PORT` - SMTP port (e.g., 587)
- ✅ `SMTP_SECURE` - Use secure connection (true/false)
- ✅ `SMTP_USER` - SMTP username (email address)
- ✅ `SMTP_PASS` - SMTP password (Gmail App Password)
- ✅ `MAIL_FROM` - From email address
- ✅ `MANAGER_EMAIL` - Manager email for notifications

### Stripe Configuration
- ✅ `STRIPE_SECRET_KEY` - Stripe secret key (sk_test_... or sk_live_...)
- ✅ `STRIPE_PUBLISHABLE_KEY` - Stripe publishable key (pk_test_... or pk_live_...)
- ✅ `STRIPE_WEBHOOK_SECRET` - Stripe webhook secret (whsec_...)

### Admin Configuration
- ✅ `ADMIN_SECRET_KEY` - Secret key for admin access

## ✅ Dependencies Verification

### All Required Packages (package.json)
- ✅ `express` - Web framework
- ✅ `dotenv` - Environment variable management
- ✅ `sqlite3` - Database
- ✅ `stripe` - Payment processing
- ✅ `nodemailer` - Email sending
- ✅ `helmet` - Security headers
- ✅ `cors` - CORS support
- ✅ `express-rate-limit` - Rate limiting
- ✅ `express-slow-down` - Slow down requests
- ✅ `express-brute` - Brute force protection
- ✅ `morgan` - HTTP request logger
- ✅ `winston` - Logging
- ✅ `validator` - Input validation
- ✅ `dompurify` - XSS protection
- ✅ `jsdom` - DOM manipulation

## ✅ Stripe Configuration Status

### Backend Endpoints
- ✅ `/api/create-payment` - Stripe Elements (Payment Intent) - KEPT for compatibility
- ✅ `/api/create-checkout-session` - Stripe Checkout (Checkout Session) - NEW
- ✅ `/api/stripe-config` - Returns publishable key
- ✅ `/api/stripe-webhook` - Handles webhook events

### Webhook Events Handled
- ✅ `payment_intent.succeeded` - Payment succeeded (Elements)
- ✅ `checkout.session.completed` - Checkout completed (Checkout)
- ✅ `payment_intent.payment_failed` - Payment failed

### Frontend Implementation
- ✅ `payment-checkout.html` - Stripe Checkout implementation
- ✅ `/payment-success` - Success page after Checkout

## ⚠️ Important Notes

1. **Stripe Keys**: Make sure to use LIVE keys (`sk_live_...` and `pk_live_...`) in production, not test keys
2. **Webhook Secret**: Must be set in `.env` file for webhook verification to work
3. **Webhook URL**: Must be configured in Stripe Dashboard: `https://yourdomain.com/api/stripe-webhook`
4. **SMTP Password**: Use Gmail App Password, not regular password
5. **Database**: SQLite database `reservations.db` will be created automatically if it doesn't exist

## ✅ Files Cleaned Up

- ✅ `payment.html` - DELETED (replaced by payment-checkout.html)
- ✅ `payment-test.html` - DELETED (test file)
- ✅ `payment.js` - DELETED (unused file)

## 🎯 Next Steps

1. **Verify Environment Variables**: Ensure all required variables are set in `.env` file on production server
2. **Test Stripe Checkout**: Test payment flow with Stripe Checkout
3. **Configure Webhook**: Set up webhook endpoint in Stripe Dashboard
4. **Test Email**: Verify email sending works with SMTP credentials
5. **Test All Routes**: Verify all routes work correctly in production

---

**Status**: ✅ All links verified, environment variables documented, dependencies checked

