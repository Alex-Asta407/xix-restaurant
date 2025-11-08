const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Load environment variables FIRST before using them
dotenv.config();

// Additional Security Imports
const winston = require('winston');
const morgan = require('morgan');

// Initialize Stripe with error handling (AFTER dotenv.config())
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not set in environment variables. Payment functionality will not work.');
  stripe = null;
}

const app = express();
const port = process.env.PORT || 3001;

// Trust proxy for dev tunnels and production deployments
app.set('trust proxy', true);

// Security Logging Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'xix-restaurant' },
  transports: [
    new winston.transports.File({ filename: 'logs/security.log', level: 'warn' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Create logs directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://use.fontawesome.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "https://use.fontawesome.com", "data:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com", "https://js.stripe.com", "https://checkout.stripe.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.stripe.com", "https://checkout.stripe.com"],
      frameSrc: ["'self'", "https://js.stripe.com", "https://hooks.stripe.com", "https://checkout.stripe.com"],
      frameAncestors: ["'self'"]
    }
  } : false // Disable CSP in development
}));

// Rate limiting - Very lenient for restaurant website
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 1000 : 10000, // Very high limits
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const reservationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: process.env.NODE_ENV === 'production' ? 100 : 500, // Increased for legitimate use (users may try multiple dates/times)
  message: {
    error: 'Too many reservation attempts. Please try again later.'
  }
});

// Apply security middleware
// Exclude webhook endpoint from rate limiting (Stripe needs to send webhooks)
app.use((req, res, next) => {
  if (req.path === '/api/stripe-webhook') {
    return next(); // Skip rate limiting for webhooks
  }
  limiter(req, res, next);
});
app.use('/api/reservations', reservationLimiter);

// HTTP Request Logging
app.use(morgan('combined', {
  stream: {
    write: (message) => {
      logger.info(message.trim());
    }
  }
}));

// Security event logging middleware
app.use((req, res, next) => {
  // Log suspicious requests
  if (req.url.includes('<script>') || req.url.includes('javascript:') || req.url.includes('eval(')) {
    logger.warn('Suspicious request detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url,
      method: req.method,
      timestamp: new Date().toISOString()
    });
  }
  next();
});

// Mobile-specific security middleware
app.use((req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  const isMobile = /Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);

  // Add mobile-specific security headers
  if (isMobile) {
    // Prevent mobile browsers from caching sensitive data
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Mobile-specific security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Mobile device fingerprinting protection
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  }

  // Log mobile requests for security monitoring
  if (isMobile) {
    logger.info('Mobile request detected', {
      ip: req.ip,
      userAgent: userAgent,
      url: req.url,
      method: req.method,
      timestamp: new Date().toISOString()
    });
  }

  next();
});

app.use(cors({
  origin: true, // Allow all origins in development
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Request Size Limits
// Webhook endpoint MUST be defined BEFORE express.json() middleware
// because it needs raw body for signature verification
// (Moved to after static files but before JSON parser)

// JSON and URL-encoded parsers (exclude webhook endpoint)
app.use((req, res, next) => {
  if (req.path === '/api/stripe-webhook') {
    return next(); // Skip JSON parsing for webhooks (handled by express.raw)
  }
  express.json({ limit: '10mb' })(req, res, next);
});
app.use((req, res, next) => {
  if (req.path === '/api/stripe-webhook') {
    return next(); // Skip URL-encoded parsing for webhooks
  }
  express.urlencoded({ limit: '10mb', extended: true })(req, res, next);
});

// Serve service worker with proper headers
app.get('/sw.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.sendFile(__dirname + '/sw.js');
});

// Explicit route handlers for HTML pages
app.get('/', (req, res) => {
  console.log('ROOT ROUTE HIT - Serving landing.html directly');
  // Add cache-busting headers to prevent browser caching
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  res.sendFile(__dirname + '/landing.html');
});


app.get('/xix', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.get('/menu', (req, res) => {
  res.sendFile(__dirname + '/menu.html');
});

app.get('/events', (req, res) => {
  res.sendFile(__dirname + '/events.html');
});

app.get('/reservations', (req, res) => {
  res.sendFile(__dirname + '/reservations.html');
});

app.get('/mirror', (req, res) => {
  res.sendFile(__dirname + '/mirror/mirror.html');
});

app.get('/mirror/events', (req, res) => {
  res.sendFile(__dirname + '/mirror/events.html');
});

app.get('/mirror/reservations', (req, res) => {
  res.sendFile(__dirname + '/mirror/reservations.html');
});

app.get('/mirror/menu', (req, res) => {
  res.sendFile(__dirname + '/mirror/menu.html');
});

app.get('/offline', (req, res) => {
  res.sendFile(__dirname + '/offline.html');
});

// Payment page route - using Stripe Checkout (hosted page)
app.get('/payment', (req, res) => {
  res.sendFile(__dirname + '/payment-checkout.html');
});

// Stripe configuration endpoint
app.get('/api/stripe-config', (req, res) => {
  const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;

  if (!publishableKey) {
    console.error('STRIPE_PUBLISHABLE_KEY is not set in environment variables');
    return res.status(500).json({
      error: 'Stripe configuration missing. Please contact support.',
      publishableKey: null
    });
  }

  res.json({
    publishableKey: publishableKey
  });
});

// Debug middleware to log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Disable caching for development
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  next();
});

// Input validation and sanitization functions
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return DOMPurify.sanitize(input.trim());
};

const validateEmail = (email) => {
  return validator.isEmail(email) && email.length <= 254;
};

const validatePhone = (phone) => {
  if (!phone) return false;
  // Very flexible phone validation - just needs to have some digits
  const cleanPhone = phone.replace(/\D/g, '');
  return cleanPhone.length >= 7 && cleanPhone.length <= 20;
};

const validateName = (name) => {
  if (!name) return false;
  // Very flexible name validation - allow most characters except numbers and special symbols
  return name.length >= 2 && name.length <= 100 && !/^[\d\s\-'\.]+$/.test(name);
};

const validateDate = (date) => {
  if (!date) return false;

  // Parse date string (YYYY-MM-DD format) and compare date-only (ignore time/timezone)
  const inputDateParts = date.split('-');
  if (inputDateParts.length !== 3) return false;

  const inputYear = parseInt(inputDateParts[0], 10);
  const inputMonth = parseInt(inputDateParts[1], 10) - 1; // Month is 0-indexed
  const inputDay = parseInt(inputDateParts[2], 10);

  // Get today's date in local timezone (date-only, no time)
  const today = new Date();
  const todayYear = today.getFullYear();
  const todayMonth = today.getMonth();
  const todayDay = today.getDate();

  // Create date objects for comparison (date-only, no time)
  const inputDateOnly = new Date(inputYear, inputMonth, inputDay);
  const todayDateOnly = new Date(todayYear, todayMonth, todayDay);

  // Compare dates (input date should be today or later)
  return inputDateOnly >= todayDateOnly;
};

const validateTime = (time) => {
  const timeRegex = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
  return timeRegex.test(time);
};

const validateGuests = (guests, venue = 'xix') => {
  const num = parseInt(guests);
  if (venue === 'mirror') {
    return num >= 1 && num <= 300; // Mirror can accommodate up to 300 guests
  }
  return num >= 1 && num <= 20; // XIX restaurant limit
};

const validateSpecialRequests = (requests) => {
  // Special requests are completely optional
  return !requests || requests.length <= 1000;
};

// Mobile-specific validation functions
const validateMobileInput = (input, type = 'general') => {
  if (!input || typeof input !== 'string') return false;

  // Remove any mobile-specific characters that might cause issues
  const cleaned = input.replace(/[\u200B-\u200D\uFEFF]/g, ''); // Remove zero-width characters

  // Check for mobile-specific attack patterns
  const mobileAttackPatterns = [
    /javascript:/i,
    /data:text\/html/i,
    /vbscript:/i,
    /onload=/i,
    /onerror=/i,
    /onclick=/i,
    /<script/i,
    /<\/script>/i,
    /eval\(/i,
    /expression\(/i
  ];

  for (const pattern of mobileAttackPatterns) {
    if (pattern.test(cleaned)) {
      return false;
    }
  }

  return true;
};

const validateMobileUserAgent = (userAgent) => {
  if (!userAgent) return false;

  // Check for legitimate mobile user agents
  const legitimateMobilePatterns = [
    /Mobile/i,
    /Android/i,
    /iPhone/i,
    /iPad/i,
    /iPod/i,
    /BlackBerry/i,
    /IEMobile/i,
    /Opera Mini/i,
    /Windows Phone/i
  ];

  return legitimateMobilePatterns.some(pattern => pattern.test(userAgent));
};

// Initialize SQLite database
const db = new sqlite3.Database('./reservations.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Create reservations table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    guests INTEGER NOT NULL,
    table_preference TEXT,
    occasion TEXT,
    special_requests TEXT,
    venue TEXT DEFAULT 'XIX',
    event_type TEXT,
    menu_preference TEXT,
    entertainment TEXT,
    email_sent_to_customer BOOLEAN DEFAULT 0,
    email_sent_to_manager BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Add new columns to existing table if they don't exist
  db.run(`ALTER TABLE reservations ADD COLUMN email_sent_to_customer BOOLEAN DEFAULT 0`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding email_sent_to_customer column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN email_sent_to_manager BOOLEAN DEFAULT 0`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding email_sent_to_manager column:', err.message);
    }
  });

  // Add Mirror-specific columns
  db.run(`ALTER TABLE reservations ADD COLUMN venue TEXT DEFAULT 'XIX'`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding venue column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN event_type TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding event_type column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN menu_preference TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding menu_preference column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN entertainment TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding entertainment column:', err.message);
    }
  });

  // Create payments table (separate from reservations for better database design)
  // Payments are for events and don't require reservations
  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id INTEGER,
    payment_intent_id TEXT NOT NULL UNIQUE,
    amount_paid DECIMAL(10,2) NOT NULL,
    currency TEXT DEFAULT 'gbp',
    payment_status TEXT DEFAULT 'pending',
    event_type TEXT,
    customer_email TEXT,
    customer_name TEXT,
    stripe_session_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Error creating payments table:', err.message);
    } else {
      console.log('Payments table created/verified');
    }
  });

  // Remove foreign key constraint if it exists (payments don't require reservations)
  // SQLite doesn't support DROP CONSTRAINT, so we'll just make reservation_id nullable
  db.run(`ALTER TABLE payments ADD COLUMN reservation_id INTEGER`, (err) => {
    // Ignore error if column already exists or constraint doesn't exist
    if (err && !err.message.includes('duplicate column name')) {
      // Try to make reservation_id nullable (SQLite doesn't support ALTER COLUMN directly)
      // The column is already nullable in the new schema, so this is just for existing tables
    }
  });

  // Add UNIQUE constraint on payment_intent_id if it doesn't exist
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_intent_id ON payments(payment_intent_id)`, (err) => {
    if (err && !err.message.includes('already exists')) {
      console.error('Error creating unique index on payment_intent_id:', err.message);
    }
  });

  // Add event_type column if it doesn't exist (for existing payments tables)
  db.run(`ALTER TABLE payments ADD COLUMN event_type TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding event_type column to payments:', err.message);
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', database: 'connected' });
});

// Secret admin endpoint to view today's reservations
app.get('/admin/today', (req, res) => {
  const secretKey = req.query.key;
  const expectedKey = process.env.ADMIN_SECRET_KEY;

  if (secretKey !== expectedKey) {
    return res.status(403).json({ error: 'Unauthorized access' });
  }

  const today = new Date().toISOString().split('T')[0];

  db.all(
    'SELECT * FROM reservations WHERE date = ? ORDER BY time ASC',
    [today],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        date: today,
        totalReservations: rows.length,
        reservations: rows
      });
    }
  );
});

// Secret admin endpoint to view all reservations
app.get('/admin/all', (req, res) => {
  const secretKey = req.query.key;
  const expectedKey = process.env.ADMIN_SECRET_KEY;

  if (secretKey !== expectedKey) {
    return res.status(403).json({ error: 'Unauthorized access' });
  }

  db.all(
    'SELECT * FROM reservations ORDER BY date DESC, time ASC',
    [],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        totalReservations: rows.length,
        reservations: rows
      });
    }
  );
});

// Get all reservations (for admin)
app.get('/api/reservations', (req, res) => {
  db.all('SELECT * FROM reservations ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get all payments (for admin)
app.get('/api/payments', (req, res) => {
  db.all('SELECT * FROM payments ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get payments with reservation details (joined query)
app.get('/api/payments/with-reservations', (req, res) => {
  db.all(`
    SELECT 
      p.*,
      r.name as reservation_name,
      r.email as reservation_email,
      r.phone as reservation_phone,
      r.date as reservation_date,
      r.time as reservation_time,
      r.guests as reservation_guests,
      r.venue
    FROM payments p
    LEFT JOIN reservations r ON p.reservation_id = r.id
    ORDER BY p.created_at DESC
  `, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Debug endpoint to check payment and reservation data
app.get('/api/debug/payment-info', async (req, res) => {
  try {
    const { session_id } = req.query;

    if (!session_id) {
      return res.status(400).json({ error: 'Missing session_id parameter' });
    }

    console.log('🔍 DEBUG: Checking payment info for session:', session_id);

    // Retrieve the Checkout Session from Stripe
    const session = await stripe.checkout.sessions.retrieve(session_id);

    console.log('🔍 DEBUG: Session retrieved:', {
      id: session.id,
      payment_status: session.payment_status,
      amount_total: session.amount_total
    });

    const reservationId = session.metadata?.reservationId;
    const paymentIntentId = session.payment_intent || session.id;

    // Check if reservation exists
    let reservation = null;
    if (reservationId) {
      await new Promise((resolve) => {
        db.get('SELECT * FROM reservations WHERE id = ?', [reservationId], (err, row) => {
          if (!err) reservation = row;
          resolve();
        });
      });
    }

    // Check if payment exists
    let payment = null;
    await new Promise((resolve) => {
      db.get('SELECT * FROM payments WHERE payment_intent_id = ? OR stripe_session_id = ?',
        [paymentIntentId, session_id], (err, row) => {
          if (!err) payment = row;
          resolve();
        });
    });

    res.json({
      session: {
        id: session.id,
        payment_status: session.payment_status,
        amount_total: session.amount_total,
        customer_email: session.customer_email,
        payment_intent: session.payment_intent
      },
      metadata: session.metadata,
      reservationId: reservationId,
      paymentIntentId: paymentIntentId,
      reservation: reservation ? {
        id: reservation.id,
        name: reservation.name,
        email: reservation.email,
        exists: true
      } : { exists: false, id: reservationId },
      payment: payment ? {
        id: payment.id,
        reservation_id: payment.reservation_id,
        payment_intent_id: payment.payment_intent_id,
        stripe_session_id: payment.stripe_session_id,
        amount_paid: payment.amount_paid,
        exists: true
      } : { exists: false }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Test endpoint to manually save a payment (for debugging)
app.post('/api/debug/save-payment', async (req, res) => {
  try {
    const { session_id } = req.body;

    if (!session_id) {
      return res.status(400).json({ error: 'Missing session_id parameter' });
    }

    console.log('🧪 TEST: Manually saving payment for session:', session_id);

    // Retrieve the Checkout Session from Stripe
    const session = await stripe.checkout.sessions.retrieve(session_id);

    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment status is not paid', payment_status: session.payment_status });
    }

    const reservationId = session.metadata?.reservationId || null;
    const amountPaid = session.amount_total / 100;
    const eventType = session.metadata?.eventId ? 'event' : null;
    const paymentIntentId = session.payment_intent || session.id;

    console.log('🧪 TEST: Attempting to save payment with data:', {
      reservationId,
      paymentIntentId,
      amountPaid,
      currency: session.currency || 'gbp',
      eventType,
      customerEmail: session.customer_email || '',
      customerName: session.metadata?.customerName || '',
      stripeSessionId: session.id
    });

    // Save payment to database
    const saveResult = await savePaymentToDatabase({
      reservationId,
      paymentIntentId,
      amountPaid,
      currency: session.currency || 'gbp',
      eventType,
      customerEmail: session.customer_email || '',
      customerName: session.metadata?.customerName || '',
      stripeSessionId: session.id
    });

    console.log('🧪 TEST: Payment saved successfully:', saveResult);

    res.json({
      success: true,
      message: 'Payment saved successfully',
      paymentId: saveResult.id,
      updated: saveResult.updated
    });
  } catch (error) {
    console.error('🧪 TEST: Error saving payment:', error);
    res.status(500).json({
      error: error.message,
      code: error.code,
      details: error.stack
    });
  }
});

// Get reservations by date
app.get('/api/reservations/:date', (req, res) => {
  const { date } = req.params;
  db.all('SELECT * FROM reservations WHERE date = ? ORDER BY time', [date], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get reservations by venue
app.get('/api/reservations/venue/:venue', (req, res) => {
  const { venue } = req.params;
  db.all('SELECT * FROM reservations WHERE venue = ? ORDER BY date, time', [venue], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get reservations by venue and date
app.get('/api/reservations/venue/:venue/:date', (req, res) => {
  const { venue, date } = req.params;
  db.all('SELECT * FROM reservations WHERE venue = ? AND date = ? ORDER BY time', [venue, date], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// Get available time slots for a specific date
app.get('/api/availability/:date', (req, res) => {
  const { date } = req.params;
  const { venue = 'XIX' } = req.query;

  // Get all time slots for the day of week and venue
  // Parse date string (YYYY-MM-DD) to avoid timezone issues
  const dateParts = date.split('-');
  const dateYear = parseInt(dateParts[0], 10);
  const dateMonth = parseInt(dateParts[1], 10) - 1; // Month is 0-indexed
  const dateDay = parseInt(dateParts[2], 10);
  const dateObj = new Date(dateYear, dateMonth, dateDay);
  const dayOfWeek = dateObj.toLocaleDateString('en-US', { weekday: 'long' });

  // XIX Restaurant time slots (evening dining)
  const xixTimeSlots = {
    'Monday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Tuesday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Wednesday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Thursday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Friday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00', '22:30'],
    'Saturday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00', '22:30'],
    'Sunday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00']
  };

  // Mirror Banquet Hall time slots (all day events)
  const mirrorTimeSlots = {
    'Monday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00'],
    'Tuesday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00'],
    'Wednesday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00'],
    'Thursday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00'],
    'Friday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00', '22:00'],
    'Saturday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00', '22:00'],
    'Sunday': ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00']
  };

  const availableSlots = venue === 'Mirror' ? mirrorTimeSlots[dayOfWeek] || [] : xixTimeSlots[dayOfWeek] || [];

  // Get booked time slots for this date and venue
  db.all('SELECT time FROM reservations WHERE date = ? AND venue = ?', [date, venue], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }

    const bookedTimes = rows.map(row => row.time);
    const availableTimes = availableSlots.filter(time => !bookedTimes.includes(time));

    res.json({
      date: date,
      venue: venue,
      available: availableTimes,
      booked: bookedTimes,
      total: availableSlots.length
    });
  });
});

// Security monitoring endpoint (admin only)
app.get('/api/security/logs', (req, res) => {
  // Basic IP whitelist for admin access (in production, use proper authentication)
  const adminIPs = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
  if (process.env.NODE_ENV === 'production' && !adminIPs.includes(req.ip)) {
    logger.warn('Unauthorized access attempt to security logs', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
    return res.status(403).json({ error: 'Access denied' });
  }

  // Read and return recent security logs
  try {
    const fs = require('fs');
    const path = require('path');
    const logPath = path.join(__dirname, 'logs', 'security.log');

    if (fs.existsSync(logPath)) {
      const logs = fs.readFileSync(logPath, 'utf8');
      const recentLogs = logs.split('\n').slice(-50).filter(line => line.trim()); // Last 50 lines
      res.json({ logs: recentLogs });
    } else {
      res.json({ logs: [] });
    }
  } catch (error) {
    logger.error('Error reading security logs', { error: error.message });
    res.status(500).json({ error: 'Failed to read logs' });
  }
});

// Email endpoint with comprehensive validation
app.post('/api/send-reservation-email', async (req, res) => {
  try {
    const reservation = req.body;

    // Debug: Log the received reservation data
    console.log('Received reservation data:', reservation);

    // Basic validation
    if (!reservation) {
      return res.status(400).json({ error: 'Missing reservation data' });
    }

    // Mobile-specific security validation
    const userAgent = req.get('User-Agent') || '';
    const isMobile = /Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);

    if (isMobile) {
      // Validate mobile user agent
      if (!validateMobileUserAgent(userAgent)) {
        logger.warn('Suspicious mobile user agent detected', {
          ip: req.ip,
          userAgent: userAgent,
          timestamp: new Date().toISOString()
        });
        return res.status(400).json({ error: 'Invalid mobile device detected' });
      }

      // Mobile-specific input validation
      const mobileFields = ['name', 'email', 'phone', 'specialRequests', 'occasion', 'eventType', 'menuPreference', 'entertainment'];
      for (const field of mobileFields) {
        if (reservation[field] && !validateMobileInput(reservation[field])) {
          logger.warn('Mobile input validation failed', {
            ip: req.ip,
            userAgent: userAgent,
            field: field,
            value: reservation[field],
            timestamp: new Date().toISOString()
          });
          return res.status(400).json({ error: `Invalid input in ${field} field` });
        }
      }
    }

    // Auto-detect venue from referrer or request URL if not provided
    let detectedVenue = sanitizeInput(reservation.venue);
    if (!detectedVenue) {
      const referrer = req.get('Referer') || req.get('Referrer') || '';
      const requestUrl = req.originalUrl || req.url || '';

      if (referrer.includes('/mirror') || requestUrl.includes('/mirror')) {
        detectedVenue = 'mirror';
        console.log('Auto-detected venue as mirror from referrer:', referrer, 'or URL:', requestUrl);
      } else {
        detectedVenue = 'xix';
        console.log('Auto-detected venue as xix from referrer:', referrer, 'or URL:', requestUrl);
      }
    }

    // Sanitize all inputs and map field names
    const sanitizedReservation = {
      name: sanitizeInput(reservation.name),
      email: sanitizeInput(reservation.email),
      phone: sanitizeInput(reservation.phone),
      date: sanitizeInput(reservation.date),
      time: sanitizeInput(reservation.time),
      guests: reservation.guests,
      table: sanitizeInput(reservation.table),
      occasion: sanitizeInput(reservation.occasion),
      specialRequests: sanitizeInput(reservation.specialRequests),
      venue: detectedVenue,
      eventType: sanitizeInput(reservation.eventType || reservation['event-type']),
      menuPreference: sanitizeInput(reservation.menuPreference || reservation['menu-preference']),
      entertainment: sanitizeInput(reservation.entertainment)
    };

    // Comprehensive validation
    const errors = [];

    if (!validateName(sanitizedReservation.name)) {
      errors.push('Please enter your full name (2-100 characters)');
    }

    if (!validateEmail(sanitizedReservation.email)) {
      errors.push('Please provide a valid email address');
    }

    if (!validatePhone(sanitizedReservation.phone)) {
      errors.push('Please provide a valid phone number (7-20 digits)');
    }

    if (!validateDate(sanitizedReservation.date)) {
      errors.push('Please select a valid date (today or later)');
    }

    if (!validateTime(sanitizedReservation.time)) {
      errors.push('Please select a valid time');
    }

    if (!validateGuests(sanitizedReservation.guests, sanitizedReservation.venue)) {
      if (sanitizedReservation.venue === 'mirror') {
        errors.push('Number of guests must be between 1 and 300');
      } else {
        errors.push('Number of guests must be between 1 and 20');
      }
    }

    if (!validateSpecialRequests(sanitizedReservation.specialRequests)) {
      errors.push('Special requests must be 1000 characters or less');
    }

    if (errors.length > 0) {
      console.log('Validation errors:', errors);
      logger.warn('Reservation validation failed', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        errors: errors,
        reservationData: {
          name: sanitizedReservation.name,
          email: sanitizedReservation.email,
          phone: sanitizedReservation.phone,
          date: sanitizedReservation.date,
          time: sanitizedReservation.time,
          guests: sanitizedReservation.guests
        },
        timestamp: new Date().toISOString()
      });
      return res.status(400).json({
        error: 'Validation failed',
        details: errors
      });
    }

    let reservationId; // Store reservation ID for updating email status

    // Save reservation to database with venue-specific fields
    const stmt = db.prepare(`INSERT INTO reservations 
      (name, email, phone, date, time, guests, table_preference, occasion, special_requests, venue, event_type, menu_preference, entertainment, email_sent_to_customer, email_sent_to_manager) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    stmt.run([
      sanitizedReservation.name,
      sanitizedReservation.email,
      sanitizedReservation.phone,
      sanitizedReservation.date,
      sanitizedReservation.time,
      sanitizedReservation.guests,
      sanitizedReservation.table || null,
      sanitizedReservation.occasion || null,
      sanitizedReservation.specialRequests || null,
      sanitizedReservation.venue || 'XIX', // Default to XIX if not specified
      sanitizedReservation.eventType || null,
      sanitizedReservation.menuPreference || null,
      sanitizedReservation.entertainment || null,
      0, // email_sent_to_customer - will be updated after sending
      0  // email_sent_to_manager - will be updated after sending
    ], function (err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to save reservation' });
      }

      console.log(`Reservation saved with ID: ${this.lastID}`);
      reservationId = this.lastID; // Store for updating email status
    });

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: {
        rejectUnauthorized: false
      }
    });

    // Parse date string (YYYY-MM-DD) to avoid timezone issues
    const dateParts = sanitizedReservation.date.split('-');
    const dateYear = parseInt(dateParts[0], 10);
    const dateMonth = parseInt(dateParts[1], 10) - 1; // Month is 0-indexed
    const dateDay = parseInt(dateParts[2], 10);
    const dateObj = new Date(dateYear, dateMonth, dateDay);

    const date = dateObj.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    });

    const time24 = sanitizedReservation.time || '19:00';
    const [h, m] = time24.split(':');
    const hh = parseInt(h, 10);
    const time12 = `${(hh % 12) || 12}:${m} ${hh >= 12 ? 'PM' : 'AM'}`;

    const from = process.env.MAIL_FROM || process.env.SMTP_USER;
    const managerEmail = process.env.MANAGER_EMAIL || process.env.SMTP_USER;

    // Determine venue details
    const isMirror = sanitizedReservation.venue === 'Mirror';
    const venueName = isMirror ? 'Mirror Ukrainian Banquet Hall' : 'XIX Restaurant';
    const venueAddress = isMirror ? 'Mirror Ukrainian Banquet Hall, 123 King\'s Road, London SW3 4RD' : 'XIX Restaurant, 123 King\'s Road, London SW3 4RD';
    const eventDuration = isMirror ? 8 : 2; // Mirror events are all-day (8 hours), XIX is 2 hours

    // Customer confirmation email
    const customerSubject = `${venueName} Reservation Confirmed - ${date} at ${time12}`;
    const customerHtml = `
      <div style="font-family:Arial,Helvetica,sans-serif;color:#020702">
        <h2 style="font-family: 'Gilda Display', Georgia, serif;">Reservation Confirmed</h2>
        <p>Hi ${sanitizedReservation.name || ''},</p>
        <p>Your reservation at <strong>${venueName}</strong> is confirmed. Here are the details:</p>
        <ul>
          <li><strong>Date:</strong> ${date}</li>
          <li><strong>Time:</strong> ${time12}</li>
          <li><strong>Guests:</strong> ${sanitizedReservation.guests}</li>
          ${isMirror ? '' : `<li><strong>Table:</strong> ${sanitizedReservation.table || 'Any'}</li>`}
          ${sanitizedReservation.occasion ? `<li><strong>Occasion:</strong> ${sanitizedReservation.occasion}</li>` : ''}
          ${sanitizedReservation.eventType ? `<li><strong>Event Type:</strong> ${sanitizedReservation.eventType}</li>` : ''}
          ${sanitizedReservation.menuPreference ? `<li><strong>Menu Preference:</strong> ${sanitizedReservation.menuPreference}</li>` : ''}
          ${sanitizedReservation.entertainment ? `<li><strong>Entertainment:</strong> ${sanitizedReservation.entertainment}</li>` : ''}
        </ul>
        ${sanitizedReservation.specialRequests ? `<p><strong>Special requests:</strong> ${sanitizedReservation.specialRequests}</p>` : ''}
        <p>We look forward to welcoming you.</p>
        <p style="color:#6E6E6E">${venueAddress}</p>
      </div>
    `;

    // Create Google Calendar event URL
    const eventDate = new Date(`${sanitizedReservation.date}T${sanitizedReservation.time}:00`);
    const endDate = new Date(eventDate.getTime() + (eventDuration * 60 * 60 * 1000)); // Dynamic duration based on venue

    const eventTitle = `${isMirror ? 'Event' : 'Reservation'}: ${sanitizedReservation.name} (${sanitizedReservation.guests} guests)`;
    const eventDetails = `Customer: ${sanitizedReservation.name}
Email: ${sanitizedReservation.email}
Phone: ${sanitizedReservation.phone}
Guests: ${sanitizedReservation.guests}
${isMirror ? '' : `Table Preference: ${sanitizedReservation.table || 'Any Available'}`}
${sanitizedReservation.occasion ? `Occasion: ${sanitizedReservation.occasion}` : ''}
${sanitizedReservation.eventType ? `Event Type: ${sanitizedReservation.eventType}` : ''}
${sanitizedReservation.menuPreference ? `Menu Preference: ${sanitizedReservation.menuPreference}` : ''}
${sanitizedReservation.entertainment ? `Entertainment: ${sanitizedReservation.entertainment}` : ''}
${sanitizedReservation.specialRequests ? `Special Requests: ${sanitizedReservation.specialRequests}` : ''}

Reservation made through ${venueName} website.`;

    const location = venueAddress;

    // Format dates for Google Calendar (YYYYMMDDTHHMMSSZ)
    const formatDateForGoogle = (date) => {
      return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    };

    const googleCalendarUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(eventTitle)}&dates=${formatDateForGoogle(eventDate)}/${formatDateForGoogle(endDate)}&details=${encodeURIComponent(eventDetails)}&location=${encodeURIComponent(location)}`;

    // Manager notification email
    const managerSubject = `New ${isMirror ? 'Event' : 'Reservation'} - ${sanitizedReservation.name} - ${date} at ${time12}`;
    const managerHtml = `
      <div style="font-family:Arial,Helvetica,sans-serif;color:#020702">
        <h2 style="font-family: 'Gilda Display', Georgia, serif;">New ${isMirror ? 'Event Booking' : 'Table Reservation'}</h2>
        <p><strong>Customer Details:</strong></p>
        <ul>
          <li><strong>Name:</strong> ${sanitizedReservation.name}</li>
          <li><strong>Email:</strong> ${sanitizedReservation.email}</li>
          <li><strong>Phone:</strong> ${sanitizedReservation.phone}</li>
        </ul>
        <p><strong>${isMirror ? 'Event' : 'Reservation'} Details:</strong></p>
        <ul>
          <li><strong>Date:</strong> ${date}</li>
          <li><strong>Time:</strong> ${time12}</li>
          <li><strong>Guests:</strong> ${sanitizedReservation.guests}</li>
          ${isMirror ? '' : `<li><strong>Table Preference:</strong> ${sanitizedReservation.table || 'Any Available'}</li>`}
          ${sanitizedReservation.occasion ? `<li><strong>Occasion:</strong> ${sanitizedReservation.occasion}</li>` : ''}
          ${sanitizedReservation.eventType ? `<li><strong>Event Type:</strong> ${sanitizedReservation.eventType}</li>` : ''}
          ${sanitizedReservation.menuPreference ? `<li><strong>Menu Preference:</strong> ${sanitizedReservation.menuPreference}</li>` : ''}
          ${sanitizedReservation.entertainment ? `<li><strong>Entertainment:</strong> ${sanitizedReservation.entertainment}</li>` : ''}
        </ul>
        ${sanitizedReservation.specialRequests ? `<p><strong>Special Requests:</strong> ${sanitizedReservation.specialRequests}</p>` : ''}
        
        <div style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 4px solid #A8871A; border-radius: 4px;">
          <h3 style="margin-top: 0; color: #A8871A;">📅 Add to Google Calendar</h3>
          <p>Click the button below to add this reservation to your Google Calendar:</p>
          <a href="${googleCalendarUrl}" 
             style="display: inline-block; background-color: #A8871A; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px 0;">
            📅 Add to Google Calendar
          </a>
          <p style="font-size: 0.9em; color: #666; margin: 10px 0 0 0;">
            This will create a ${eventDuration}-hour event with all ${isMirror ? 'event' : 'reservation'} details pre-filled.
          </p>
        </div>
        
        <p style="color:#6E6E6E; font-size: 0.9em;">This reservation was made through the XIX Restaurant website.</p>
      </div>
    `;

    // Send both emails
    console.log('Attempting to send emails...');
    console.log('Customer email:', sanitizedReservation.email);
    console.log('Manager email:', managerEmail);

    const customerInfo = await transporter.sendMail({
      from,
      to: sanitizedReservation.email,
      subject: customerSubject,
      html: customerHtml
    });
    console.log('Customer email sent:', customerInfo.messageId);

    const managerInfo = await transporter.sendMail({
      from,
      to: managerEmail,
      subject: managerSubject,
      html: managerHtml
    });
    console.log('Manager email sent:', managerInfo.messageId);

    // Update email status in database
    if (reservationId) {
      db.run(
        'UPDATE reservations SET email_sent_to_customer = 1, email_sent_to_manager = 1 WHERE id = ?',
        [reservationId],
        (err) => {
          if (err) {
            console.error('Error updating email status:', err);
          } else {
            console.log('Email status updated for reservation ID:', reservationId);
          }
        }
      );
    }

    // Log successful reservation
    logger.info('Reservation successfully created', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      reservationId: reservationId,
      customerEmail: sanitizedReservation.email,
      customerName: sanitizedReservation.name,
      date: sanitizedReservation.date,
      time: sanitizedReservation.time,
      guests: sanitizedReservation.guests,
      timestamp: new Date().toISOString()
    });

    res.json({
      success: true,
      customerMessageId: customerInfo.messageId,
      managerMessageId: managerInfo.messageId,
      reservation: {
        name: sanitizedReservation.name,
        email: sanitizedReservation.email,
        phone: sanitizedReservation.phone,
        date: sanitizedReservation.date,
        time: sanitizedReservation.time,
        guests: sanitizedReservation.guests,
        table: sanitizedReservation.table,
        occasion: sanitizedReservation.occasion,
        specialRequests: sanitizedReservation.specialRequests,
        venue: sanitizedReservation.venue,
        eventType: sanitizedReservation.eventType,
        menuPreference: sanitizedReservation.menuPreference,
        entertainment: sanitizedReservation.entertainment
      }
    });
  } catch (err) {
    console.error('Email send error:', err);
    logger.error('Reservation email send failed', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      error: err.message,
      stack: err.stack,
      reservationData: {
        name: sanitizedReservation?.name,
        email: sanitizedReservation?.email,
        date: sanitizedReservation?.date,
        time: sanitizedReservation?.time
      },
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// API endpoint to check available times for a specific date
// Optimized: Only queries for specific date/venue instead of all reservations
app.get('/api/available-times', (req, res) => {
  const { date, venue } = req.query;

  if (!date) {
    return res.status(400).json({ error: 'Date parameter is required' });
  }

  const detectedVenue = venue || 'xix'; // Default to xix if not specified

  // Define all possible time slots
  const allTimeSlots = [
    '12:00', '13:00', '14:00', '15:00', '16:00',
    '17:00', '18:00', '19:00', '20:00', '21:00'
  ];

  // Optimized: Only query reservations for this specific date and venue
  db.all('SELECT time FROM reservations WHERE date = ? AND venue = ?', [date, detectedVenue], (err, rows) => {
    if (err) {
      console.error('Database error checking availability:', err);
      res.status(500).json({ error: err.message });
      return;
    }

    // Get booked times - filter out null values
    const bookedTimes = rows
      .map(r => r.time)
      .filter(time => time !== null && time !== undefined);

    // Filter out booked times
    const availableTimes = allTimeSlots.filter(time => !bookedTimes.includes(time));

    res.json({
      date: date,
      venue: detectedVenue,
      availableTimes: availableTimes,
      bookedTimes: bookedTimes,
      totalReservations: rows.length
    });
  });
});

// Stripe Payment Gateway Integration - Two Options:
// 1. Stripe Elements (embedded form) - current implementation
// 2. Stripe Checkout (hosted page) - alternative implementation

// Option 1: Stripe Elements - Create Payment Intent (current)
app.post('/api/create-payment', async (req, res) => {
  try {
    // Check if Stripe is initialized
    if (!stripe) {
      console.error('Stripe is not initialized - STRIPE_SECRET_KEY missing');
      return res.status(500).json({ error: 'Payment system not configured. Please contact support.' });
    }

    const { amount, eventId, reservationId, customerEmail, customerName } = req.body;

    // Validate required fields
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }

    // Create payment intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Convert to pence/cents
      currency: 'gbp',
      metadata: {
        eventId: eventId || null,
        reservationId: reservationId || null,
        customerEmail: customerEmail || null,
        customerName: customerName || null
      },
      description: `XIX Restaurant Payment - ${eventId ? 'Event' : 'Reservation'}`,
      automatic_payment_methods: {
        enabled: true,
      },
    });

    // Log payment intent creation
    logger.info('Payment intent created', {
      paymentIntentId: paymentIntent.id,
      amount: amount,
      currency: 'gbp',
      eventId: eventId,
      reservationId: reservationId,
      timestamp: new Date().toISOString()
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    });

  } catch (error) {
    console.error('Stripe payment creation error:', error);
    logger.error('Payment intent creation failed', {
      error: error.message,
      amount: req.body.amount,
      eventId: req.body.eventId,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ error: 'Failed to create payment intent' });
  }
});

// Option 2: Stripe Checkout - Create Checkout Session (hosted page)
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    // Check if Stripe is initialized
    if (!stripe) {
      console.error('Stripe is not initialized - STRIPE_SECRET_KEY missing');
      return res.status(500).json({ error: 'Payment system not configured. Please contact support.' });
    }

    const { amount, eventId, reservationId, customerEmail, customerName } = req.body;

    // Validate required fields
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }

    // Get base URL from request
    const baseUrl = req.protocol + '://' + req.get('host');
    const successUrl = `${baseUrl}/payment-success?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${baseUrl}/payment?amount=${amount}&reservationId=${reservationId || ''}&eventId=${eventId || ''}`;

    // Create Checkout Session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'gbp',
            product_data: {
              name: eventId ? 'Event Booking' : 'Restaurant Reservation',
              description: `XIX Restaurant - ${eventId ? 'Event' : 'Reservation'} Payment`,
            },
            unit_amount: Math.round(amount * 100), // Convert to pence
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      customer_email: customerEmail || undefined,
      metadata: {
        eventId: eventId || '',
        reservationId: reservationId || '',
        customerName: customerName || '',
      },
      success_url: successUrl,
      cancel_url: cancelUrl,
    });

    // Log checkout session creation
    logger.info('Checkout session created', {
      sessionId: session.id,
      amount: amount,
      currency: 'gbp',
      eventId: eventId,
      reservationId: reservationId,
      timestamp: new Date().toISOString()
    });

    res.json({
      sessionId: session.id,
      url: session.url
    });

  } catch (error) {
    console.error('Stripe Checkout creation error:', error);
    logger.error('Checkout session creation failed', {
      error: error.message,
      amount: req.body.amount,
      eventId: req.body.eventId,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Helper function to save payment to database (returns Promise)
function savePaymentToDatabase(paymentData) {
  console.log('💾 savePaymentToDatabase called with:', paymentData);
  return new Promise((resolve, reject) => {
    const {
      reservationId,
      paymentIntentId,
      amountPaid,
      currency,
      eventType,
      customerEmail,
      customerName,
      stripeSessionId
    } = paymentData;

    // Validate required fields
    if (!paymentIntentId) {
      const error = new Error('paymentIntentId is required');
      console.error('❌ Validation error:', error.message);
      reject(error);
      return;
    }

    // Check if payment already exists
    console.log('🔍 Checking for existing payment:', { paymentIntentId, stripeSessionId });
    db.get(
      'SELECT id FROM payments WHERE payment_intent_id = ? OR stripe_session_id = ?',
      [paymentIntentId, stripeSessionId || null],
      (err, existing) => {
        if (err) {
          console.error('❌ Error checking existing payment:', err);
          console.error('Error code:', err.code);
          console.error('Error message:', err.message);
          reject(err);
          return;
        }

        console.log('🔍 Existing payment check result:', existing ? `Found ID: ${existing.id}` : 'Not found');

        if (existing) {
          // Update existing payment
          db.run(
            `UPDATE payments SET 
              payment_status = 'paid',
              amount_paid = ?,
              reservation_id = ?,
              updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [amountPaid, reservationId, existing.id],
            function (err) {
              if (err) {
                console.error('Error updating payment record:', err);
                reject(err);
              } else {
                console.log('✓ Payment record updated in payments table (ID:', existing.id + ')');
                resolve({ id: existing.id, updated: true });
              }
            }
          );
        } else {
          // Insert new payment
          db.run(
            `INSERT INTO payments (reservation_id, payment_intent_id, amount_paid, currency, payment_status, event_type, customer_email, customer_name, stripe_session_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              reservationId,
              paymentIntentId,
              amountPaid,
              currency || 'gbp',
              'paid',
              eventType,
              customerEmail || '',
              customerName || '',
              stripeSessionId || null
            ],
            function (err) {
              if (err) {
                console.error('Error saving payment record:', err);
                console.error('Error code:', err.code);
                console.error('Error message:', err.message);
                console.error('Payment details:', paymentData);
                reject(err);
              } else {
                const paymentId = this.lastID;
                console.log('✓ Payment record saved to payments table successfully (ID:', paymentId + ')');

                // Verify the payment was actually saved
                db.get('SELECT * FROM payments WHERE id = ?', [paymentId], (verifyErr, savedPayment) => {
                  if (verifyErr) {
                    console.error('Error verifying payment save:', verifyErr);
                    reject(verifyErr);
                  } else if (!savedPayment) {
                    console.error('Payment was not saved! ID:', paymentId);
                    reject(new Error('Payment verification failed'));
                  } else {
                    console.log('✓ Payment verified in database:', savedPayment);
                    resolve({ id: paymentId, updated: false });
                  }
                });
              }
            }
          );
        }
      }
    );
  });
}

// Helper function to send payment confirmation emails
async function sendPaymentConfirmationEmails(session, reservation) {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: {
        rejectUnauthorized: false
      }
    });

    const from = process.env.MAIL_FROM || process.env.SMTP_USER;
    const managerEmail = process.env.MANAGER_EMAIL || process.env.SMTP_USER;
    const amountPaid = session.amount_total / 100;
    const paymentDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric'
    });
    const paymentTime = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit'
    });

    // Parse reservation date
    const dateParts = reservation.date.split('-');
    const dateYear = parseInt(dateParts[0], 10);
    const dateMonth = parseInt(dateParts[1], 10) - 1;
    const dateDay = parseInt(dateParts[2], 10);
    const dateObj = new Date(dateYear, dateMonth, dateDay);
    const formattedDate = dateObj.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    });

    const time24 = reservation.time || '19:00';
    const [h, m] = time24.split(':');
    const hh = parseInt(h, 10);
    const time12 = `${(hh % 12) || 12}:${m} ${hh >= 12 ? 'PM' : 'AM'}`;

    // Determine venue details
    const isMirror = reservation.venue === 'Mirror' || reservation.venue === 'mirror';
    const venueName = isMirror ? 'Mirror Ukrainian Banquet Hall' : 'XIX Restaurant';
    const venueAddress = isMirror ? 'Mirror Ukrainian Banquet Hall, 123 King\'s Road, London SW3 4RD' : 'XIX Restaurant, 123 King\'s Road, London SW3 4RD';

    // Generate invoice number (using session ID)
    const invoiceNumber = `INV-${session.id.substring(0, 12).toUpperCase()}`;

    // Customer Ticket/Invoice Email
    const customerSubject = `${venueName} - Payment Confirmation & Invoice #${invoiceNumber}`;
    const customerHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, Helvetica, sans-serif; color: #020702; line-height: 1.6; }
          .invoice-container { max-width: 600px; margin: 0 auto; background: #ffffff; }
          .invoice-header { background: linear-gradient(135deg, #A8871A 0%, #8B6F1A 100%); color: white; padding: 30px; text-align: center; }
          .invoice-header h1 { font-family: 'Gilda Display', Georgia, serif; margin: 0; font-size: 28px; }
          .invoice-body { padding: 30px; }
          .invoice-section { margin-bottom: 25px; }
          .invoice-section h2 { font-family: 'Gilda Display', Georgia, serif; color: #A8871A; border-bottom: 2px solid #A8871A; padding-bottom: 10px; margin-bottom: 15px; }
          .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
          .info-label { font-weight: 600; color: #333; }
          .info-value { color: #666; }
          .ticket-box { background: #f8f9fa; border: 2px solid #A8871A; border-radius: 8px; padding: 20px; margin: 20px 0; }
          .ticket-box h3 { margin-top: 0; color: #A8871A; }
          .payment-summary { background: #f8f9fa; border-left: 4px solid #A8871A; padding: 20px; margin: 20px 0; }
          .payment-summary h3 { margin-top: 0; color: #A8871A; }
          .total-amount { font-size: 24px; font-weight: bold; color: #A8871A; text-align: center; padding: 15px; background: white; border-radius: 8px; margin-top: 15px; }
          .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; border-top: 1px solid #eee; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="invoice-container">
          <div class="invoice-header">
            <h1>✓ Payment Confirmed</h1>
            <p style="margin: 10px 0 0 0; font-size: 16px;">Invoice #${invoiceNumber}</p>
          </div>
          
          <div class="invoice-body">
            <div class="invoice-section">
              <h2>Reservation Ticket</h2>
              <div class="ticket-box">
                <h3>${venueName}</h3>
                <div class="info-row">
                  <span class="info-label">Date:</span>
                  <span class="info-value">${formattedDate}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Time:</span>
                  <span class="info-value">${time12}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Number of Guests:</span>
                  <span class="info-value">${reservation.guests}</span>
                </div>
                ${reservation.table_preference ? `
                <div class="info-row">
                  <span class="info-label">Table Preference:</span>
                  <span class="info-value">${reservation.table_preference}</span>
                </div>
                ` : ''}
                ${reservation.occasion ? `
                <div class="info-row">
                  <span class="info-label">Occasion:</span>
                  <span class="info-value">${reservation.occasion}</span>
                </div>
                ` : ''}
                ${reservation.event_type ? `
                <div class="info-row">
                  <span class="info-label">Event Type:</span>
                  <span class="info-value">${reservation.event_type}</span>
                </div>
                ` : ''}
                <div class="info-row">
                  <span class="info-label">Location:</span>
                  <span class="info-value">${venueAddress}</span>
                </div>
                ${reservation.special_requests ? `
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ddd;">
                  <strong>Special Requests:</strong>
                  <p style="margin: 5px 0 0 0; color: #666;">${reservation.special_requests}</p>
                </div>
                ` : ''}
              </div>
            </div>

            <div class="invoice-section">
              <h2>Payment Invoice</h2>
              <div class="payment-summary">
                <div class="info-row">
                  <span class="info-label">Customer Name:</span>
                  <span class="info-value">${reservation.name}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Customer Email:</span>
                  <span class="info-value">${reservation.email}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Payment Date:</span>
                  <span class="info-value">${paymentDate} at ${paymentTime}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Payment Method:</span>
                  <span class="info-value">Stripe (Card Payment)</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Transaction ID:</span>
                  <span class="info-value">${session.payment_intent || session.id}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Session ID:</span>
                  <span class="info-value">${session.id}</span>
                </div>
                <div class="total-amount">
                  Total Paid: £${amountPaid.toFixed(2)}
                </div>
                <p style="text-align: center; color: #28a745; font-weight: 600; margin-top: 10px;">
                  ✓ Payment Status: Confirmed
                </p>
              </div>
            </div>

            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px;">
              <strong>Important Information:</strong>
              <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                <li>Please arrive 15 minutes before your reservation time</li>
                <li>This email serves as your confirmation ticket</li>
                <li>If you need to make changes, please contact us at least 24 hours in advance</li>
                <li>Keep this email for your records</li>
              </ul>
            </div>

            <p style="margin-top: 30px;">Thank you for choosing ${venueName}. We look forward to serving you!</p>
            <p>Best regards,<br><strong>The ${venueName} Team</strong></p>
          </div>

          <div class="footer">
            <p>${venueAddress}</p>
            <p>For inquiries, please contact: ${managerEmail}</p>
            <p style="margin-top: 10px; font-size: 10px; color: #999;">This is an automated email. Please do not reply directly to this message.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Manager Notification Email
    const managerSubject = `💰 New Paid Reservation - ${reservation.name} - ${formattedDate} at ${time12}`;
    const managerHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, Helvetica, sans-serif; color: #020702; line-height: 1.6; }
          .notification-container { max-width: 600px; margin: 0 auto; background: #ffffff; }
          .notification-header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .notification-header h1 { font-family: 'Gilda Display', Georgia, serif; margin: 0; }
          .notification-body { padding: 30px; }
          .info-section { background: #f8f9fa; border-left: 4px solid #A8871A; padding: 20px; margin: 15px 0; border-radius: 4px; }
          .info-section h3 { margin-top: 0; color: #A8871A; }
          .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
          .info-label { font-weight: 600; color: #333; }
          .info-value { color: #666; }
          .payment-highlight { background: #d4edda; border: 2px solid #28a745; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
          .payment-highlight h3 { margin-top: 0; color: #28a745; }
          .amount { font-size: 32px; font-weight: bold; color: #28a745; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="notification-container">
          <div class="notification-header">
            <h1>💰 New Paid Reservation</h1>
            <p style="margin: 10px 0 0 0;">Payment Received Successfully</p>
          </div>
          
          <div class="notification-body">
            <div class="payment-highlight">
              <h3>Payment Confirmed</h3>
              <div class="amount">£${amountPaid.toFixed(2)}</div>
              <p style="margin: 5px 0;">Transaction ID: ${session.payment_intent || session.id}</p>
              <p style="margin: 5px 0;">Session ID: ${session.id}</p>
            </div>

            <div class="info-section">
              <h3>Customer Information</h3>
              <div class="info-row">
                <span class="info-label">Name:</span>
                <span class="info-value">${reservation.name}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Email:</span>
                <span class="info-value"><a href="mailto:${reservation.email}">${reservation.email}</a></span>
              </div>
              <div class="info-row">
                <span class="info-label">Phone:</span>
                <span class="info-value"><a href="tel:${reservation.phone}">${reservation.phone}</a></span>
              </div>
            </div>

            <div class="info-section">
              <h3>Reservation Details</h3>
              <div class="info-row">
                <span class="info-label">Venue:</span>
                <span class="info-value">${venueName}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Date:</span>
                <span class="info-value">${formattedDate}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Time:</span>
                <span class="info-value">${time12}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Number of Guests:</span>
                <span class="info-value">${reservation.guests}</span>
              </div>
              ${reservation.table_preference ? `
              <div class="info-row">
                <span class="info-label">Table Preference:</span>
                <span class="info-value">${reservation.table_preference}</span>
              </div>
              ` : ''}
              ${reservation.occasion ? `
              <div class="info-row">
                <span class="info-label">Occasion:</span>
                <span class="info-value">${reservation.occasion}</span>
              </div>
              ` : ''}
              ${reservation.event_type ? `
              <div class="info-row">
                <span class="info-label">Event Type:</span>
                <span class="info-value">${reservation.event_type}</span>
              </div>
              ` : ''}
              ${reservation.menu_preference ? `
              <div class="info-row">
                <span class="info-label">Menu Preference:</span>
                <span class="info-value">${reservation.menu_preference}</span>
              </div>
              ` : ''}
              ${reservation.entertainment ? `
              <div class="info-row">
                <span class="info-label">Entertainment:</span>
                <span class="info-value">${reservation.entertainment}</span>
              </div>
              ` : ''}
              ${reservation.special_requests ? `
              <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ddd;">
                <strong>Special Requests:</strong>
                <p style="margin: 5px 0 0 0; color: #666;">${reservation.special_requests}</p>
              </div>
              ` : ''}
            </div>

            <div class="info-section">
              <h3>Payment Information</h3>
              <div class="info-row">
                <span class="info-label">Amount Paid:</span>
                <span class="info-value" style="font-weight: bold; color: #28a745;">£${amountPaid.toFixed(2)}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Payment Date:</span>
                <span class="info-value">${paymentDate} at ${paymentTime}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Payment Method:</span>
                <span class="info-value">Stripe Checkout</span>
              </div>
              <div class="info-row">
                <span class="info-label">Invoice Number:</span>
                <span class="info-value">${invoiceNumber}</span>
              </div>
            </div>

            <p style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-left: 4px solid #2196F3; border-radius: 4px;">
              <strong>Action Required:</strong> Please prepare for this reservation and ensure all special requests are noted.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send customer email
    const customerInfo = await transporter.sendMail({
      from,
      to: reservation.email || session.customer_email,
      subject: customerSubject,
      html: customerHtml
    });
    console.log('✓ Payment confirmation email sent to customer:', customerInfo.messageId);

    // Send manager email
    const managerInfo = await transporter.sendMail({
      from,
      to: managerEmail,
      subject: managerSubject,
      html: managerHtml
    });
    console.log('✓ Payment notification email sent to manager:', managerInfo.messageId);

    // Update email status in database
    db.run(
      'UPDATE reservations SET email_sent_to_customer = 1, email_sent_to_manager = 1 WHERE id = ?',
      [reservation.id],
      (err) => {
        if (err) {
          console.error('Error updating email status:', err);
        } else {
          console.log('✓ Email status updated for reservation ID:', reservation.id);
        }
      }
    );

    return { customerInfo, managerInfo };
  } catch (error) {
    console.error('Error sending payment confirmation emails:', error);
    logger.error('Failed to send payment confirmation emails', {
      sessionId: session?.id || 'unknown',
      reservationId: reservation?.id || 'unknown',
      error: error.message,
      timestamp: new Date().toISOString()
    });
    throw error;
  }
}

// Stripe Checkout Success Page - Verify payment and update reservation
app.get('/payment-success', async (req, res) => {
  console.log('🔵 PAYMENT-SUCCESS ENDPOINT CALLED');
  console.log('Query params:', req.query);

  try {
    const { session_id } = req.query;

    if (!session_id) {
      console.error('❌ Missing session_id parameter');
      return res.status(400).send('Missing session_id parameter');
    }

    console.log('📥 Retrieving Stripe session:', session_id);

    // Retrieve the Checkout Session
    const session = await stripe.checkout.sessions.retrieve(session_id);

    console.log('✅ Session retrieved:', {
      id: session.id,
      payment_status: session.payment_status,
      amount_total: session.amount_total,
      customer_email: session.customer_email,
      metadata: session.metadata
    });

    if (session.payment_status === 'paid') {
      console.log('💰 Payment is PAID - Processing payment save...');
      // Insert payment record into payments table
      // Payments are for events and don't require reservations
      const reservationId = session.metadata?.reservationId || null; // Optional - can be NULL
      const amountPaid = session.amount_total / 100; // Convert from pence/cents to pounds/dollars
      const eventType = session.metadata?.eventId ? 'event' : null;
      const paymentIntentId = session.payment_intent || session.id; // Use session.id as fallback

      // Save payment to database using helper function
      console.log('💾 Attempting to save payment to database with data:', {
        reservationId,
        paymentIntentId,
        amountPaid,
        currency: session.currency || 'gbp',
        eventType,
        customerEmail: session.customer_email || '',
        customerName: session.metadata?.customerName || '',
        stripeSessionId: session.id
      });

      try {
        const saveResult = await savePaymentToDatabase({
          reservationId,
          paymentIntentId,
          amountPaid,
          currency: session.currency || 'gbp',
          eventType,
          customerEmail: session.customer_email || '',
          customerName: session.metadata?.customerName || '',
          stripeSessionId: session.id
        });
        console.log('✅ Payment saved successfully in payment-success endpoint:', saveResult);
      } catch (paymentError) {
        console.error('❌ Payment save FAILED in payment-success:', paymentError);
        console.error('❌ Payment error details:', {
          message: paymentError.message,
          code: paymentError.code,
          stack: paymentError.stack,
          sessionId: session.id,
          reservationId: reservationId,
          paymentIntentId: paymentIntentId
        });
        logger.error('Failed to save payment to database (payment-success)', {
          sessionId: session.id,
          reservationId: reservationId,
          error: paymentError.message,
          code: paymentError.code,
          stack: paymentError.stack,
          timestamp: new Date().toISOString()
        });
        // Continue anyway to send emails, but log the error
      }

      // Retrieve reservation data and send confirmation emails (only if reservation exists)
      if (reservationId) {
        db.get(
          'SELECT * FROM reservations WHERE id = ?',
          [reservationId],
          async (err, reservation) => {
            if (err) {
              console.error('Error retrieving reservation for email:', err);
              logger.error('Failed to retrieve reservation for email', {
                reservationId: reservationId,
                error: err.message,
                timestamp: new Date().toISOString()
              });
            } else if (reservation) {
              try {
                await sendPaymentConfirmationEmails(session, reservation);
              } catch (emailError) {
                console.error('Error sending payment confirmation emails:', emailError);
                // Don't fail the request if email fails
              }
            } else {
              console.warn('Reservation not found for ID:', reservationId);
              console.warn('Payment saved successfully, but no reservation found for email');
            }
          }
        );
      } else {
        // Payment is for an event, no reservation needed
        console.log('Payment saved for event (no reservation required)');
        // TODO: Send event payment confirmation email if needed
      }

      // Log successful payment
      logger.info('Payment succeeded via Checkout', {
        sessionId: session.id,
        paymentIntentId: session.payment_intent,
        amount: session.amount_total / 100,
        currency: session.currency,
        customerEmail: session.customer_email,
        reservationId: session.metadata.reservationId,
        timestamp: new Date().toISOString()
      });

      // Send success page
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Payment Successful - XIX Restaurant</title>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <link rel="stylesheet" href="base.css">
          <link rel="stylesheet" href="navigation.css">
          <link rel="stylesheet" href="footer.css">
          <style>
            .success-container {
              max-width: 600px;
              margin: 4rem auto;
              padding: 2rem;
              text-align: center;
              background: var(--white);
              border-radius: 12px;
              box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            }
            .success-icon {
              font-size: 4rem;
              color: #28a745;
              margin-bottom: 1rem;
            }
            .success-message {
              font-family: 'Gilda Display', serif;
              font-size: 2rem;
              color: var(--very-dark-green);
              margin-bottom: 1rem;
            }
            .success-details {
              color: var(--dark-gray);
              margin-bottom: 2rem;
            }
            .btn-primary {
              padding: 1rem 2rem;
              background: var(--gold);
              color: var(--white);
              text-decoration: none;
              border-radius: 8px;
              display: inline-block;
            }
          </style>
        </head>
        <body>
          <nav class="navbar">
            <div class="nav-container">
              <div class="nav-logo">
                <a href="/xix"><h1>XIX</h1></a>
              </div>
            </div>
          </nav>
          <div class="success-container">
            <div class="success-icon">✓</div>
            <h1 class="success-message">Payment Successful!</h1>
            <p class="success-details">Your reservation has been confirmed. You will receive a confirmation email shortly.</p>
            <a href="/xix" class="btn-primary">Return to Home</a>
          </div>
        </body>
        </html>
      `);
    } else {
      console.log('⚠️ Payment status is not paid:', session.payment_status);
      res.status(400).send('Payment not completed');
    }
  } catch (error) {
    console.error('❌ ERROR in payment-success endpoint:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      type: error.type,
      code: error.code
    });
    logger.error('Error in payment-success endpoint', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).send('Error verifying payment');
  }
});

// Webhook endpoint for Stripe events
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  console.log('🔵 WEBHOOK ENDPOINT CALLED');
  const sig = req.headers['stripe-signature'];
  console.log('Webhook signature present:', !!sig);
  console.log('Webhook secret configured:', !!process.env.STRIPE_WEBHOOK_SECRET);

  let event;

  try {
    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      console.error('❌ STRIPE_WEBHOOK_SECRET not configured!');
      return res.status(500).send('Webhook secret not configured');
    }

    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log('✅ Webhook signature verified. Event type:', event.type);
    console.log('Event ID:', event.id);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    logger.warn('Invalid webhook signature', {
      error: err.message,
      timestamp: new Date().toISOString()
    });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  try {
    switch (event.type) {
      case 'payment_intent.succeeded': {
        const paymentIntent = event.data.object;
        console.log('Webhook: Payment succeeded:', paymentIntent.id);

        const reservationId = paymentIntent.metadata?.reservationId || null;
        const amountPaid = paymentIntent.amount / 100;
        const eventType = paymentIntent.metadata?.eventId ? 'event' : null;

        // Save payment to database
        try {
          await savePaymentToDatabase({
            reservationId,
            paymentIntentId: paymentIntent.id,
            amountPaid,
            currency: paymentIntent.currency || 'gbp',
            eventType,
            customerEmail: paymentIntent.metadata?.customerEmail || '',
            customerName: paymentIntent.metadata?.customerName || '',
            stripeSessionId: null
          });
        } catch (paymentError) {
          console.error('Failed to save payment in webhook:', paymentError);
          logger.error('Failed to save payment in webhook', {
            paymentIntentId: paymentIntent.id,
            error: paymentError.message,
            timestamp: new Date().toISOString()
          });
        }

        // Send confirmation email if reservation exists
        if (reservationId) {
          db.get('SELECT * FROM reservations WHERE id = ?', [reservationId], async (err, reservation) => {
            if (err || !reservation) {
              console.warn('Reservation not found for email:', reservationId);
              return;
            }

            const mockSession = {
              id: paymentIntent.id,
              payment_intent: paymentIntent.id,
              amount_total: paymentIntent.amount,
              currency: paymentIntent.currency || 'gbp',
              customer_email: paymentIntent.metadata?.customerEmail || reservation.email,
              metadata: paymentIntent.metadata
            };

            try {
              await sendPaymentConfirmationEmails(mockSession, reservation);
              console.log('✓ Webhook (Payment Intent): Payment confirmation emails sent');
            } catch (emailError) {
              console.error('Error sending confirmation email:', emailError);
            }
          });
        }

        logger.info('Payment succeeded (webhook)', {
          paymentIntentId: paymentIntent.id,
          amount: paymentIntent.amount,
          currency: paymentIntent.currency,
          timestamp: new Date().toISOString()
        });
        break;
      }

      case 'checkout.session.completed': {
        const session = event.data.object;
        console.log('🔵 Webhook: Checkout session completed:', session.id);
        console.log('Session details:', {
          id: session.id,
          payment_status: session.payment_status,
          amount_total: session.amount_total,
          customer_email: session.customer_email,
          metadata: session.metadata
        });

        // Only process if payment was successful
        if (session.payment_status !== 'paid') {
          console.log('⚠️ Session payment status is not paid:', session.payment_status);
          break;
        }

        const reservationId = session.metadata?.reservationId || null;
        const amountPaid = session.amount_total / 100;
        const eventType = session.metadata?.eventId ? 'event' : null;
        const paymentIntentId = session.payment_intent || session.id;

        console.log('💾 Webhook: Attempting to save payment with data:', {
          reservationId,
          paymentIntentId,
          amountPaid,
          currency: session.currency || 'gbp',
          eventType,
          customerEmail: session.customer_email || '',
          customerName: session.metadata?.customerName || '',
          stripeSessionId: session.id
        });

        // Save payment to database
        try {
          const saveResult = await savePaymentToDatabase({
            reservationId,
            paymentIntentId,
            amountPaid,
            currency: session.currency || 'gbp',
            eventType,
            customerEmail: session.customer_email || '',
            customerName: session.metadata?.customerName || '',
            stripeSessionId: session.id
          });
          console.log('✅ Webhook: Payment saved successfully:', saveResult);
        } catch (paymentError) {
          console.error('❌ Webhook: Failed to save payment:', paymentError);
          console.error('❌ Error details:', {
            message: paymentError.message,
            code: paymentError.code,
            stack: paymentError.stack
          });
          logger.error('Failed to save payment in webhook', {
            sessionId: session.id,
            error: paymentError.message,
            code: paymentError.code,
            timestamp: new Date().toISOString()
          });
        }

        // Send confirmation email if reservation exists
        if (reservationId) {
          db.get('SELECT * FROM reservations WHERE id = ?', [reservationId], async (err, reservation) => {
            if (err || !reservation) {
              console.warn('Reservation not found for email:', reservationId);
              return;
            }

            try {
              await sendPaymentConfirmationEmails(session, reservation);
              console.log('✓ Webhook: Payment confirmation emails sent');
            } catch (emailError) {
              console.error('Error sending confirmation email:', emailError);
            }
          });
        }

        logger.info('Payment succeeded via Checkout (webhook)', {
          sessionId: session.id,
          paymentIntentId: session.payment_intent,
          amount: session.amount_total / 100,
          currency: session.currency,
          timestamp: new Date().toISOString()
        });
        break;
      }

      case 'payment_intent.payment_failed': {
        const failedPayment = event.data.object;
        console.log('Payment failed:', failedPayment.id);

        logger.warn('Payment failed', {
          paymentIntentId: failedPayment.id,
          amount: failedPayment.amount,
          currency: failedPayment.currency,
          error: failedPayment.last_payment_error,
          timestamp: new Date().toISOString()
        });
        break;
      }

      default:
        console.log(`Unhandled event type: ${event.type}`);
    }

    // Always return success to Stripe (even if there were errors)
    // This prevents Stripe from retrying the webhook
    res.json({ received: true });
  } catch (error) {
    console.error('Error processing webhook:', error);
    logger.error('Webhook processing error', {
      eventType: event.type,
      error: error.message,
      timestamp: new Date().toISOString()
    });
    // Still return success to prevent retries
    res.json({ received: true, error: error.message });
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Database connection closed.');
    process.exit(0);
  });
});

// Serve admin dashboard
app.get('/admin', (req, res) => {
  const secretKey = req.query.key;
  const expectedKey = process.env.ADMIN_SECRET_KEY;

  if (secretKey !== expectedKey) {
    return res.status(403).send(`
      <html>
        <head><title>Access Denied</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1>Access Denied</h1>
          <p>Please provide a valid secret key.</p>
        </body>
      </html>
    `);
  }

  res.sendFile(__dirname + '/admin-dashboard.html');
});

// Database viewer route (without .html extension) - Protected with password
app.get('/database-viewer', (req, res) => {
  const secretKey = req.query.key;
  const expectedKey = process.env.ADMIN_SECRET_KEY;

  if (secretKey !== expectedKey) {
    return res.status(403).send(`
      <html>
        <head>
          <title>Access Denied - Database Viewer</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #d32f2f; margin-bottom: 20px; }
            p { color: #666; margin-bottom: 30px; }
            .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-top: 20px; color: #1976d2; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🔒 Access Denied</h1>
            <p>Please provide a valid secret key to access the database viewer.</p>
            <div class="info">
              <strong>Usage:</strong> /database-viewer?key=YOUR_ADMIN_SECRET_KEY
            </div>
          </div>
        </body>
      </html>
    `);
  }

  res.sendFile(__dirname + '/database-viewer.html');
});

// Serve static files (HTML, CSS, JS, images) - AFTER all explicit routes
// Disable default index.html serving to allow our explicit routes to work
app.use(express.static('.', { index: false }));

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
  console.log(`View reservations: http://localhost:${port}/api/reservations`);
  console.log(`Admin dashboard: http://localhost:${port}/admin?key=xix-admin-2024`);
});