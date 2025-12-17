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

// Initialize Google Calendar API (optional)
let calendar;
if (process.env.GOOGLE_CALENDAR_CREDENTIALS_PATH && process.env.GOOGLE_CALENDAR_ID) {
  try {
    const { google } = require('googleapis');
    const auth = new google.auth.GoogleAuth({
      keyFile: process.env.GOOGLE_CALENDAR_CREDENTIALS_PATH,
      scopes: ['https://www.googleapis.com/auth/calendar']
    });
    calendar = google.calendar({ version: 'v3', auth });
    console.log('✅ Google Calendar API initialized');
  } catch (err) {
    console.warn('⚠️  Google Calendar API not configured. Calendar sync will be disabled.');
    calendar = null;
  }
} else {
  console.warn('⚠️  GOOGLE_CALENDAR_CREDENTIALS_PATH or GOOGLE_CALENDAR_ID not set. Calendar sync disabled.');
  calendar = null;
}

// Initialize Twilio SMS (optional)
let twilioClient;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.ENABLE_SMS_REMINDERS === 'true') {
  try {
    twilioClient = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    console.log('✅ Twilio SMS initialized');
  } catch (err) {
    console.warn('⚠️  Twilio SMS not configured. SMS reminders will be disabled.');
    twilioClient = null;
  }
} else {
  console.warn('⚠️  Twilio credentials not set or SMS disabled. SMS reminders disabled.');
  twilioClient = null;
}

const app = express();
const port = process.env.PORT || 3001;

// Trust proxy for dev tunnels and production deployments
// Set to 1 to trust only the first proxy (prevents IP spoofing)
// In production behind nginx/load balancer, this is safe
// Set to true only if you're behind a trusted reverse proxy
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : true);

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
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://use.fontawesome.com", "https://checkout.stripe.com", "https://js.stripe.com", "https://stripecdn.com"],
      fontSrc: ["'self'", "data:", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "https://use.fontawesome.com", "https://checkout.stripe.com", "https://js.stripe.com", "https://stripecdn.com", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com", "https://js.stripe.com", "https://checkout.stripe.com", "https://stripecdn.com", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      imgSrc: ["'self'", "data:", "https:", "https://js.stripe.com", "https://stripecdn.com"],
      connectSrc: ["'self'", "https://api.stripe.com", "https://checkout.stripe.com", "https://js.stripe.com", "https://hooks.stripe.com", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      frameSrc: ["'self'", "https://js.stripe.com", "https://hooks.stripe.com", "https://checkout.stripe.com", "https://hcaptcha.com", "https://*.hcaptcha.com", "https://www.google.com", "https://maps.google.com", "https://*.google.com"],
      frameAncestors: ["'self'"],
      workerSrc: ["'self'", "blob:"],
      childSrc: ["'self'", "blob:"]
    }
  } : false // Disable CSP in development
}));

// Rate limiting - Very lenient for restaurant website
// Note: trust proxy is configured above to trust only first proxy (1) in production
// This prevents IP spoofing while still working correctly behind reverse proxies
// The validation warning can be safely ignored since we're using a secure configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 1000 : 10000, // Very high limits
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
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


app.get('/xix/catering', (req, res) => {
  console.log('✅ /xix/catering route hit');
  const filePath = __dirname + '/catering.html';
  console.log('Serving file from:', filePath);
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error('Error serving catering.html:', err);
      res.status(500).send('Error loading catering page');
    }
  });
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

app.get('/mirror/catering', (req, res) => {
  res.sendFile(__dirname + '/catering.html');
});

app.get('/offline', (req, res) => {
  res.sendFile(__dirname + '/offline.html');
});

// Event mapping - maps eventId to event title and date
// This is used to populate event_type and event_date in the payments table
const eventMapping = {
  'wine-cheese-evening': {
    title: 'Wine & Cheese Evening',
    date: '2025-01-15'
  },
  'jazz-night': {
    title: 'Jazz Night with Sarah Johnson',
    date: '2025-01-22'
  },
  'valentines-special': {
    title: 'Valentine\'s Day Special',
    date: '2025-02-14'
  },
  'burgundy-wine-masterclass': {
    title: 'Burgundy Wine Masterclass',
    date: '2025-02-05'
  },
  'ukrainian-new-year': {
    title: 'Ukrainian New Year Celebration',
    date: '2025-01-15'
  }
};

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

// Helper function to get base URL for confirmation links
function getBaseUrl() {
  // Use BASE_URL from environment if set
  if (process.env.BASE_URL) {
    return process.env.BASE_URL;
  }

  // In production, default to the production domain
  if (process.env.NODE_ENV === 'production') {
    return 'https://xixlondon.co.uk';
  }

  // In development, use localhost
  return 'http://localhost:3001';
}

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

  // Add table assignment and confirmation columns
  db.run(`ALTER TABLE reservations ADD COLUMN assigned_table TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding assigned_table column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN end_time TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding end_time column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN google_calendar_event_id TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding google_calendar_event_id column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN confirmation_status TEXT DEFAULT 'pending'`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding confirmation_status column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN confirmation_deadline DATETIME`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding confirmation_deadline column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN confirmation_token TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding confirmation_token column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN confirmed_at DATETIME`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding confirmed_at column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN last_synced_at DATETIME`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding last_synced_at column:', err.message);
    }
  });

  // Create tables reference table (22 tables with capacity 2-6 people)
  db.run(`CREATE TABLE IF NOT EXISTS tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_number TEXT NOT NULL UNIQUE,
    capacity INTEGER NOT NULL,
    venue TEXT DEFAULT 'XIX',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Error creating tables table:', err.message);
    } else {
      console.log('Tables table created/verified');

      // Initialize/Update tables based on actual restaurant layout
      // 7 tables for 2 people, 1 table for 3 people, 6 tables for 4 people,
      // 3 tables for 6 people, 1 table for 12 people
      db.get('SELECT COUNT(*) as count FROM tables WHERE venue = ?', ['XIX'], (err, row) => {
        if (err) {
          console.error('Error checking tables:', err.message);
          return;
        }

        const tables = [
          // 7 tables for 2 people
          { number: 'Table 2-1', capacity: 2 },
          { number: 'Table 2-2', capacity: 2 },
          { number: 'Table 2-3', capacity: 2 },
          { number: 'Table 2-4', capacity: 2 },
          { number: 'Table 2-5', capacity: 2 },
          { number: 'Table 2-6', capacity: 2 },
          { number: 'Table 2-7', capacity: 2 },
          // 1 table for 3 people
          { number: 'Table 3-1', capacity: 3 },
          // 6 tables for 4 people
          { number: 'Table 4-1', capacity: 4 },
          { number: 'Table 4-2', capacity: 4 },
          { number: 'Table 4-3', capacity: 4 },
          { number: 'Table 4-4', capacity: 4 },
          { number: 'Table 4-5', capacity: 4 },
          { number: 'Table 4-6', capacity: 4 },
          // 3 tables for 6 people
          { number: 'Table 6-1', capacity: 6 },
          { number: 'Table 6-2', capacity: 6 },
          { number: 'Table 6-3', capacity: 6 },
          // 1 table for 12 people (can be used for 7+ people, can be split for 2x5 via phone call)
          { number: 'Table 12-1', capacity: 12 },
        ];

        if (row.count === 0) {
          // No tables exist, initialize them
          console.log('Initializing tables based on restaurant layout...');
          const stmt = db.prepare('INSERT INTO tables (table_number, capacity, venue) VALUES (?, ?, ?)');

          tables.forEach((table) => {
            stmt.run(table.number, table.capacity, 'XIX');
          });

          stmt.finalize((err) => {
            if (err) {
              console.error('Error initializing tables:', err.message);
            } else {
              console.log(`✅ ${tables.length} tables initialized successfully`);
              console.log('   - 7 tables for 2 people');
              console.log('   - 1 table for 3 people');
              console.log('   - 6 tables for 4 people');
              console.log('   - 3 tables for 6 people');
              console.log('   - 1 table for 12 people (for 7+ people, can be split for 2x5 via phone call)');
            }
          });
        } else {
          // Tables exist, update them to match the new layout while preserving IDs
          console.log(`Updating existing tables (${row.count} found) to match new layout...`);

          // Use UPSERT logic: Update existing tables, insert missing ones
          // This preserves table IDs which are referenced in reservations
          const updateStmt = db.prepare('UPDATE tables SET capacity = ? WHERE table_number = ? AND venue = ?');
          const insertStmt = db.prepare('INSERT INTO tables (table_number, capacity, venue) VALUES (?, ?, ?)');

          let updatedCount = 0;
          let insertedCount = 0;
          let processedCount = 0;

          tables.forEach((table) => {
            // Check if table exists by table_number
            db.get('SELECT id FROM tables WHERE table_number = ? AND venue = ?', [table.number, 'XIX'], (err, existingTable) => {
              if (err) {
                console.error(`Error checking table ${table.number}:`, err.message);
                processedCount++;
                if (processedCount === tables.length) {
                  finalizeUpdate();
                }
                return;
              }

              if (existingTable) {
                // Table exists, update it (preserves ID)
                updateStmt.run(table.capacity, table.number, 'XIX', (updateErr) => {
                  if (updateErr) {
                    console.error(`Error updating table ${table.number}:`, updateErr.message);
                  } else {
                    updatedCount++;
                  }
                  processedCount++;
                  if (processedCount === tables.length) {
                    finalizeUpdate();
                  }
                });
              } else {
                // Table doesn't exist, insert it
                insertStmt.run(table.number, table.capacity, 'XIX', (insertErr) => {
                  if (insertErr) {
                    console.error(`Error inserting table ${table.number}:`, insertErr.message);
                  } else {
                    insertedCount++;
                  }
                  processedCount++;
                  if (processedCount === tables.length) {
                    finalizeUpdate();
                  }
                });
              }
            });
          });

          function finalizeUpdate() {
            updateStmt.finalize();
            insertStmt.finalize();

            // Delete any tables that are no longer in the layout (orphaned tables)
            const tableNumbers = tables.map(t => t.number);
            const placeholders = tableNumbers.map(() => '?').join(',');
            db.run(
              `DELETE FROM tables WHERE venue = ? AND table_number NOT IN (${placeholders})`,
              ['XIX', ...tableNumbers],
              (deleteErr) => {
                if (deleteErr) {
                  console.error('Error deleting orphaned tables:', deleteErr.message);
                } else {
                  console.log(`✅ Tables updated successfully (${updatedCount} updated, ${insertedCount} inserted)`);
                  console.log('   - 7 tables for 2 people');
                  console.log('   - 1 table for 3 people');
                  console.log('   - 6 tables for 4 people');
                  console.log('   - 3 tables for 6 people');
                  console.log('   - 1 table for 12 people (for 7+ people, can be split for 2x5 via phone call)');
                }
              }
            );
          }
        }
      });
    }
  });

  // Create payments table (separate from reservations for better database design)
  // Payments are for events and don't require reservations
  // NOTE: reservation_id is removed - payments don't need to link to reservations
  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_intent_id TEXT NOT NULL UNIQUE,
    amount_paid DECIMAL(10,2) NOT NULL,
    currency TEXT DEFAULT 'gbp',
    payment_status TEXT DEFAULT 'pending',
    event_type TEXT,
    event_date TEXT,
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

  // Add event_date column if it doesn't exist
  db.run(`ALTER TABLE payments ADD COLUMN event_date TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding event_date column to payments:', err.message);
    }
  });

  // Migration: Remove reservation_id column from payments table
  // SQLite doesn't support DROP COLUMN, so we need to recreate the table
  db.get("SELECT sql FROM sqlite_master WHERE type='table' AND name='payments'", (err, row) => {
    if (err) {
      console.error('Error checking payments table schema:', err);
      return;
    }

    // Check if reservation_id column exists
    if (row && row.sql && row.sql.includes('reservation_id')) {
      console.log('⚠️  Payments table has reservation_id column - migrating to remove it...');

      // Create new table without reservation_id
      db.run(`CREATE TABLE IF NOT EXISTS payments_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
          console.error('Error creating new payments table:', err);
          return;
        }

        // Copy existing data (excluding reservation_id)
        db.run(`INSERT INTO payments_new 
          SELECT id, payment_intent_id, amount_paid, currency, 
                 payment_status, event_type, customer_email, customer_name, 
                 stripe_session_id, created_at, updated_at
          FROM payments`, (err) => {
          if (err) {
            console.error('Error copying data to new payments table:', err);
            return;
          }

          // Drop old table
          db.run(`DROP TABLE payments`, (err) => {
            if (err) {
              console.error('Error dropping old payments table:', err);
              return;
            }

            // Rename new table
            db.run(`ALTER TABLE payments_new RENAME TO payments`, (err) => {
              if (err) {
                console.error('Error renaming payments table:', err);
              } else {
                console.log('✅ Payments table migrated successfully - reservation_id column removed');
              }
            });
          });
        });
      });
    } else {
      console.log('✅ Payments table schema is correct - no reservation_id column');
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
// Join with tables table to get table_number when assigned_table is a table ID
app.get('/api/reservations', (req, res) => {
  db.all(`
    SELECT r.*, 
           t.table_number as table_name,
           t.capacity as table_capacity
    FROM reservations r
    LEFT JOIN tables t ON r.assigned_table = t.id
    ORDER BY r.created_at DESC
  `, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    // Map the result to include table_number in assigned_table for backward compatibility
    const mappedRows = rows.map(row => ({
      ...row,
      // If assigned_table is an ID and we have table_name, use table_name for display
      // Keep assigned_table as ID for internal use
      assigned_table_display: row.table_name || row.assigned_table || null
    }));
    res.json(mappedRows);
  });
});

// Delete reservation endpoint
app.delete('/api/reservations/:id', (req, res) => {
  const reservationId = parseInt(req.params.id);

  if (!reservationId || isNaN(reservationId)) {
    return res.status(400).json({ error: 'Invalid reservation ID' });
  }

  // First, get the reservation to check for Google Calendar event ID
  db.get('SELECT google_calendar_event_id FROM reservations WHERE id = ?', [reservationId], (err, reservation) => {
    if (err) {
      console.error('Error fetching reservation:', err);
      return res.status(500).json({ error: 'Failed to fetch reservation: ' + err.message });
    }

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    const calendarEventId = reservation.google_calendar_event_id;

    // Delete from database
    db.run('DELETE FROM reservations WHERE id = ?', [reservationId], function (deleteErr) {
      if (deleteErr) {
        console.error('Error deleting reservation:', deleteErr);
        return res.status(500).json({ error: 'Failed to delete reservation: ' + deleteErr.message });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Reservation not found' });
      }

      console.log(`✅ Reservation ${reservationId} deleted from database`);

      // If there's a Google Calendar event ID, delete it from Google Calendar too
      if (calendarEventId && calendar && process.env.GOOGLE_CALENDAR_ID) {
        const calendarId = process.env.GOOGLE_CALENDAR_ID;
        calendar.events.delete({
          calendarId: calendarId,
          eventId: calendarEventId
        }).then(() => {
          console.log(`✅ Google Calendar event ${calendarEventId} deleted successfully`);
          res.json({
            success: true,
            message: `Reservation ${reservationId} and Google Calendar event deleted successfully`
          });
        }).catch((calendarErr) => {
          console.error('⚠️ Error deleting Google Calendar event:', calendarErr.message);
          // Still return success since DB deletion succeeded
          res.json({
            success: true,
            message: `Reservation ${reservationId} deleted from database, but Google Calendar deletion failed: ${calendarErr.message}`,
            warning: 'Google Calendar event may still exist'
          });
        });
      } else {
        // No calendar event to delete, or calendar not configured
        res.json({ success: true, message: `Reservation ${reservationId} deleted successfully` });
      }
    });
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
// Note: reservation_id column removed, but we can still get reservation date from reservations table
// For event payments, we'll try to find a matching reservation by email and date
app.get('/api/payments/with-reservations', (req, res) => {
  db.all(`
    SELECT 
      p.*,
      p.event_date as reservation_date,
      r.time as reservation_time,
      r.name as reservation_name,
      r.email as reservation_email
    FROM payments p
    LEFT JOIN reservations r ON (
      r.email = p.customer_email 
      AND r.date >= date('now', '-30 days')
      AND r.event_type IS NOT NULL
    )
    ORDER BY p.created_at DESC
  `, (err, rows) => {
    if (err) {
      // If join fails, just return payments without reservation data
      db.all('SELECT * FROM payments ORDER BY created_at DESC', (err2, rows2) => {
        if (err2) {
          res.status(500).json({ error: err2.message });
          return;
        }
        // Use event_date as reservation_date if available
        const paymentsWithDates = rows2.map(p => ({
          ...p,
          reservation_date: p.event_date || null,
          reservation_time: null,
          reservation_name: null,
          reservation_email: null
        }));
        res.json(paymentsWithDates);
      });
      return;
    }
    // Use event_date as reservation_date if available
    const processedRows = rows.map(payment => ({
      ...payment,
      reservation_date: payment.event_date || payment.reservation_date || null
    }));
    res.json(processedRows);
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
        payment_intent_id: payment.payment_intent_id,
        stripe_session_id: payment.stripe_session_id,
        amount_paid: payment.amount_paid,
        event_type: payment.event_type,
        event_date: payment.event_date,
        customer_email: payment.customer_email,
        customer_name: payment.customer_name,
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
    const { session_id, payment_intent_id } = req.body;

    if (!session_id && !payment_intent_id) {
      return res.status(400).json({ error: 'Missing session_id or payment_intent_id parameter' });
    }

    console.log('🧪 TEST: Manually saving payment');

    let session = null;
    let paymentIntent = null;

    // Try to get session first
    if (session_id) {
      try {
        session = await stripe.checkout.sessions.retrieve(session_id);
        console.log('🧪 TEST: Retrieved session:', session.id);
      } catch (err) {
        console.error('🧪 TEST: Could not retrieve session:', err.message);
      }
    }

    // Try to get payment intent
    if (payment_intent_id || (session && session.payment_intent)) {
      try {
        paymentIntent = await stripe.paymentIntents.retrieve(payment_intent_id || session.payment_intent);
        console.log('🧪 TEST: Retrieved payment intent:', paymentIntent.id);
      } catch (err) {
        console.error('🧪 TEST: Could not retrieve payment intent:', err.message);
      }
    }

    // Use session data if available (has all metadata), otherwise use payment intent
    // Note: reservation_id column removed from payments table
    const amountPaid = session ? (session.amount_total / 100) : (paymentIntent ? (paymentIntent.amount / 100) : 0);
    const eventType = (session?.metadata?.eventId || paymentIntent?.metadata?.eventId) ? 'event' : null;
    const paymentIntentId = paymentIntent?.id || session?.payment_intent || payment_intent_id;
    const customerEmail = session?.customer_email || paymentIntent?.receipt_email || paymentIntent?.metadata?.customerEmail || '';
    const customerName = session?.metadata?.customerName || paymentIntent?.metadata?.customerName || '';
    const stripeSessionId = session?.id || null;

    if (!paymentIntentId) {
      return res.status(400).json({ error: 'Could not determine payment_intent_id' });
    }

    console.log('🧪 TEST: Attempting to save payment with data:', {
      paymentIntentId,
      amountPaid,
      currency: session?.currency || paymentIntent?.currency || 'gbp',
      eventType,
      customerEmail,
      customerName,
      stripeSessionId
    });

    // Save payment to database
    const saveResult = await savePaymentToDatabase({
      paymentIntentId,
      amountPaid,
      currency: session?.currency || paymentIntent?.currency || 'gbp',
      eventType,
      customerEmail,
      customerName,
      stripeSessionId
    });

    console.log('🧪 TEST: Payment saved successfully:', saveResult);

    res.json({
      success: true,
      message: 'Payment saved successfully',
      paymentId: saveResult.id,
      updated: saveResult.updated,
      data: {
        reservationId,
        paymentIntentId,
        amountPaid,
        customerEmail
      }
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

  // XIX Restaurant time slots (9:00 AM to 1:00 AM)
  // Generate all time slots from 9:00 AM to 1:00 AM (30-minute intervals)
  const generateXIXTimeSlots = () => {
    const slots = [];
    // 9:00 AM to 11:59 PM
    for (let hour = 9; hour < 24; hour++) {
      slots.push(`${hour.toString().padStart(2, '0')}:00`);
      slots.push(`${hour.toString().padStart(2, '0')}:30`);
    }
    // 12:00 AM to 1:00 AM
    slots.push('00:00');
    slots.push('00:30');
    slots.push('01:00');
    return slots;
  };

  const allXIXTimeSlots = generateXIXTimeSlots();

  const xixTimeSlots = {
    'Monday': allXIXTimeSlots,
    'Tuesday': allXIXTimeSlots,
    'Wednesday': allXIXTimeSlots,
    'Thursday': allXIXTimeSlots,
    'Friday': allXIXTimeSlots,
    'Saturday': allXIXTimeSlots,
    'Sunday': allXIXTimeSlots
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
        detectedVenue = 'Mirror'; // Capitalize for consistency
        console.log('Auto-detected venue as Mirror from referrer:', referrer, 'or URL:', requestUrl);
      } else {
        detectedVenue = 'XIX'; // Uppercase to match tables table
        console.log('Auto-detected venue as XIX from referrer:', referrer, 'or URL:', requestUrl);
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
      venue: detectedVenue ? detectedVenue.toUpperCase() : 'XIX', // Normalize to uppercase to match tables
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
    // Assign table and calculate end time
    assignTable(
      sanitizedReservation.guests,
      sanitizedReservation.date,
      sanitizedReservation.time,
      (sanitizedReservation.venue || 'XIX').toUpperCase(), // Normalize to uppercase
      (err, assignedTable, endTime) => {
        if (err) {
          console.error('Error assigning table:', err);
          // Continue without table assignment
        }

        // Generate confirmation token and deadline
        const confirmationToken = generateConfirmationToken();
        const confirmationDeadline = calculateConfirmationDeadline(sanitizedReservation.date, sanitizedReservation.time);

        const stmt = db.prepare(`INSERT INTO reservations 
          (name, email, phone, date, time, guests, table_preference, occasion, special_requests, venue, event_type, menu_preference, entertainment, 
           assigned_table, end_time, confirmation_status, confirmation_token, confirmation_deadline, email_sent_to_customer, email_sent_to_manager, google_calendar_event_id) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

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
          assignedTable ? assignedTable.toString() : null,
          endTime,
          'pending',
          confirmationToken,
          confirmationDeadline,
          0, // email_sent_to_customer - will be updated after sending
          0, // email_sent_to_manager - will be updated after sending
          null // google_calendar_event_id - will be set after creating calendar event
        ], async function (err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to save reservation' });
          }

          console.log(`Reservation saved with ID: ${this.lastID}, Table: ${assignedTable || 'Not assigned'}`);
          reservationId = this.lastID; // Store for updating email status

          // Create Google Calendar event for this reservation
          if (calendar && process.env.GOOGLE_CALENDAR_ID) {
            // Get full reservation data for calendar event
            db.get('SELECT * FROM reservations WHERE id = ?', [reservationId], async (err, fullReservation) => {
              if (!err && fullReservation) {
                const calendarEventId = await createGoogleCalendarEvent(fullReservation);
                if (calendarEventId) {
                  // Update reservation with calendar event ID
                  db.run('UPDATE reservations SET google_calendar_event_id = ? WHERE id = ?', [calendarEventId, reservationId], (updateErr) => {
                    if (updateErr) {
                      console.error('Error updating reservation with calendar event ID:', updateErr);
                    } else {
                      console.log(`✅ Linked reservation ${reservationId} to Google Calendar event ${calendarEventId}`);
                    }
                  });
                }
              }
            });
          }

          // Send response immediately (don't wait for email)
          res.json({
            success: true,
            reservationId: reservationId,
            reservation: {
              name: sanitizedReservation.name,
              email: sanitizedReservation.email,
              phone: sanitizedReservation.phone,
              date: sanitizedReservation.date,
              time: sanitizedReservation.time,
              guests: sanitizedReservation.guests,
              table: sanitizedReservation.table || assignedTable,
              occasion: sanitizedReservation.occasion,
              specialRequests: sanitizedReservation.specialRequests,
              venue: sanitizedReservation.venue, // Already normalized to uppercase
              eventType: sanitizedReservation.eventType,
              menuPreference: sanitizedReservation.menuPreference,
              entertainment: sanitizedReservation.entertainment
            }
          });

          // Assign table immediately if not already assigned (for pending reservations)
          // This ensures tables are reserved even before customer confirms
          if (!assignedTable) {
            console.log('⚠️ No table assigned during creation, attempting to assign now...');
            assignTable(
              sanitizedReservation.guests,
              sanitizedReservation.date,
              sanitizedReservation.time,
              (sanitizedReservation.venue || 'XIX').toUpperCase(), // Normalize to uppercase
              (assignErr, newAssignedTable, newEndTime) => {
                if (!assignErr && newAssignedTable) {
                  // Update reservation with assigned table
                  db.run(
                    'UPDATE reservations SET assigned_table = ?, end_time = ? WHERE id = ?',
                    [newAssignedTable.toString(), newEndTime, reservationId],
                    (updateErr) => {
                      if (updateErr) {
                        console.error('Error updating reservation with assigned table:', updateErr);
                      } else {
                        console.log(`✅ Table ${newAssignedTable} assigned to reservation ${reservationId}`);
                        assignedTable = newAssignedTable; // Update local variable for email
                      }
                      // Send email with assigned table
                      sendPreliminaryReservationEmail(reservationId, assignedTable || newAssignedTable, sanitizedReservation).catch(err => {
                        console.error('Error sending preliminary email:', err);
                        logger.error('Failed to send preliminary reservation email', {
                          reservationId: reservationId,
                          error: err.message,
                          stack: err.stack,
                          timestamp: new Date().toISOString()
                        });
                      });
                    }
                  );
                } else {
                  console.log('⚠️ Could not assign table - all tables may be booked');
                  // Send email anyway (table will be assigned later if available)
                  sendPreliminaryReservationEmail(reservationId, assignedTable, sanitizedReservation).catch(err => {
                    console.error('Error sending preliminary email:', err);
                    logger.error('Failed to send preliminary reservation email', {
                      reservationId: reservationId,
                      error: err.message,
                      stack: err.stack,
                      timestamp: new Date().toISOString()
                    });
                  });
                }
              }
            );
          } else {
            // Table already assigned, send email immediately
            sendPreliminaryReservationEmail(reservationId, assignedTable, sanitizedReservation).catch(err => {
              console.error('Error sending preliminary email:', err);
              logger.error('Failed to send preliminary reservation email', {
                reservationId: reservationId,
                error: err.message,
                stack: err.stack,
                timestamp: new Date().toISOString()
              });
            });
          }

          // Send second email 5 minutes later (confirmation button only)
          // BUT ONLY if table was assigned (skip for waitlist customers)
          // (or immediately if reservation is less than 5 minutes away)
          if (assignedTable) {
            const reservationDateTime = new Date(`${sanitizedReservation.date}T${sanitizedReservation.time}`);
            const now = new Date();
            const timeUntilReservation = reservationDateTime.getTime() - now.getTime();
            const fiveMinutes = 5 * 60 * 1000; // Changed to 5 minutes for testing

            if (timeUntilReservation <= fiveMinutes) {
              // If reservation is less than 5 minutes away, send confirmation button email immediately
              console.log(`⏰ Reservation is less than 5 minutes away, sending confirmation button email immediately`);
              sendConfirmationButtonEmail(reservationId, confirmationToken).catch(err => {
                console.error('❌ Error sending immediate confirmation button email:', err);
              });
            } else {
              // Otherwise, send confirmation button email 5 minutes after reservation creation
              console.log(`⏰ Scheduling confirmation button email to be sent in 5 minutes for reservation ID: ${reservationId}`);
              setTimeout(() => {
                console.log(`⏰ Timeout triggered - sending confirmation button email for reservation ID: ${reservationId}`);
                sendConfirmationButtonEmail(reservationId, confirmationToken).catch(err => {
                  console.error('❌ Error sending scheduled confirmation button email:', err);
                });
              }, fiveMinutes);
            }
          } else {
            console.log(`ℹ️ Skipping confirmation button email for waitlist reservation ${reservationId} (no table assigned)`);
          }
        });
      }
    );

    // Function to send preliminary email immediately (with all info, no button)
    // table parameter is now a table ID (integer), not table_number (string)
    // If tableId is null/undefined, it means no table was available - send waitlist message
    async function sendPreliminaryReservationEmail(resId, tableId, reservationData) {
      console.log('📧 sendPreliminaryReservationEmail called with:', { resId, tableId, email: reservationData?.email });

      // Check if table was assigned
      const hasTable = tableId && tableId !== null && tableId !== undefined;

      // Look up table_number from tables table if tableId is provided
      let tableDisplay = null;
      if (hasTable) {
        try {
          const tableInfo = await new Promise((resolve, reject) => {
            db.get('SELECT table_number FROM tables WHERE id = ?', [tableId], (err, row) => {
              if (err) reject(err);
              else resolve(row);
            });
          });
          if (tableInfo) {
            tableDisplay = tableInfo.table_number;
          }
        } catch (err) {
          console.warn('Could not look up table name for ID:', tableId, err.message);
        }
      }

      // If no table was assigned, use a waitlist message
      if (!hasTable && !tableDisplay) {
        tableDisplay = reservationData?.table || null; // Keep user's preference if they had one
      }

      try {
        if (!reservationData || !reservationData.email) {
          console.error('❌ Invalid reservation data:', reservationData);
          return;
        }
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

        // Parse date string (YYYY-MM-DD) to avoid timezone issues
        const dateParts = reservationData.date.split('-');
        const dateYear = parseInt(dateParts[0], 10);
        const dateMonth = parseInt(dateParts[1], 10) - 1; // Month is 0-indexed
        const dateDay = parseInt(dateParts[2], 10);
        const dateObj = new Date(dateYear, dateMonth, dateDay);

        const date = dateObj.toLocaleDateString('en-US', {
          weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
        });

        const time24 = reservationData.time || '19:00';
        const [h, m] = time24.split(':');
        const hh = parseInt(h, 10);
        const time12 = `${(hh % 12) || 12}:${m} ${hh >= 12 ? 'PM' : 'AM'}`;

        const from = process.env.MAIL_FROM || process.env.SMTP_USER;
        const managerEmail = process.env.MANAGER_EMAIL || process.env.SMTP_USER;

        // Determine venue details
        const isMirror = reservationData.venue === 'Mirror';
        const venueName = isMirror ? 'Mirror Ukrainian Banquet Hall' : 'XIX Restaurant';
        const venueAddress = isMirror ? 'Mirror Ukrainian Banquet Hall, 123 King\'s Road, London SW3 4RD' : 'XIX Restaurant, 123 King\'s Road, London SW3 4RD';
        const eventDuration = isMirror ? 8 : 2;

        // Create Google Calendar event URL
        const eventDate = new Date(`${reservationData.date}T${reservationData.time}:00`);
        const endDate = new Date(eventDate.getTime() + (eventDuration * 60 * 60 * 1000));

        const eventTitle = `${isMirror ? 'Event' : 'Reservation'}: ${reservationData.name} (${reservationData.guests} guests)`;
        const eventDetails = `Customer: ${reservationData.name}
Email: ${reservationData.email}
Phone: ${reservationData.phone}
Guests: ${reservationData.guests}
${isMirror ? '' : `Table: ${tableDisplay}`}
${reservationData.occasion ? `Occasion: ${reservationData.occasion}` : ''}
${reservationData.eventType ? `Event Type: ${reservationData.eventType}` : ''}
${reservationData.menuPreference ? `Menu Preference: ${reservationData.menuPreference}` : ''}
${reservationData.entertainment ? `Entertainment: ${reservationData.entertainment}` : ''}
${reservationData.specialRequests ? `Special Requests: ${reservationData.specialRequests}` : ''}

Reservation made through ${venueName} website.`;

        const location = venueAddress;

        // Format dates for Google Calendar (YYYYMMDDTHHMMSSZ)
        const formatDateForGoogle = (date) => {
          return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
        };

        const googleCalendarUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(eventTitle)}&dates=${formatDateForGoogle(eventDate)}/${formatDateForGoogle(endDate)}&details=${encodeURIComponent(eventDetails)}&location=${encodeURIComponent(location)}`;

        // Customer preliminary email (all info, no confirmation button)
        // Different message if no table was assigned (waitlist scenario)
        const customerSubject = hasTable
          ? `${venueName} Reservation Received - ${date} at ${time12}`
          : `${venueName} Reservation Request Received - ${date} at ${time12}`;

        const waitlistMessage = hasTable ? '' : `
        <div style="margin: 25px 0; padding: 20px; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
          <h3 style="margin-top: 0; color: #856404; font-size: 1.1em;">⏳ Table Availability Check</h3>
          <p style="color: #856404; margin-bottom: 0;">
            We've received your reservation request for <strong>${date} at ${time12}</strong>. 
            All tables are currently booked for this time slot, but we're checking for availability.
          </p>
          <p style="color: #856404; margin-top: 10px; margin-bottom: 0;">
            <strong>Our team will contact you shortly</strong> via phone at <strong>${reservationData.phone}</strong> 
            to confirm availability or discuss alternative options. Please keep your phone nearby.
          </p>
        </div>
        `;

        const customerHtml = `
      <div style="font-family:Arial,Helvetica,sans-serif;color:#020702">
        <h2 style="font-family: 'Gilda Display', Georgia, serif;">${hasTable ? 'Reservation Received' : 'Reservation Request Received'}</h2>
        <p>Hi ${reservationData.name || ''},</p>
        ${hasTable
            ? `<p>Thank you for your reservation at <strong>${venueName}</strong>. Here are your reservation details:</p>`
            : `<p>Thank you for your interest in dining at <strong>${venueName}</strong>. We've received your reservation request:</p>`
          }
        <ul>
          <li><strong>Date:</strong> ${date}</li>
          <li><strong>Time:</strong> ${time12}</li>
          <li><strong>Guests:</strong> ${reservationData.guests}</li>
          ${isMirror ? '' : (hasTable && tableDisplay ? `<li><strong>Table:</strong> ${tableDisplay}</li>` : '')}
          ${reservationData.occasion ? `<li><strong>Occasion:</strong> ${reservationData.occasion}</li>` : ''}
          ${reservationData.eventType ? `<li><strong>Event Type:</strong> ${reservationData.eventType}</li>` : ''}
          ${reservationData.menuPreference ? `<li><strong>Menu Preference:</strong> ${reservationData.menuPreference}</li>` : ''}
          ${reservationData.entertainment ? `<li><strong>Entertainment:</strong> ${reservationData.entertainment}</li>` : ''}
        </ul>
        ${reservationData.specialRequests ? `<p><strong>Special requests:</strong> ${reservationData.specialRequests}</p>` : ''}
        
        ${waitlistMessage}
        
        ${hasTable ? `
        <div style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 4px solid #A8871A; border-radius: 4px;">
          <h3 style="margin-top: 0; color: #A8871A;">📅 Add to Google Calendar</h3>
          <p>Click the button below to add this reservation to your Google Calendar:</p>
          <a href="${googleCalendarUrl}" 
             style="display: inline-block; background-color: #A8871A; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px 0;">
            📅 Add to Google Calendar
          </a>
        </div>
        
        <p style="margin-top: 20px; color: #666; font-size: 0.9em;">You will receive a confirmation email shortly. Please confirm your reservation when you receive it.</p>
        ` : `
        <p style="margin-top: 20px; color: #666; font-size: 0.9em;">
          We appreciate your patience and will do our best to accommodate your request. 
          If a table becomes available, we'll contact you immediately.
        </p>
        `}
        <p>We look forward to welcoming you.</p>
        <p style="color:#6E6E6E">${venueAddress}</p>
        ${hasTable ? '' : `<p style="color:#6E6E6E; font-size: 0.9em;">Phone: ${process.env.RESTAURANT_PHONE || '+44 20 1234 5678'}</p>`}
      </div>
    `;

        // Manager notification email
        const managerSubject = hasTable
          ? `New ${isMirror ? 'Event' : 'Reservation'} - ${reservationData.name} - ${date} at ${time12}`
          : `⚠️ WAITLIST: ${isMirror ? 'Event' : 'Reservation'} Request - ${reservationData.name} - ${date} at ${time12}`;

        const managerWaitlistWarning = hasTable ? '' : `
        <div style="margin: 20px 0; padding: 15px; background-color: #ffebee; border-left: 4px solid #dc3545; border-radius: 4px;">
          <h3 style="margin-top: 0; color: #c62828;">⚠️ No Table Assigned - Waitlist</h3>
          <p style="color: #c62828; margin-bottom: 0;">
            <strong>Action Required:</strong> All tables are booked for this time slot. 
            Please contact the customer to confirm availability or suggest alternative times.
          </p>
        </div>
        `;

        const managerHtml = `
      <div style="font-family:Arial,Helvetica,sans-serif;color:#020702">
        <h2 style="font-family: 'Gilda Display', Georgia, serif;">${hasTable ? `New ${isMirror ? 'Event Booking' : 'Table Reservation'}` : `⚠️ ${isMirror ? 'Event' : 'Reservation'} Request - Waitlist`}</h2>
        <p><strong>Customer Details:</strong></p>
        <ul>
          <li><strong>Name:</strong> ${reservationData.name}</li>
          <li><strong>Email:</strong> ${reservationData.email}</li>
          <li><strong>Phone:</strong> ${reservationData.phone}</li>
        </ul>
        <p><strong>${isMirror ? 'Event' : 'Reservation'} Details:</strong></p>
        <ul>
          <li><strong>Date:</strong> ${date}</li>
          <li><strong>Time:</strong> ${time12}</li>
          <li><strong>Guests:</strong> ${reservationData.guests}</li>
          ${isMirror ? '' : `<li><strong>Table:</strong> ${hasTable && tableDisplay ? tableDisplay : '<span style="color: #dc3545;">NOT ASSIGNED - Waitlist</span>'}</li>`}
          ${reservationData.occasion ? `<li><strong>Occasion:</strong> ${reservationData.occasion}</li>` : ''}
          ${reservationData.eventType ? `<li><strong>Event Type:</strong> ${reservationData.eventType}</li>` : ''}
          ${reservationData.menuPreference ? `<li><strong>Menu Preference:</strong> ${reservationData.menuPreference}</li>` : ''}
          ${reservationData.entertainment ? `<li><strong>Entertainment:</strong> ${reservationData.entertainment}</li>` : ''}
        </ul>
        ${reservationData.specialRequests ? `<p><strong>Special Requests:</strong> ${reservationData.specialRequests}</p>` : ''}
        
        ${managerWaitlistWarning}
        
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
        
        <p style="color:#6E6E6E; font-size: 0.9em;">This reservation was made through the ${venueName} website.</p>
        ${hasTable ? '' : `<p style="color:#dc3545; font-size: 0.9em; font-weight: bold;">⚠️ Please contact customer at ${reservationData.phone} to confirm availability.</p>`}
      </div>
    `;

        // Send both emails
        console.log('Sending preliminary reservation email...');
        console.log('Customer email:', reservationData.email);
        console.log('Manager email:', managerEmail);

        const customerInfo = await transporter.sendMail({
          from,
          to: reservationData.email,
          subject: customerSubject,
          html: customerHtml
        });
        console.log('Preliminary customer email sent:', customerInfo.messageId);

        const managerInfo = await transporter.sendMail({
          from,
          to: managerEmail,
          subject: managerSubject,
          html: managerHtml
        });
        console.log('Manager email sent:', managerInfo.messageId);

        // Update email status in database
        if (resId) {
          db.run(
            'UPDATE reservations SET email_sent_to_customer = 1, email_sent_to_manager = 1 WHERE id = ?',
            [resId],
            (err) => {
              if (err) {
                console.error('Error updating email status:', err);
              } else {
                console.log('Email status updated for reservation ID:', resId);
              }
            }
          );
        }

        // Log successful email sending
        logger.info('Preliminary reservation email sent', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          reservationId: resId,
          customerEmail: reservationData.email,
          customerName: reservationData.name,
          date: reservationData.date,
          time: reservationData.time,
          guests: reservationData.guests,
          timestamp: new Date().toISOString()
        });
      } catch (emailErr) {
        console.error('Error sending preliminary email:', emailErr);
        logger.error('Preliminary reservation email send failed', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          error: emailErr.message,
          stack: emailErr.stack,
          reservationId: resId,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Function to send confirmation button email (5 minutes later, only button)
    async function sendConfirmationButtonEmail(resId, token) {
      console.log('📧 sendConfirmationButtonEmail called with:', { resId, token });
      try {
        // Fetch reservation data from database - wrap callback in Promise
        const reservation = await new Promise((resolve, reject) => {
          db.get('SELECT * FROM reservations WHERE id = ?', [resId], (err, row) => {
            if (err) {
              reject(err);
            } else {
              resolve(row);
            }
          });
        });

        if (!reservation) {
          console.error('❌ Reservation not found for confirmation email:', resId);
          return;
        }

        console.log('✅ Reservation found:', { id: reservation.id, email: reservation.email, status: reservation.confirmation_status });

        // Check if already confirmed
        if (reservation.confirmation_status === 'confirmed') {
          console.log('ℹ️ Reservation already confirmed, skipping confirmation button email');
          return;
        }

        const confirmationUrl = `${getBaseUrl()}/api/confirm-reservation/${token}`;

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

        // Determine venue details
        const isMirror = reservation.venue === 'Mirror';
        const venueName = isMirror ? 'Mirror Ukrainian Banquet Hall' : 'XIX Restaurant';

        // Parse date string (YYYY-MM-DD) to avoid timezone issues
        const dateParts = reservation.date.split('-');
        const dateYear = parseInt(dateParts[0], 10);
        const dateMonth = parseInt(dateParts[1], 10) - 1;
        const dateDay = parseInt(dateParts[2], 10);
        const dateObj = new Date(dateYear, dateMonth, dateDay);

        const date = dateObj.toLocaleDateString('en-US', {
          weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
        });

        const time24 = reservation.time || '19:00';
        const [h, m] = time24.split(':');
        const hh = parseInt(h, 10);
        const time12 = `${(hh % 12) || 12}:${m} ${hh >= 12 ? 'PM' : 'AM'}`;

        // Confirmation button email (only button, minimal info)
        const cancellationUrl = `${getBaseUrl()}/api/cancel-reservation/${token}`;
        const customerSubject = `Please Confirm Your Reservation - ${venueName}`;
        const customerHtml = `
      <div style="font-family:Arial,Helvetica,sans-serif;color:#020702; text-align: center; padding: 40px 20px;">
        <h2 style="font-family: 'Gilda Display', Georgia, serif; color: #A8871A;">Confirm Your Reservation</h2>
        <p>Hi ${reservation.name || ''},</p>
        <p style="font-size: 16px; margin-bottom: 30px;">Please confirm your reservation at <strong>${venueName}</strong> for ${date} at ${time12}.</p>
        
        <div style="text-align: center; margin: 40px 0;">
          <a href="${confirmationUrl}" 
             style="display: inline-block; background-color: #28a745; color: white; padding: 20px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 18px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-right: 15px;">
            ✅ Confirm Reservation
          </a>
          <a href="${cancellationUrl}" 
             style="display: inline-block; background-color: #dc3545; color: white; padding: 20px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 18px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            ❌ Cancel Booking
          </a>
        </div>
        
        <p style="color: #666; font-size: 0.9em; margin-top: 30px;">Or copy this link: ${confirmationUrl}</p>
        <p style="color: #999; font-size: 0.85em; margin-top: 20px;">If you don't confirm your reservation, it may be automatically cancelled.</p>
      </div>
    `;

        console.log('📧 Sending confirmation button email...');
        console.log('📧 Customer email:', reservation.email);
        console.log('📧 Confirmation URL:', confirmationUrl);

        const customerInfo = await transporter.sendMail({
          from,
          to: reservation.email,
          subject: customerSubject,
          html: customerHtml
        });
        console.log('✅ Confirmation button email sent successfully:', customerInfo.messageId);

        // Log successful email sending
        logger.info('Confirmation button email sent', {
          reservationId: resId,
          customerEmail: reservation.email,
          customerName: reservation.name,
          date: reservation.date,
          time: reservation.time,
          timestamp: new Date().toISOString()
        });
      } catch (emailErr) {
        console.error('❌ Error in sendConfirmationButtonEmail function:', emailErr);
        logger.error('Confirmation button email function error', {
          error: emailErr.message,
          stack: emailErr.stack,
          reservationId: resId,
          timestamp: new Date().toISOString()
        });
        // Re-throw to allow caller's .catch() to handle it
        throw emailErr;
      }
    }
  } catch (err) {
    console.error('Reservation creation error:', err);
    logger.error('Reservation creation failed', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      error: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ error: 'Failed to create reservation' });
  }
});

// Function to send waitlist assignment email (when waitlist customer gets a table)
// Must be defined at module level to be accessible from reassignTableToWaitlist
async function sendWaitlistAssignmentEmail(resId, tableId, confirmationToken, reservationData) {
  console.log('📧 sendWaitlistAssignmentEmail called with:', { resId, tableId, email: reservationData?.email });

  // Look up table_number from tables table
  let tableDisplay = null;
  if (tableId) {
    try {
      const tableInfo = await new Promise((resolve, reject) => {
        db.get('SELECT table_number FROM tables WHERE id = ?', [tableId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
      if (tableInfo) {
        tableDisplay = tableInfo.table_number;
      }
    } catch (err) {
      console.warn('Could not look up table name for ID:', tableId, err.message);
    }
  }

  try {
    if (!reservationData || !reservationData.email) {
      console.error('❌ Invalid reservation data:', reservationData);
      return;
    }
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

    // Parse date string (YYYY-MM-DD) to avoid timezone issues
    const dateParts = reservationData.date.split('-');
    const dateYear = parseInt(dateParts[0], 10);
    const dateMonth = parseInt(dateParts[1], 10) - 1; // Month is 0-indexed
    const dateDay = parseInt(dateParts[2], 10);
    const dateObj = new Date(dateYear, dateMonth, dateDay);

    const date = dateObj.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    });

    const time24 = reservationData.time || '19:00';
    const [h, m] = time24.split(':');
    const hh = parseInt(h, 10);
    const time12 = `${(hh % 12) || 12}:${m} ${hh >= 12 ? 'PM' : 'AM'}`;

    const from = process.env.MAIL_FROM || process.env.SMTP_USER;

    // Determine venue details
    const isMirror = reservationData.venue === 'Mirror';
    const venueName = isMirror ? 'Mirror Ukrainian Banquet Hall' : 'XIX Restaurant';
    const venueAddress = isMirror ? 'Mirror Ukrainian Banquet Hall, 123 King\'s Road, London SW3 4RD' : 'XIX Restaurant, 123 King\'s Road, London SW3 4RD';
    const eventDuration = isMirror ? 8 : 2;

    // Create Google Calendar event URL
    const eventDate = new Date(`${reservationData.date}T${reservationData.time}:00`);
    const endDate = new Date(eventDate.getTime() + (eventDuration * 60 * 60 * 1000));

    const eventTitle = `${isMirror ? 'Event' : 'Reservation'}: ${reservationData.name} (${reservationData.guests} guests)`;
    const eventDetails = `Customer: ${reservationData.name}
Email: ${reservationData.email}
Phone: ${reservationData.phone}
Guests: ${reservationData.guests}
${isMirror ? '' : `Table: ${tableDisplay}`}
${reservationData.occasion ? `Occasion: ${reservationData.occasion}` : ''}
${reservationData.specialRequests ? `Special Requests: ${reservationData.specialRequests}` : ''}

Reservation made through ${venueName} website.`;

    const location = venueAddress;

    // Format dates for Google Calendar (YYYYMMDDTHHMMSSZ)
    const formatDateForGoogle = (date) => {
      return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    };

    const googleCalendarUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(eventTitle)}&dates=${formatDateForGoogle(eventDate)}/${formatDateForGoogle(endDate)}&details=${encodeURIComponent(eventDetails)}&location=${encodeURIComponent(location)}`;

    const confirmationUrl = `${getBaseUrl()}/api/confirm-reservation/${confirmationToken}`;
    const cancellationUrl = `${getBaseUrl()}/api/cancel-reservation/${confirmationToken}`;

    // Waitlist assignment email - table is now available!
    const customerSubject = `🎉 Table Available! - ${venueName} Reservation Confirmed`;
    const customerHtml = `
      <div style="font-family:Arial,Helvetica,sans-serif;color:#020702; text-align: center; padding: 40px 20px;">
        <div style="margin: 25px 0; padding: 20px; background-color: #d4edda; border-left: 4px solid #28a745; border-radius: 4px;">
          <h2 style="font-family: 'Gilda Display', Georgia, serif; color: #155724; margin-top: 0; font-size: 1.5em;">🎉 Great News! Your Table is Available</h2>
          <p style="color: #155724; margin-bottom: 0; font-size: 16px;">
            We're excited to inform you that a table has become available for your reservation request!
          </p>
        </div>
        
        <h2 style="font-family: 'Gilda Display', Georgia, serif; color: #A8871A; margin-top: 30px;">Your Reservation Details</h2>
        <p>Hi ${reservationData.name || ''},</p>
        <p style="font-size: 16px; margin-bottom: 30px;">Your reservation at <strong>${venueName}</strong> has been confirmed:</p>
        
        <div style="text-align: left; max-width: 500px; margin: 0 auto; padding: 20px; background-color: #f8f9fa; border-radius: 8px;">
          <ul style="list-style: none; padding: 0;">
            <li style="margin: 10px 0;"><strong>Date:</strong> ${date}</li>
            <li style="margin: 10px 0;"><strong>Time:</strong> ${time12}</li>
            <li style="margin: 10px 0;"><strong>Guests:</strong> ${reservationData.guests}</li>
            ${isMirror ? '' : `<li style="margin: 10px 0;"><strong>Table:</strong> ${tableDisplay}</li>`}
            ${reservationData.occasion ? `<li style="margin: 10px 0;"><strong>Occasion:</strong> ${reservationData.occasion}</li>` : ''}
          </ul>
          ${reservationData.specialRequests ? `<p style="margin-top: 15px;"><strong>Special Requests:</strong> ${reservationData.specialRequests}</p>` : ''}
        </div>
        
        <div style="text-align: center; margin: 40px 0;">
          <a href="${confirmationUrl}" 
             style="display: inline-block; background-color: #28a745; color: white; padding: 20px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 18px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-right: 15px;">
            ✅ Confirm Reservation
          </a>
          <a href="${cancellationUrl}" 
             style="display: inline-block; background-color: #dc3545; color: white; padding: 20px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 18px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            ❌ Cancel Booking
          </a>
        </div>
        
        <div style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 4px solid #A8871A; border-radius: 4px;">
          <h3 style="margin-top: 0; color: #A8871A;">📅 Add to Google Calendar</h3>
          <p>Click the button below to add this reservation to your Google Calendar:</p>
          <a href="${googleCalendarUrl}" 
             style="display: inline-block; background-color: #A8871A; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px 0;">
            📅 Add to Google Calendar
          </a>
        </div>
        
        <p style="color: #666; font-size: 0.9em; margin-top: 30px;">Please confirm your reservation as soon as possible to secure your table.</p>
        <p style="color: #999; font-size: 0.85em; margin-top: 20px;">If you don't confirm your reservation, it may be automatically cancelled.</p>
        <p>We look forward to welcoming you!</p>
        <p style="color:#6E6E6E">${venueAddress}</p>
      </div>
    `;

    console.log('📧 Sending waitlist assignment email...');
    console.log('📧 Customer email:', reservationData.email);

    const customerInfo = await transporter.sendMail({
      from,
      to: reservationData.email,
      subject: customerSubject,
      html: customerHtml
    });
    console.log('✅ Waitlist assignment email sent successfully:', customerInfo.messageId);

    // Log successful email sending
    logger.info('Waitlist assignment email sent', {
      reservationId: resId,
      customerEmail: reservationData.email,
      messageId: customerInfo.messageId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Error sending waitlist assignment email:', error);
    logger.error('Failed to send waitlist assignment email', {
      reservationId: resId,
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
  }
}

// Payment email endpoint - same pattern as reservation emails
app.post('/api/send-payment-email', async (req, res) => {
  try {
    const { session_id } = req.body;

    // Basic validation
    if (!session_id) {
      return res.status(400).json({ error: 'Missing session_id parameter' });
    }

    console.log('📧 Received payment email request for session:', session_id);

    // Retrieve the Stripe session
    const session = await stripe.checkout.sessions.retrieve(session_id);

    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    // Extract payment data
    const amountPaid = session.amount_total / 100;
    const eventId = session.metadata?.eventId || '';
    const eventDetails = eventId ? eventMapping[eventId] : null;
    const eventType = eventDetails ? eventDetails.title : (eventId ? 'event' : null);
    const eventDate = eventDetails?.date || null;
    const paymentIntentId = session.payment_intent || session.id;

    // Get customer email - prioritize metadata (from client form) over session.customer_email
    const customerEmail = session.metadata?.customerEmail || session.customer_email || '';
    const customerName = session.metadata?.customerName || '';

    console.log('📧 Payment email data:', {
      customerEmail,
      customerName,
      eventType,
      eventDate,
      amountPaid
    });

    // Check if email is configured
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      console.warn('⚠️ Email not configured - skipping email send');
      return res.status(500).json({ error: 'Email service not configured' });
    }

    // Save payment to database first (if not already saved)
    try {
      await savePaymentToDatabase({
        paymentIntentId,
        amountPaid,
        currency: session.currency || 'gbp',
        eventType,
        eventDate,
        customerEmail,
        customerName,
        stripeSessionId: session.id
      });
      console.log('✅ Payment saved to database');
    } catch (paymentError) {
      console.error('❌ Failed to save payment:', paymentError);
      // Continue to send emails even if save fails
    }

    // Send emails using the same function
    if (!customerEmail || !customerEmail.includes('@')) {
      console.warn('⚠️ No valid customer email - skipping customer email');
    }

    const emailResult = await sendEventPaymentConfirmationEmails(
      session,
      eventType,
      eventDate,
      customerEmail,
      customerName
    );

    console.log('✅ Payment emails sent successfully');

    // Return success response (same pattern as reservations)
    res.json({
      success: true,
      customerMessageId: emailResult?.customerInfo?.messageId || null,
      managerMessageId: emailResult?.managerInfo?.messageId || null,
      payment: {
        sessionId: session.id,
        paymentIntentId: paymentIntentId,
        amount: amountPaid,
        currency: session.currency,
        eventType: eventType,
        eventDate: eventDate,
        customerEmail: customerEmail,
        customerName: customerName
      }
    });
  } catch (error) {
    console.error('❌ Payment email send error:', error);
    logger.error('Payment email send failed', {
      error: error.message,
      stack: error.stack,
      sessionId: req.body?.session_id,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ error: 'Failed to send payment confirmation email' });
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

  // Define all possible time slots (9:00 AM to 1:00 AM)
  const generateAllTimeSlots = () => {
    const slots = [];
    // 9:00 AM to 11:59 PM
    for (let hour = 9; hour < 24; hour++) {
      slots.push(`${hour.toString().padStart(2, '0')}:00`);
      slots.push(`${hour.toString().padStart(2, '0')}:30`);
    }
    // 12:00 AM to 1:00 AM
    slots.push('00:00');
    slots.push('00:30');
    slots.push('01:00');
    return slots;
  };

  const allTimeSlots = generateAllTimeSlots();

  // Return all time slots - table availability is checked separately via /api/table-availability
  // This endpoint should show all possible times, and the frontend will check table availability
  // for each time slot based on guest count
  res.json({
    date: date,
    venue: detectedVenue,
    availableTimes: allTimeSlots,
    totalReservations: 0 // Not needed, but kept for compatibility
  });
});

// API endpoint to check table availability based on guest count
app.get('/api/table-availability', (req, res) => {
  const { date, time, guests, venue } = req.query;

  if (!date || !time || !guests) {
    return res.status(400).json({ error: 'Date, time, and guests parameters are required' });
  }

  // Normalize venue to uppercase for consistency (tables are stored as 'XIX')
  const detectedVenue = venue ? venue.toUpperCase() : 'XIX';
  const guestCount = parseInt(guests, 10);

  if (isNaN(guestCount) || guestCount < 1) {
    return res.status(400).json({ error: 'Invalid guest count' });
  }

  // Calculate end time (default 2 hours after start) - handles midnight crossover
  const endTime = calculateEndTime(date, time, 2);

  // Determine which table capacities to show based on guest count
  // Logic: Show only appropriate tables (not too large)
  let allowedCapacities = [];
  if (guestCount === 1 || guestCount === 2) {
    allowedCapacities = [2]; // Only 2-person tables
  } else if (guestCount === 3) {
    allowedCapacities = [3, 4]; // 3-person and 4-person tables
  } else if (guestCount === 4) {
    allowedCapacities = [4]; // Only 4-person tables
  } else if (guestCount === 5) {
    allowedCapacities = [6]; // Only 6-person tables (no 5-person tables)
  } else if (guestCount === 6) {
    allowedCapacities = [6]; // Only 6-person tables
  } else {
    // 7+ guests
    allowedCapacities = [12]; // Only 12-person table
  }

  // First, count how many reservations (with or without assigned tables) overlap with this time slot
  // and would need tables of the same capacity
  // Calculate end_time for reservations that don't have it (default 2 hours after start)
  db.all(
    `SELECT COUNT(*) as overlapping_count FROM reservations r
     WHERE r.date = ? AND UPPER(r.venue) = UPPER(?) 
     AND r.confirmation_status != 'cancelled'
     AND (
       -- Two time slots overlap if: existing_start < requested_end AND existing_end >= requested_start
       -- Handle midnight crossover: end_time >= 25 indicates next day (e.g., "25:00" = 1:00 AM next day)
       -- Normalize both sides: times >= 25 are normalized to "99:00" for comparison
       (
         -- Compare: existing_start < requested_end
         CASE 
           WHEN CAST(SUBSTR(r.time, 1, 2) AS INTEGER) >= 25 THEN '99:00'
           ELSE r.time
         END < 
         CASE 
           WHEN CAST(SUBSTR(?, 1, 2) AS INTEGER) >= 25 THEN '99:00'
           ELSE ?
         END
         AND
         -- Compare: existing_end >= requested_start
         CASE 
           WHEN r.end_time IS NOT NULL THEN 
             CASE 
               WHEN CAST(SUBSTR(r.end_time, 1, 2) AS INTEGER) >= 25 THEN '99:00'
               ELSE r.end_time
             END
           ELSE 
             -- Calculate end_time: if result crosses midnight, use "25:00" format
             CASE 
               WHEN CAST(SUBSTR(time(r.time, '+2 hours'), 1, 2) AS INTEGER) < CAST(SUBSTR(r.time, 1, 2) AS INTEGER) THEN
                 -- Crossed midnight: add 24 hours to hour part
                 CASE 
                   WHEN CAST(SUBSTR(time(r.time, '+2 hours'), 1, 2) AS INTEGER) + 24 < 100 THEN
                     printf('%02d:%s', CAST(SUBSTR(time(r.time, '+2 hours'), 1, 2) AS INTEGER) + 24, SUBSTR(time(r.time, '+2 hours'), 4))
                   ELSE
                     '99:00'
                 END
               ELSE
                 time(r.time, '+2 hours')
             END
         END >= 
         CASE 
           WHEN CAST(SUBSTR(?, 1, 2) AS INTEGER) >= 25 THEN '99:00'
           ELSE ?
         END
       )
     )
     AND (
       -- Check if reservation needs tables of the same capacity
       -- For 1-2 guests: match reservations with 1-2 guests
       ((? = 1 OR ? = 2) AND (r.guests = 1 OR r.guests = 2)) OR
       -- For 3 guests: match reservations with 3-4 guests
       (? = 3 AND (r.guests = 3 OR r.guests = 4)) OR
       -- For 4 guests: match reservations with 4 guests
       (? = 4 AND r.guests = 4) OR
       -- For 5-6 guests: match reservations with 5-6 guests
       ((? = 5 OR ? = 6) AND (r.guests = 5 OR r.guests = 6)) OR
       -- For 7+ guests: match reservations with 7+ guests
       (? >= 7 AND r.guests >= 7)
     )`,
    [date, detectedVenue, endTime, endTime, time, time, guestCount, guestCount, guestCount, guestCount, guestCount, guestCount, guestCount],
    (err, overlapRows) => {
      if (err) {
        console.error('Error counting overlapping reservations:', err);
        return res.status(500).json({ error: 'Database error checking table availability' });
      }

      const overlappingReservations = overlapRows[0]?.overlapping_count || 0;
      console.log(`📊 Table availability check: ${overlappingReservations} overlapping reservations found for ${guestCount} guests at ${time} on ${date}`);

      // Find available tables that match the allowed capacities
      const capacityPlaceholders = allowedCapacities.map(() => '?').join(',');
      db.all(
        `SELECT t.* FROM tables t 
         WHERE UPPER(t.venue) = UPPER(?) AND t.capacity IN (${capacityPlaceholders})
         AND t.id NOT IN (
           -- Exclude tables already assigned to overlapping reservations (using table ID)
           SELECT r.assigned_table FROM reservations r
           WHERE r.date = ? AND UPPER(r.venue) = UPPER(?) 
           AND r.confirmation_status != 'cancelled'
           AND r.assigned_table IS NOT NULL
           AND r.end_time IS NOT NULL
           AND (
             -- Two time slots overlap if: existing_start < requested_end AND existing_end >= requested_start
             -- Using >= ensures a table booked until 4:00 PM blocks bookings starting at 4:00 PM
             CASE 
               WHEN CAST(SUBSTR(r.time, 1, 2) AS INTEGER) >= 25 THEN '99:00'
               ELSE r.time
             END < 
             CASE 
               WHEN CAST(SUBSTR(?, 1, 2) AS INTEGER) >= 25 THEN '99:00'
               ELSE ?
             END
             AND
             CASE 
               WHEN r.end_time IS NOT NULL THEN
                 CASE 
                   WHEN CAST(SUBSTR(r.end_time, 1, 2) AS INTEGER) >= 25 THEN '99:00'
                   ELSE r.end_time
                 END
               ELSE
                 CASE 
                   WHEN CAST(SUBSTR(time(r.time, '+2 hours'), 1, 2) AS INTEGER) >= 25 THEN '99:00'
                   ELSE time(r.time, '+2 hours')
                 END
             END >= 
             CASE 
               WHEN CAST(SUBSTR(?, 1, 2) AS INTEGER) >= 25 THEN '99:00'
               ELSE ?
             END
           )
         )
         ORDER BY t.capacity ASC`,
        [detectedVenue, ...allowedCapacities, date, detectedVenue, endTime, endTime, time, time],
        (err, availableTables) => {
          if (err) {
            console.error('Error checking table availability:', err);
            return res.status(500).json({ error: 'Database error checking table availability' });
          }

          // Get total tables with allowed capacities
          db.all(
            `SELECT COUNT(*) as total FROM tables WHERE UPPER(venue) = UPPER(?) AND capacity IN (${capacityPlaceholders})`,
            [detectedVenue, ...allowedCapacities],
            (err, totalRows) => {
              if (err) {
                console.error('Error counting total tables:', err);
                return res.status(500).json({ error: 'Database error counting tables' });
              }

              const totalTables = totalRows[0]?.total || 0;
              // Calculate actual available count: total tables minus overlapping reservations
              // This accounts for reservations with or without assigned_table
              const actualAvailableCount = Math.max(0, totalTables - overlappingReservations);
              const bookedCount = totalTables - actualAvailableCount;

              // Determine availability status
              let availabilityStatus = 'available';
              if (actualAvailableCount === 0) {
                availabilityStatus = 'full';
              } else if (actualAvailableCount <= 2) {
                availabilityStatus = 'limited';
              }

              res.json({
                date,
                time,
                guests: guestCount,
                venue: detectedVenue,
                availableTables: availableTables.slice(0, actualAvailableCount).map(t => ({
                  tableNumber: t.table_number,
                  capacity: t.capacity
                })),
                availableCount: actualAvailableCount,
                totalTables,
                bookedCount,
                availabilityStatus,
                message: availabilityStatus === 'full'
                  ? 'Sorry, all tables for this party size are currently booked. Please provide your phone number and we will contact you if a table becomes available.'
                  : availabilityStatus === 'limited'
                    ? `Only ${actualAvailableCount} table(s) available for ${guestCount} guests. Book soon!`
                    : `${actualAvailableCount} table(s) available for ${guestCount} guests.`
              });
            }
          );
        }
      );
    }
  );
});

// ============================================
// TABLE ASSIGNMENT & CONFIRMATION SYSTEM
// ============================================

// Helper function to calculate end_time, handling midnight crossover
// Returns end_time in format "HH:MM" or "25:MM" (hours > 24) if crossing midnight
function calculateEndTime(date, time, durationHours = 2) {
  const startDateTime = new Date(`${date}T${time}`);
  const endDateTime = new Date(startDateTime);
  endDateTime.setHours(endDateTime.getHours() + durationHours);

  // Check if end time is on the next day
  const endDate = endDateTime.toISOString().split('T')[0];
  const isNextDay = endDate !== date;

  if (isNextDay) {
    // Store as hours > 24 to indicate next day (e.g., "25:00" for 1:00 AM next day)
    const nextDayHour = endDateTime.getHours() + 24;
    return `${nextDayHour.toString().padStart(2, '0')}:${endDateTime.getMinutes().toString().padStart(2, '0')}`;
  } else {
    return `${endDateTime.getHours().toString().padStart(2, '0')}:${endDateTime.getMinutes().toString().padStart(2, '0')}`;
  }
}

// Helper function to assign best available table
function assignTable(guests, date, time, venue, callback) {
  // Calculate end time (default 2 hours after start) - handles midnight crossover
  const endTime = calculateEndTime(date, time, 2);

  // Determine which table capacities to use based on guest count (same logic as table-availability)
  let capacityQuery = '';
  if (guests >= 1 && guests <= 2) {
    capacityQuery = 't.capacity = 2';
  } else if (guests === 3) {
    capacityQuery = 't.capacity = 3 OR t.capacity = 4';
  } else if (guests === 4) {
    capacityQuery = 't.capacity = 4';
  } else if (guests >= 5 && guests <= 6) {
    capacityQuery = 't.capacity = 6';
  } else if (guests >= 7) {
    capacityQuery = 't.capacity = 12';
  } else {
    return callback(new Error('Invalid guest count for table assignment'), null, endTime);
  }

  // Find available tables that can accommodate guests
  // Use table ID instead of table_number for simpler joins
  // Handle both cases: assigned_table might be table_number (string) or table ID (integer)
  console.log(`🔍 assignTable: Looking for table for ${guests} guests on ${date} at ${time} (endTime: ${endTime}, capacity: ${capacityQuery})`);

  // First, get all tables of the required capacity
  // Normalize venue to uppercase for consistency (tables are stored as 'XIX')
  // IMPORTANT: Order by capacity ASC to prioritize smaller tables first
  // For 3 guests, this ensures capacity 3 tables are checked before capacity 4 tables
  const normalizedVenue = venue ? venue.toUpperCase() : 'XIX';
  console.log(`🔍 Query parameters: venue="${venue}" → normalized="${normalizedVenue}", capacityQuery="${capacityQuery}"`);
  db.all(
    `SELECT t.* FROM tables t 
     WHERE UPPER(t.venue) = UPPER(?) AND (${capacityQuery})
     ORDER BY t.capacity ASC`,
    [normalizedVenue],
    (err, allTables) => {
      if (err) {
        console.error('❌ Error fetching tables:', err);
        return callback(err, null, endTime);
      }

      console.log(`📋 Found ${allTables.length} total tables matching capacity (${capacityQuery})`);

      // Debug: Check if tables exist at all
      if (allTables.length === 0) {
        console.warn(`⚠️ No tables found! Checking if tables exist in database...`);
        db.all('SELECT COUNT(*) as count FROM tables WHERE UPPER(venue) = UPPER(?)', [normalizedVenue], (err2, countRows) => {
          if (!err2 && countRows.length > 0) {
            const totalTables = countRows[0].count;
            console.warn(`   Total tables in database for venue "${normalizedVenue}": ${totalTables}`);
            if (totalTables === 0) {
              console.error(`   ❌ No tables exist in database for venue "${normalizedVenue}"!`);
              console.error(`   Please check if tables were initialized correctly.`);
            } else {
              // Check what capacities exist
              db.all('SELECT DISTINCT capacity FROM tables WHERE UPPER(venue) = UPPER(?)', [normalizedVenue], (err3, capacityRows) => {
                if (!err3) {
                  const capacities = capacityRows.map(r => r.capacity).join(', ');
                  console.warn(`   Available capacities for venue "${normalizedVenue}": ${capacities}`);
                  console.warn(`   Looking for capacity matching: ${capacityQuery}`);
                }
              });
            }
          }
        });
      }

      // Now get overlapping reservations and determine which tables are blocked
      // IMPORTANT: We need to check ALL overlapping reservations, not just those with assigned_table
      // because reservations without assigned_table still need tables and should block availability
      db.all(
        `SELECT r.assigned_table, r.time, r.end_time, r.guests
         FROM reservations r
         WHERE r.date = ? AND UPPER(r.venue) = UPPER(?) 
         AND r.confirmation_status != 'cancelled'
         AND (
           -- Two time slots overlap if: existing_start < requested_end AND existing_end >= requested_start
           CASE 
             WHEN CAST(SUBSTR(r.time, 1, 2) AS INTEGER) >= 25 THEN '99:00'
             ELSE r.time
           END < 
           CASE 
             WHEN CAST(SUBSTR(?, 1, 2) AS INTEGER) >= 25 THEN '99:00'
             ELSE ?
           END
           AND
           CASE 
             WHEN r.end_time IS NOT NULL THEN
               CASE 
                 WHEN CAST(SUBSTR(r.end_time, 1, 2) AS INTEGER) >= 25 THEN '99:00'
                 ELSE r.end_time
               END
             ELSE
               CASE 
                 WHEN CAST(SUBSTR(time(r.time, '+2 hours'), 1, 2) AS INTEGER) >= 25 THEN '99:00'
                 ELSE time(r.time, '+2 hours')
               END
           END >= 
           CASE 
             WHEN CAST(SUBSTR(?, 1, 2) AS INTEGER) >= 25 THEN '99:00'
             ELSE ?
           END
         )`,
        [date, normalizedVenue, endTime, endTime, time, time],
        (err2, overlappingReservations) => {
          if (err2) {
            console.error('❌ Error checking overlapping reservations:', err2);
            return callback(err2, null, endTime);
          }

          console.log(`🔍 Found ${overlappingReservations.length} overlapping reservations (including those without assigned tables)`);

          // Convert assigned_table values to table IDs
          // assigned_table might be:
          // 1. A table ID (integer as string, e.g., "257")
          // 2. A table_number (string, e.g., "Table 2-1")
          // 3. NULL (reservation without assigned table - still needs a table, so we count it)
          const blockedTableIds = new Set();
          let reservationsWithoutTables = 0;

          // For 3 guests: count how many unassigned reservations need capacity 3 vs capacity 4
          // This helps us prioritize skipping capacity 4 tables before capacity 3 tables
          let unassignedNeedingCapacity3 = 0;
          let unassignedNeedingCapacity4 = 0;

          if (overlappingReservations.length > 0) {
            // Separate reservations with and without assigned tables
            const reservationsWithTables = overlappingReservations.filter(r => r.assigned_table);
            const reservationsWithoutAssignedTables = overlappingReservations.filter(r => !r.assigned_table);

            reservationsWithoutTables = reservationsWithoutAssignedTables.length;
            console.log(`   📊 ${reservationsWithTables.length} reservations with assigned tables, ${reservationsWithoutTables} without`);

            // For 3 guests: categorize unassigned reservations by their capacity needs
            if (guests === 3 && reservationsWithoutAssignedTables.length > 0) {
              reservationsWithoutAssignedTables.forEach(r => {
                const resGuestCount = parseInt(r.guests, 10);
                if (resGuestCount === 3) {
                  // Reservation for 3 guests can use capacity 3 or 4, but we'll prioritize capacity 3
                  // Count it as needing capacity 3 first
                  unassignedNeedingCapacity3++;
                } else if (resGuestCount === 4) {
                  // Reservation for 4 guests needs capacity 4
                  unassignedNeedingCapacity4++;
                } else {
                  // Other guest counts - count as needing capacity 4 (larger)
                  unassignedNeedingCapacity4++;
                }
              });
              console.log(`   📊 Unassigned reservations: ${unassignedNeedingCapacity3} need capacity 3, ${unassignedNeedingCapacity4} need capacity 4`);
            }

            // Block tables that are already assigned
            if (reservationsWithTables.length > 0) {
              const assignedTableValues = reservationsWithTables.map(r => r.assigned_table).filter(Boolean);
              console.log(`🔍 Checking assigned_table values:`, assignedTableValues);

              assignedTableValues.forEach((assignedTable) => {
                // If it's a number (table ID), use it directly
                if (!isNaN(assignedTable) && assignedTable !== '') {
                  const tableId = parseInt(assignedTable, 10);
                  // Verify this ID exists and matches our capacity
                  const matchingTable = allTables.find(t => t.id === tableId);
                  if (matchingTable) {
                    blockedTableIds.add(tableId);
                    console.log(`   ✅ Blocked table ID ${tableId} (${matchingTable.table_number}) - assigned_table was ID`);
                  }
                } else {
                  // It's a table_number string, need to look it up
                  const matchingTable = allTables.find(t => t.table_number === assignedTable);
                  if (matchingTable) {
                    blockedTableIds.add(matchingTable.id);
                    console.log(`   ✅ Blocked table ID ${matchingTable.id} (${assignedTable}) - assigned_table was table_number`);
                  } else {
                    console.log(`   ⚠️ Could not find table for assigned_table: "${assignedTable}"`);
                  }
                }
              });
            }

            // For reservations without assigned tables, we need to reserve tables for them too
            // Count how many tables we need to reserve for these overlapping reservations
            // This prevents double-booking: if 2 reservations overlap and both need 2-person tables,
            // we need to reserve 2 tables total, not just 1
            if (reservationsWithoutAssignedTables.length > 0) {
              console.log(`   ⚠️ ${reservationsWithoutAssignedTables.length} overlapping reservations without assigned tables - they also need tables!`);
            }
          }

          // Calculate how many tables we need to reserve for overlapping reservations without assigned tables
          // Each overlapping reservation without a table needs a table, so we need to block that many
          const tablesNeededForUnassigned = reservationsWithoutTables;
          const totalBlocked = blockedTableIds.size + tablesNeededForUnassigned;
          const availableCount = allTables.length - totalBlocked;

          console.log(`📊 Total tables: ${allTables.length}, Blocked (with tables): ${blockedTableIds.size}, Unassigned overlapping: ${reservationsWithoutTables}, Total blocked: ${totalBlocked}, Available: ${availableCount}`);

          // Find first available table (not in blocked set)
          // For 3 guests: prioritize capacity 3 tables, skip capacity 4 tables first for unassigned reservations
          let skippedForUnassigned = 0;
          let skippedCapacity4ForUnassigned = 0;
          const availableTable = allTables.find(t => {
            if (blockedTableIds.has(t.id)) {
              return false; // Table is already assigned to another reservation
            }

            // For 3 guests: smart skipping logic
            if (guests === 3) {
              // If this is a capacity 4 table and we still need to skip capacity 4 tables for unassigned reservations
              if (t.capacity === 4 && skippedCapacity4ForUnassigned < unassignedNeedingCapacity4) {
                skippedCapacity4ForUnassigned++;
                skippedForUnassigned++;
                console.log(`   ⏭️ Skipping capacity 4 table ${t.table_number} for unassigned reservation (${skippedCapacity4ForUnassigned}/${unassignedNeedingCapacity4})`);
                return false;
              }

              // If this is a capacity 3 table and we still need to skip capacity 3 tables for unassigned reservations
              if (t.capacity === 3 && skippedForUnassigned < unassignedNeedingCapacity3) {
                skippedForUnassigned++;
                console.log(`   ⏭️ Skipping capacity 3 table ${t.table_number} for unassigned reservation (${skippedForUnassigned}/${unassignedNeedingCapacity3})`);
                return false;
              }

              // If we've skipped enough tables for unassigned reservations, this table is available
              if (skippedForUnassigned >= reservationsWithoutTables) {
                return true;
              }

              // For capacity 4 tables, skip them if we still need to reserve capacity 4 for unassigned
              if (t.capacity === 4 && skippedForUnassigned < reservationsWithoutTables) {
                skippedForUnassigned++;
                return false;
              }

              // Capacity 3 table is available (we've skipped enough or no unassigned reservations need capacity 3)
              if (t.capacity === 3) {
                return true;
              }
            } else {
              // For other guest counts: original logic
              if (skippedForUnassigned >= reservationsWithoutTables) {
                return true;
              }
              skippedForUnassigned++;
              return false;
            }

            return true; // Default: table is available
          });

          if (!availableTable) {
            console.warn(`⚠️ No available table for ${guests} guests on ${date} at ${time}`);
            console.warn(`   All ${allTables.length} tables are blocked (${blockedTableIds.size} with assigned tables + ${reservationsWithoutTables} needed for unassigned overlapping reservations)`);
            return callback(null, null, endTime);
          }

          console.log(`✅ Assigned table ID ${availableTable.id} (${availableTable.table_number}, capacity: ${availableTable.capacity}) to ${guests} guests on ${date} at ${time}`);
          callback(null, availableTable.id, endTime);
        }
      );
    }
  );
}

// Generate unique confirmation token
function generateConfirmationToken() {
  return require('crypto').randomBytes(32).toString('hex');
}

// Calculate confirmation deadline (3 hours before reservation, but minimum 30 minutes from now)
function calculateConfirmationDeadline(date, time) {
  const [hours, minutes] = time.split(':');
  const reservationDateTime = new Date(`${date}T${time}`);
  const now = new Date();

  // Calculate 3 hours before reservation
  const deadline = new Date(reservationDateTime);
  deadline.setHours(deadline.getHours() - 3);

  // If deadline is in the past or less than 30 minutes from now, set it to 30 minutes from now
  const minDeadline = new Date(now.getTime() + 30 * 60 * 1000); // 30 minutes from now

  if (deadline < minDeadline) {
    return minDeadline.toISOString();
  }

  return deadline.toISOString();
}

// Confirmation endpoint - one-click confirmation
app.get('/api/confirm-reservation/:token', (req, res) => {
  const { token } = req.params;

  db.get('SELECT * FROM reservations WHERE confirmation_token = ?', [token], (err, reservation) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send(`
        <html>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">Error</h1>
            <p>An error occurred. Please contact the restaurant.</p>
            <a href="/">Return to Home</a>
          </body>
        </html>
      `);
    }

    if (!reservation) {
      return res.status(404).send(`
        <html>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">Invalid Confirmation Link</h1>
            <p>This confirmation link is invalid or has expired.</p>
            <a href="/">Return to Home</a>
          </body>
        </html>
      `);
    }

    // Check if already confirmed
    if (reservation.confirmation_status === 'confirmed') {
      return res.send(`
        <html>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #28a745;">Already Confirmed</h1>
            <p>Your reservation for ${reservation.date} at ${reservation.time} has already been confirmed.</p>
            <a href="/">Return to Home</a>
          </body>
        </html>
      `);
    }

    // Check if deadline passed
    if (reservation.confirmation_deadline) {
      const deadline = new Date(reservation.confirmation_deadline);
      if (new Date() > deadline) {
        // Auto-cancel
        const cancelledTableId = reservation.assigned_table;
        const cancelledDate = reservation.date;
        const cancelledTime = reservation.time;
        const cancelledGuests = reservation.guests;
        const cancelledVenue = reservation.venue || 'XIX';

        db.run('UPDATE reservations SET confirmation_status = ? WHERE id = ?', ['cancelled', reservation.id], (err) => {
          if (err) {
            console.error('Error cancelling reservation:', err);
          } else {
            // Try to reassign table to waitlist reservations
            if (cancelledTableId) {
              reassignTableToWaitlist(cancelledTableId, cancelledDate, cancelledTime, cancelledGuests, cancelledVenue);
            }
          }
        });
        return res.send(`
          <html>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
              <h1 style="color: #d32f2f;">Confirmation Deadline Passed</h1>
              <p>Your reservation has been cancelled because it was not confirmed within 3 hours of the booking time.</p>
              <p>Please make a new reservation.</p>
              <a href="/reservations">Make New Reservation</a>
            </body>
          </html>
        `);
      }
    }

    // Confirm reservation
    db.run(
      'UPDATE reservations SET confirmation_status = ?, confirmed_at = CURRENT_TIMESTAMP WHERE id = ?',
      ['confirmed', reservation.id],
      (err) => {
        if (err) {
          console.error('Error confirming reservation:', err);
          return res.status(500).send(`
            <html>
              <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #d32f2f;">Error</h1>
                <p>An error occurred while confirming your reservation.</p>
                <a href="/">Return to Home</a>
              </body>
            </html>
          `);
        }

        res.send(`
          <html>
            <head>
              <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .success-box { background: white; padding: 40px; border-radius: 10px; max-width: 500px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #28a745; margin-bottom: 20px; }
                .details { text-align: left; margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }
                .details p { margin: 10px 0; }
                a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #A8871A; color: white; text-decoration: none; border-radius: 5px; }
              </style>
            </head>
            <body>
              <div class="success-box">
                <h1>✅ Reservation Confirmed!</h1>
                <p>Thank you for confirming your reservation.</p>
                <div class="details">
                  <p><strong>Name:</strong> ${reservation.name}</p>
                  <p><strong>Date:</strong> ${reservation.date}</p>
                  <p><strong>Time:</strong> ${reservation.time}</p>
                  <p><strong>Guests:</strong> ${reservation.guests}</p>
                  ${reservation.assigned_table ? `<p><strong>Table:</strong> ${reservation.assigned_table}</p>` : ''}
                </div>
                <p style="color: #666; font-size: 0.9em;">We look forward to seeing you!</p>
                <a href="/">Return to Home</a>
              </div>
            </body>
          </html>
        `);
      }
    );
  });
});

// Cancellation endpoint - allows customers to cancel their reservation
app.get('/api/cancel-reservation/:token', (req, res) => {
  const { token } = req.params;

  db.get('SELECT * FROM reservations WHERE confirmation_token = ?', [token], (err, reservation) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send(`
        <html>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">Error</h1>
            <p>An error occurred. Please contact the restaurant.</p>
            <a href="/">Return to Home</a>
          </body>
        </html>
      `);
    }

    if (!reservation) {
      return res.status(404).send(`
        <html>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">Invalid Cancellation Link</h1>
            <p>This cancellation link is invalid or has expired.</p>
            <a href="/">Return to Home</a>
          </body>
        </html>
      `);
    }

    // Check if already cancelled
    if (reservation.confirmation_status === 'cancelled') {
      return res.send(`
        <html>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #ff9800;">Already Cancelled</h1>
            <p>Your reservation for ${reservation.date} at ${reservation.time} has already been cancelled.</p>
            <a href="/">Return to Home</a>
          </body>
        </html>
      `);
    }

    // Cancel reservation
    const cancelledTableId = reservation.assigned_table;
    const cancelledDate = reservation.date;
    const cancelledTime = reservation.time;
    const cancelledGuests = reservation.guests;
    const cancelledVenue = reservation.venue || 'XIX';
    const calendarEventId = reservation.google_calendar_event_id;

    db.run(
      'UPDATE reservations SET confirmation_status = ? WHERE id = ?',
      ['cancelled', reservation.id],
      (err) => {
        if (err) {
          console.error('Error cancelling reservation:', err);
          return res.status(500).send(`
            <html>
              <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #d32f2f;">Error</h1>
                <p>An error occurred while cancelling your reservation.</p>
                <a href="/">Return to Home</a>
              </body>
            </html>
          `);
        }

        console.log(`✅ Reservation ${reservation.id} cancelled by customer`);

        // Delete from Google Calendar if event exists
        if (calendarEventId && calendar && process.env.GOOGLE_CALENDAR_ID) {
          const calendarId = process.env.GOOGLE_CALENDAR_ID;
          calendar.events.delete({
            calendarId: calendarId,
            eventId: calendarEventId
          }).then(() => {
            console.log(`✅ Google Calendar event ${calendarEventId} deleted after cancellation`);
          }).catch((calendarErr) => {
            console.error('⚠️ Error deleting Google Calendar event after cancellation:', calendarErr.message);
            // Don't fail the cancellation if calendar deletion fails
          });
        }

        // Try to reassign table to waitlist reservations
        if (cancelledTableId) {
          reassignTableToWaitlist(cancelledTableId, cancelledDate, cancelledTime, cancelledGuests, cancelledVenue);
        }

        res.send(`
          <html>
            <head>
              <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .success-box { background: white; padding: 40px; border-radius: 10px; max-width: 500px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #dc3545; margin-bottom: 20px; }
                .details { text-align: left; margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }
                .details p { margin: 10px 0; }
                a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #A8871A; color: white; text-decoration: none; border-radius: 5px; }
              </style>
            </head>
            <body>
              <div class="success-box">
                <h1>❌ Reservation Cancelled</h1>
                <p>Your reservation has been successfully cancelled.</p>
                <div class="details">
                  <p><strong>Name:</strong> ${reservation.name}</p>
                  <p><strong>Date:</strong> ${reservation.date}</p>
                  <p><strong>Time:</strong> ${reservation.time}</p>
                  <p><strong>Guests:</strong> ${reservation.guests}</p>
                </div>
                <p style="color: #666; font-size: 0.9em;">We're sorry to see you go. We hope to serve you another time!</p>
                <a href="/reservations">Make New Reservation</a>
              </div>
            </body>
          </html>
        `);
      }
    );
  });
});

// Function to reassign a cancelled table to waitlist reservations
function reassignTableToWaitlist(freedTableId, date, time, guests, venue) {
  console.log(`🔄 Attempting to reassign table ${freedTableId} to waitlist reservations for ${date} at ${time} (${guests} guests, venue: ${venue})`);

  // Find waitlist reservations (pending, no assigned_table) for the same date/time/guest count
  db.all(
    `SELECT id, guests, date, time, venue, assigned_table 
     FROM reservations 
     WHERE confirmation_status = 'pending' 
     AND assigned_table IS NULL 
     AND date = ? 
     AND time = ? 
     AND guests = ? 
     AND UPPER(venue) = UPPER(?)
     ORDER BY id ASC
     LIMIT 1`,
    [date, time, guests, venue],
    (err, waitlistReservations) => {
      if (err) {
        console.error('❌ Error finding waitlist reservations:', err);
        return;
      }

      if (waitlistReservations.length === 0) {
        console.log(`ℹ️ No waitlist reservations found for ${date} at ${time} (${guests} guests)`);
        return;
      }

      const waitlistReservation = waitlistReservations[0];
      console.log(`✅ Found waitlist reservation ${waitlistReservation.id} - assigning table ${freedTableId}`);

      // Calculate end_time for the waitlist reservation
      const endTime = calculateEndTime(date, time, 2);

      // Assign the freed table to the waitlist reservation
      db.run(
        'UPDATE reservations SET assigned_table = ?, end_time = ? WHERE id = ?',
        [freedTableId.toString(), endTime, waitlistReservation.id],
        (updateErr) => {
          if (updateErr) {
            console.error(`❌ Error assigning table ${freedTableId} to waitlist reservation ${waitlistReservation.id}:`, updateErr);
          } else {
            console.log(`✅ Successfully assigned table ${freedTableId} to waitlist reservation ${waitlistReservation.id}`);

            // Send waitlist assignment notification email to the customer
            db.get('SELECT * FROM reservations WHERE id = ?', [waitlistReservation.id], (err, fullReservation) => {
              if (!err && fullReservation) {
                const reservationData = {
                  name: fullReservation.name,
                  email: fullReservation.email,
                  phone: fullReservation.phone,
                  date: fullReservation.date,
                  time: fullReservation.time,
                  guests: fullReservation.guests,
                  venue: fullReservation.venue,
                  occasion: fullReservation.occasion,
                  specialRequests: fullReservation.special_requests
                };
                sendWaitlistAssignmentEmail(waitlistReservation.id, freedTableId, fullReservation.confirmation_token, reservationData).catch(err => {
                  console.error('Error sending waitlist assignment email:', err);
                });
              }
            });
          }
        }
      );
    }
  );
}

// Auto-cancellation job - cancels unconfirmed reservations after confirmation deadline passes
// Only cancels if deadline has passed AND reservation time hasn't passed yet
// Also triggers automatic reassignment to waitlist
setInterval(() => {
  const now = new Date();

  // First, get reservations that will be cancelled (including Google Calendar event IDs)
  db.all(
    `SELECT id, assigned_table, date, time, guests, venue, google_calendar_event_id 
     FROM reservations 
     WHERE confirmation_status = 'pending' 
     AND confirmation_deadline IS NOT NULL 
     AND datetime(confirmation_deadline) < datetime(?)
     AND datetime(date || ' ' || time) > datetime(?)`,
    [now.toISOString(), now.toISOString()],
    (err, reservationsToCancel) => {
      if (err) {
        console.error('Error fetching reservations to cancel:', err);
        return;
      }

      if (reservationsToCancel.length === 0) {
        return; // No reservations to cancel
      }

      // Cancel each reservation individually to handle Google Calendar deletion
      reservationsToCancel.forEach((reservation) => {
        const calendarEventId = reservation.google_calendar_event_id;

        // Update status to cancelled
        db.run(
          `UPDATE reservations 
           SET confirmation_status = 'cancelled' 
           WHERE id = ?`,
          [reservation.id],
          (updateErr) => {
            if (updateErr) {
              console.error(`Error cancelling reservation ${reservation.id}:`, updateErr);
              return;
            }

            console.log(`⚠️ Auto-cancelled reservation ${reservation.id}`);

            // Delete from Google Calendar if event exists
            if (calendarEventId && calendar && process.env.GOOGLE_CALENDAR_ID) {
              const calendarId = process.env.GOOGLE_CALENDAR_ID;
              calendar.events.delete({
                calendarId: calendarId,
                eventId: calendarEventId
              }).then(() => {
                console.log(`✅ Google Calendar event ${calendarEventId} deleted after auto-cancellation`);
              }).catch((calendarErr) => {
                console.error(`⚠️ Error deleting Google Calendar event ${calendarEventId} after auto-cancellation:`, calendarErr.message);
              });
            }

            // Try to reassign table to waitlist reservations
            if (reservation.assigned_table) {
              reassignTableToWaitlist(
                reservation.assigned_table,
                reservation.date,
                reservation.time,
                reservation.guests,
                reservation.venue || 'XIX'
              );
            }
          }
        );
      });
    }
  );
}, 5 * 60 * 1000); // Every 5 minutes

// Reminder sending job - sends reminders 4-5 hours before reservation
setInterval(() => {
  const now = new Date();
  const reminderWindowStart = new Date(now.getTime() + 4 * 60 * 60 * 1000); // 4 hours from now
  const reminderWindowEnd = new Date(now.getTime() + 5 * 60 * 60 * 1000); // 5 hours from now

  // Find reservations that need reminders
  db.all(
    `SELECT * FROM reservations 
     WHERE confirmation_status = 'pending' 
     AND date || ' ' || time BETWEEN datetime(?) AND datetime(?)
     AND (email_sent_to_customer = 0 OR email_sent_to_customer IS NULL)`,
    [reminderWindowStart.toISOString().slice(0, 16), reminderWindowEnd.toISOString().slice(0, 16)],
    (err, reservations) => {
      if (err) {
        console.error('Error finding reservations for reminders:', err);
        return;
      }

      reservations.forEach(reservation => {
        sendConfirmationReminder(reservation);
      });
    }
  );
}, 10 * 60 * 1000); // Check every 10 minutes

// Function to send confirmation reminder email and SMS
function sendConfirmationReminder(reservation) {
  const confirmationUrl = `${getBaseUrl()}/api/confirm-reservation/${reservation.confirmation_token}`;

  // Send email reminder
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
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
    const subject = `Please Confirm Your Reservation - ${reservation.date} at ${reservation.time}`;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #A8871A;">Please Confirm Your Reservation</h2>
        <p>Hello ${reservation.name},</p>
        <p>This is a reminder to confirm your reservation at XIX Restaurant:</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <p><strong>Date:</strong> ${reservation.date}</p>
          <p><strong>Time:</strong> ${reservation.time}</p>
          <p><strong>Guests:</strong> ${reservation.guests}</p>
          ${reservation.assigned_table ? `<p><strong>Table:</strong> ${reservation.assigned_table}</p>` : ''}
        </div>
        <p style="color: #d32f2f; font-weight: bold;">⚠️ Important: Please confirm your reservation within 3 hours, or it will be automatically cancelled.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${confirmationUrl}" 
             style="display: inline-block; background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">
            ✅ Confirm Reservation
          </a>
        </div>
        <p style="color: #666; font-size: 0.9em;">Or copy this link: ${confirmationUrl}</p>
        <p style="color: #666; font-size: 0.9em; margin-top: 30px;">If you need to cancel or change your reservation, please contact us.</p>
      </div>
    `;

    transporter.sendMail({
      from,
      to: reservation.email,
      subject,
      html
    }, (err, info) => {
      if (err) {
        console.error('Error sending reminder email:', err);
      } else {
        console.log(`✅ Reminder email sent to ${reservation.email}`);
      }
    });
  }

  // Send SMS reminder (if enabled)
  if (twilioClient && process.env.TWILIO_PHONE_NUMBER && reservation.phone) {
    const smsMessage = `XIX Restaurant: Please confirm your reservation for ${reservation.date} at ${reservation.time}. Confirm: ${confirmationUrl}`;

    twilioClient.messages.create({
      body: smsMessage,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: reservation.phone
    }).then(message => {
      console.log(`✅ Reminder SMS sent to ${reservation.phone}: ${message.sid}`);
    }).catch(err => {
      console.error('Error sending reminder SMS:', err);
    });
  }

  // Mark as reminder sent
  db.run('UPDATE reservations SET email_sent_to_customer = 1 WHERE id = ?', [reservation.id]);
}

// Helper function to create a Google Calendar event for a reservation
async function createGoogleCalendarEvent(reservation) {
  if (!calendar || !process.env.GOOGLE_CALENDAR_ID) {
    return null; // Calendar not configured
  }

  try {
    const calendarId = process.env.GOOGLE_CALENDAR_ID;

    // Parse date and time
    const [year, month, day] = reservation.date.split('-');
    const [hours, minutes] = reservation.time.split(':');
    const startDateTime = new Date(year, month - 1, day, parseInt(hours), parseInt(minutes));

    // Calculate end time (default 2 hours, or use end_time if available)
    let endDateTime;
    if (reservation.end_time) {
      // Parse end_time (handles midnight crossover like "25:00")
      const [endHours, endMinutes] = reservation.end_time.split(':');
      let endHour = parseInt(endHours);
      let endDay = parseInt(day);

      // Handle midnight crossover (hours >= 25 means next day)
      if (endHour >= 25) {
        endHour = endHour - 24;
        endDay = endDay + 1;
      }

      endDateTime = new Date(year, month - 1, endDay, endHour, parseInt(endMinutes));
    } else {
      endDateTime = new Date(startDateTime);
      endDateTime.setHours(endDateTime.getHours() + 2); // Default 2 hours
    }

    // Get table number for display
    let tableDisplay = 'Not assigned';
    if (reservation.assigned_table) {
      try {
        const tableInfo = await new Promise((resolve, reject) => {
          db.get('SELECT table_number FROM tables WHERE id = ?', [reservation.assigned_table], (err, row) => {
            if (err) reject(err);
            else resolve(row);
          });
        });
        if (tableInfo) {
          tableDisplay = tableInfo.table_number;
        }
      } catch (err) {
        console.warn('Could not look up table name for calendar event:', err.message);
      }
    }

    // Format event details
    const venueName = reservation.venue === 'MIRROR' ? 'Mirror' : 'XIX';
    const eventTitle = `${reservation.name} - ${reservation.guests} guest${reservation.guests !== 1 ? 's' : ''} - ${venueName}`;

    let eventDescription = `Reservation for ${reservation.name}\n`;
    eventDescription += `Guests: ${reservation.guests}\n`;
    eventDescription += `Table: ${tableDisplay}\n`;
    eventDescription += `Phone: ${reservation.phone}\n`;
    eventDescription += `Email: ${reservation.email}\n`;
    if (reservation.occasion) {
      eventDescription += `Occasion: ${reservation.occasion}\n`;
    }
    if (reservation.special_requests) {
      eventDescription += `Special Requests: ${reservation.special_requests}\n`;
    }
    if (reservation.confirmation_status === 'pending') {
      eventDescription += `\n⚠️ Status: Pending Confirmation`;
    }

    // Create the event
    const event = {
      summary: eventTitle,
      description: eventDescription,
      start: {
        dateTime: startDateTime.toISOString(),
        timeZone: 'Europe/London'
      },
      end: {
        dateTime: endDateTime.toISOString(),
        timeZone: 'Europe/London'
      },
      reminders: {
        useDefault: false,
        overrides: [
          { method: 'email', minutes: 24 * 60 }, // 1 day before
          { method: 'popup', minutes: 60 } // 1 hour before
        ]
      }
    };

    const createdEvent = await calendar.events.insert({
      calendarId: calendarId,
      resource: event
    });

    console.log(`✅ Created Google Calendar event ${createdEvent.data.id} for reservation ${reservation.id}`);
    return createdEvent.data.id; // Return the event ID

  } catch (err) {
    console.error(`❌ Error creating Google Calendar event for reservation ${reservation.id}:`, err.message);
    return null;
  }
}

// Google Calendar Sync - Syncs calendar events to database
async function syncGoogleCalendar() {
  if (!calendar || !process.env.GOOGLE_CALENDAR_ID) {
    return; // Calendar not configured
  }

  try {
    const now = new Date();
    // Query events from 7 days ago to 30 days in the future
    // This ensures we catch past events (for syncing existing reservations)
    // and future events (for upcoming bookings)
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const thirtyDaysLater = new Date(now);
    thirtyDaysLater.setDate(thirtyDaysLater.getDate() + 30);

    // Get events from Google Calendar for the extended time range
    const calendarId = process.env.GOOGLE_CALENDAR_ID;

    // Try to get calendar info first to verify access
    try {
      await calendar.calendars.get({ calendarId });
      console.log(`✅ Successfully accessed calendar: ${calendarId}`);
    } catch (calendarError) {
      console.error('⚠️ Google Calendar access error:', calendarError.message);
      console.error('   Calendar ID:', calendarId);
      console.error('   Error details:', calendarError.response?.data || calendarError.message);

      // Try to list all calendars to help find the correct ID
      try {
        console.log('📋 Attempting to list available calendars...');
        const calendarList = await calendar.calendarList.list();
        console.log('Available calendars:');
        calendarList.data.items?.forEach(cal => {
          console.log(`   - ${cal.summary || cal.id}: ID = ${cal.id}`);
        });
      } catch (listError) {
        console.error('   Could not list calendars:', listError.message);
      }

      console.error('   Please verify:');
      console.error('   1. The calendar is shared with: xix-calendar-sync@xix-restaurant-calendar.iam.gserviceaccount.com');
      console.error('   2. The calendar ID in .env matches the calendar you want to use');
      console.error('   3. For secondary calendars, use the calendar ID from the list above, not the email address');
      return; // Don't proceed if we can't access the calendar
    }

    const response = await calendar.events.list({
      calendarId: calendarId,
      timeMin: sevenDaysAgo.toISOString(),
      timeMax: thirtyDaysLater.toISOString(),
      singleEvents: true,
      orderBy: 'startTime'
    });

    const events = response.data.items || [];
    console.log(`📅 Found ${events.length} events in Google Calendar (from ${sevenDaysAgo.toISOString().split('T')[0]} to ${thirtyDaysLater.toISOString().split('T')[0]})`);

    // Log event details for debugging
    if (events.length > 0) {
      console.log('📋 Events found:');
      events.forEach((event, index) => {
        const eventStart = new Date(event.start.dateTime || event.start.date);
        const eventDate = eventStart.toISOString().split('T')[0];
        const eventTime = eventStart.toTimeString().split(' ')[0].substring(0, 5);
        console.log(`   ${index + 1}. ${event.summary || 'Untitled'} - ${eventDate} at ${eventTime} (ID: ${event.id})`);
      });
    }

    for (const event of events) {
      // Check if reservation exists in DB by Google Calendar event ID
      db.get('SELECT * FROM reservations WHERE google_calendar_event_id = ?', [event.id], (err, existingReservation) => {
        if (err) {
          console.error('Error checking existing reservation:', err);
          return;
        }

        if (existingReservation) {
          // Update existing reservation if event was modified
          const eventStart = new Date(event.start.dateTime || event.start.date);
          const eventEnd = new Date(event.end.dateTime || event.end.date);
          const eventDate = eventStart.toISOString().split('T')[0];
          const eventTime = `${eventStart.getHours().toString().padStart(2, '0')}:${eventStart.getMinutes().toString().padStart(2, '0')}`;

          // Calculate end_time handling midnight crossover (use helper function)
          const endTime = calculateEndTime(
            eventDate,
            eventTime,
            (eventEnd.getTime() - eventStart.getTime()) / (1000 * 60 * 60) // duration in hours
          );

          // Update end_time if changed
          if (existingReservation.end_time !== endTime) {
            db.run(
              'UPDATE reservations SET end_time = ?, last_synced_at = CURRENT_TIMESTAMP WHERE id = ?',
              [endTime, existingReservation.id],
              (err) => {
                if (err) {
                  console.error('Error updating reservation from calendar:', err);
                } else {
                  console.log(`✅ Updated reservation ${existingReservation.id} end_time to ${endTime} from Google Calendar`);

                  // Check for conflicts
                  checkTableConflicts(existingReservation.assigned_table, eventDate, existingReservation.time, endTime, existingReservation.id);
                }
              }
            );
          }
        }
      });
    }

    // Check for reservations in DB that don't have Google Calendar events and create them
    db.all('SELECT * FROM reservations WHERE google_calendar_event_id IS NULL AND confirmation_status != "cancelled" ORDER BY date, time', [], async (err, reservationsWithoutEvents) => {
      if (!err && reservationsWithoutEvents && reservationsWithoutEvents.length > 0) {
        console.log(`⚠️ Found ${reservationsWithoutEvents.length} reservations in database without Google Calendar events - creating them now...`);

        for (const reservation of reservationsWithoutEvents) {
          const calendarEventId = await createGoogleCalendarEvent(reservation);
          if (calendarEventId) {
            // Update reservation with calendar event ID
            db.run('UPDATE reservations SET google_calendar_event_id = ? WHERE id = ?', [calendarEventId, reservation.id], (updateErr) => {
              if (updateErr) {
                console.error(`Error updating reservation ${reservation.id} with calendar event ID:`, updateErr);
              } else {
                console.log(`✅ Created and linked Google Calendar event for reservation #${reservation.id} - ${reservation.name} on ${reservation.date} at ${reservation.time}`);
              }
            });
          }
        }
      }
    });

    // Check for reservations in DB that have Google Calendar event IDs but the events no longer exist in Calendar
    // This detects when events are deleted from Google Calendar
    db.all('SELECT id, name, date, time, google_calendar_event_id FROM reservations WHERE google_calendar_event_id IS NOT NULL AND confirmation_status != "cancelled"', [], (err, reservationsWithEventIds) => {
      if (err) {
        console.error('Error checking reservations with event IDs:', err);
        return;
      }

      if (reservationsWithEventIds && reservationsWithEventIds.length > 0) {
        // Create a Set of event IDs that exist in Google Calendar
        const existingEventIds = new Set(events.map(e => e.id));

        // Find reservations whose Google Calendar events no longer exist
        const deletedEvents = reservationsWithEventIds.filter(res => !existingEventIds.has(res.google_calendar_event_id));

        if (deletedEvents.length > 0) {
          console.log(`🗑️ Found ${deletedEvents.length} reservations whose Google Calendar events were deleted:`);
          deletedEvents.forEach((res, index) => {
            console.log(`   ${index + 1}. Reservation #${res.id} - ${res.name} on ${res.date} at ${res.time} (Event ID: ${res.google_calendar_event_id})`);
          });

          // Delete these reservations from the database
          deletedEvents.forEach((res) => {
            db.run('DELETE FROM reservations WHERE id = ?', [res.id], (deleteErr) => {
              if (deleteErr) {
                console.error(`❌ Error deleting reservation ${res.id} (event deleted from calendar):`, deleteErr);
              } else {
                console.log(`✅ Deleted reservation #${res.id} (${res.name}) - Google Calendar event was removed`);
              }
            });
          });
        }
      }
    });

    console.log(`✅ Google Calendar sync completed - checked ${events.length} events`);
  } catch (err) {
    console.error('Error syncing Google Calendar:', err);
  }
}

// Check for table conflicts when end_time is extended
function checkTableConflicts(tableNumber, date, startTime, newEndTime, currentReservationId) {
  if (!tableNumber) return;

  db.all(
    `SELECT * FROM reservations 
     WHERE assigned_table = ? 
     AND date = ? 
     AND id != ?
     AND confirmation_status != 'cancelled'
     AND (
       (time >= ? AND time < ?) OR
       (time < ? AND end_time > ?)
     )`,
    [tableNumber, date, currentReservationId, startTime, newEndTime, startTime, startTime],
    (err, conflicts) => {
      if (err) {
        console.error('Error checking conflicts:', err);
        return;
      }

      if (conflicts.length > 0) {
        console.warn(`⚠️ CONFLICT DETECTED: Table ${tableNumber} on ${date} - ${conflicts.length} reservation(s) conflict with extended time`);
        // TODO: Send notification to manager about conflict
        // For now, just log it - manager can resolve manually
      }
    }
  );
}

// API endpoint to assign tables to existing reservations without assigned tables
app.post('/api/assign-tables-to-reservations', (req, res) => {
  console.log('🔄 Starting bulk table assignment for reservations without assigned tables...');

  // Get all reservations without assigned tables
  db.all(
    `SELECT id, guests, date, time, venue, assigned_table, end_time 
     FROM reservations 
     WHERE assigned_table IS NULL 
     AND confirmation_status != 'cancelled'
     ORDER BY date, time`,
    [],
    (err, reservations) => {
      if (err) {
        console.error('Error fetching reservations:', err);
        return res.status(500).json({ error: 'Failed to fetch reservations' });
      }

      if (reservations.length === 0) {
        return res.json({
          message: 'No reservations need table assignment',
          assigned: 0,
          total: 0
        });
      }

      console.log(`📋 Found ${reservations.length} reservations without assigned tables`);

      let assignedCount = 0;
      let failedCount = 0;
      const results = [];

      // Process each reservation
      reservations.forEach((reservation, index) => {
        assignTable(
          reservation.guests,
          reservation.date,
          reservation.time,
          reservation.venue || 'XIX',
          (assignErr, assignedTable, endTime) => {
            if (assignErr) {
              console.error(`❌ Error assigning table to reservation ${reservation.id}:`, assignErr);
              failedCount++;
              results.push({
                id: reservation.id,
                status: 'failed',
                error: assignErr.message
              });
            } else if (assignedTable) {
              // Update reservation with assigned table (store as string for compatibility)
              db.run(
                'UPDATE reservations SET assigned_table = ?, end_time = ? WHERE id = ?',
                [assignedTable.toString(), endTime, reservation.id],
                (updateErr) => {
                  if (updateErr) {
                    console.error(`❌ Error updating reservation ${reservation.id}:`, updateErr);
                    failedCount++;
                    results.push({
                      id: reservation.id,
                      status: 'failed',
                      error: updateErr.message
                    });
                  } else {
                    console.log(`✅ Assigned table ${assignedTable} to reservation ${reservation.id}`);
                    assignedCount++;
                    results.push({
                      id: reservation.id,
                      status: 'assigned',
                      table: assignedTable
                    });
                  }

                  // If this is the last reservation, send response
                  if (assignedCount + failedCount === reservations.length) {
                    res.json({
                      message: `Table assignment completed`,
                      assigned: assignedCount,
                      failed: failedCount,
                      total: reservations.length,
                      results: results
                    });
                  }
                }
              );
            } else {
              console.warn(`⚠️ No table available for reservation ${reservation.id}`);
              failedCount++;
              results.push({
                id: reservation.id,
                status: 'no_table_available',
                message: 'No available table found'
              });

              // If this is the last reservation, send response
              if (assignedCount + failedCount === reservations.length) {
                res.json({
                  message: `Table assignment completed`,
                  assigned: assignedCount,
                  failed: failedCount,
                  total: reservations.length,
                  results: results
                });
              }
            }
          }
        );
      });
    }
  );
});

// Google Calendar sync job - runs every 1 minute
if (calendar) {
  setInterval(() => {
    syncGoogleCalendar();
  }, 1 * 60 * 1000); // Every 1 minute

  // Initial sync on startup
  setTimeout(() => {
    syncGoogleCalendar();
  }, 30 * 1000); // Wait 30 seconds after startup
}

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

    // Validate and log email
    if (customerEmail && !customerEmail.includes('@')) {
      console.warn('⚠️ Invalid email format provided:', customerEmail);
    }
    console.log('📧 Creating checkout session with email:', customerEmail || 'not provided');

    // Get base URL from request
    const baseUrl = req.protocol + '://' + req.get('host');
    const successUrl = `${baseUrl}/payment-success?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${baseUrl}/payment?amount=${amount}&reservationId=${reservationId || ''}&eventId=${eventId || ''}`;

    // Create Checkout Session
    // Store customer email in both customer_email and metadata to ensure it's preserved
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
        customerEmail: customerEmail || '', // Store email in metadata as backup - CRITICAL for preserving email
      },
      success_url: successUrl,
      cancel_url: cancelUrl,
    });

    console.log('✅ Checkout session created with email in metadata:', session.metadata?.customerEmail || 'not found');

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
// Note: reservation_id column removed from payments table
function savePaymentToDatabase(paymentData) {
  console.log('💾 savePaymentToDatabase called with:', paymentData);
  return new Promise((resolve, reject) => {
    const {
      paymentIntentId,
      amountPaid,
      currency,
      eventType,
      eventDate,
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
          // Update existing payment with all fields (including customer_email, customer_name, event_type, event_date)
          db.run(
            `UPDATE payments SET 
              payment_status = 'paid',
              amount_paid = ?,
              event_type = ?,
              event_date = ?,
              customer_email = ?,
              customer_name = ?,
              stripe_session_id = ?,
              updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [
              amountPaid,
              eventType || null,
              eventDate || null,
              customerEmail || null,
              customerName || null,
              stripeSessionId || null,
              existing.id
            ],
            function (err) {
              if (err) {
                console.error('Error updating payment record:', err);
                reject(err);
              } else {
                console.log('✓ Payment record updated in payments table (ID:', existing.id + ')');
                console.log('✓ Updated fields:', {
                  eventType,
                  eventDate,
                  customerEmail,
                  customerName
                });
                resolve({ id: existing.id, updated: true });
              }
            }
          );
        } else {
          // Insert new payment (reservation_id removed from table)
          db.run(
            `INSERT INTO payments (payment_intent_id, amount_paid, currency, payment_status, event_type, event_date, customer_email, customer_name, stripe_session_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              paymentIntentId,
              amountPaid,
              currency || 'gbp',
              'paid',
              eventType,
              eventDate || null,
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

// Helper function to send payment confirmation emails for event payments (without reservation)
// Uses the same email pattern as reservation emails - customer email from client, manager email from .env
async function sendEventPaymentConfirmationEmails(session, eventType, eventDate, customerEmail, customerName) {
  console.log('📧 sendEventPaymentConfirmationEmails called with:', {
    sessionId: session?.id,
    eventType,
    eventDate,
    customerEmail,
    customerName,
    hasSMTP: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
    managerEmail: process.env.MANAGER_EMAIL || process.env.SMTP_USER
  });

  try {
    // Check if email is configured - same check as reservation emails
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      console.warn('⚠️ Email not configured - skipping email send');
      console.warn('⚠️ SMTP configuration check:', {
        SMTP_HOST: !!process.env.SMTP_HOST,
        SMTP_USER: !!process.env.SMTP_USER,
        SMTP_PASS: !!process.env.SMTP_PASS
      });
      return null;
    }

    console.log('✅ Email configuration found, proceeding to send emails...');

    // Use the same transporter setup as reservation emails
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

    // Use the same email addresses as reservation emails
    const from = process.env.MAIL_FROM || process.env.SMTP_USER;
    const managerEmail = process.env.MANAGER_EMAIL || process.env.SMTP_USER;

    console.log('📧 Email addresses:', {
      from,
      to_customer: customerEmail,
      to_manager: managerEmail
    });
    const amountPaid = session.amount_total / 100;
    const paymentDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric'
    });
    const paymentTime = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit'
    });

    // Format event date if available
    let formattedEventDate = 'TBA';
    if (eventDate) {
      try {
        const dateParts = eventDate.split('-');
        const dateYear = parseInt(dateParts[0], 10);
        const dateMonth = parseInt(dateParts[1], 10) - 1;
        const dateDay = parseInt(dateParts[2], 10);
        const dateObj = new Date(dateYear, dateMonth, dateDay);
        formattedEventDate = dateObj.toLocaleDateString('en-US', {
          weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
        });
      } catch (e) {
        formattedEventDate = eventDate;
      }
    }

    const venueName = 'XIX Restaurant';
    const venueAddress = 'XIX Restaurant, 123 King\'s Road, London SW3 4RD';

    // Generate invoice number (using session ID)
    const invoiceNumber = `INV-${session.id.substring(0, 12).toUpperCase()}`;

    // Customer Event Ticket/Invoice Email
    const customerSubject = `${venueName} - Event Payment Confirmation & Invoice #${invoiceNumber}`;
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
              <h2>Event Ticket</h2>
              <div class="ticket-box">
                <h3>${eventType || 'Event'}</h3>
                <div class="info-row">
                  <span class="info-label">Date:</span>
                  <span class="info-value">${formattedEventDate}</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Location:</span>
                  <span class="info-value">${venueAddress}</span>
                </div>
              </div>
            </div>

            <div class="invoice-section">
              <h2>Payment Invoice</h2>
              <div class="payment-summary">
                ${customerName ? `
                <div class="info-row">
                  <span class="info-label">Customer Name:</span>
                  <span class="info-value">${customerName}</span>
                </div>
                ` : ''}
                <div class="info-row">
                  <span class="info-label">Customer Email:</span>
                  <span class="info-value">${customerEmail}</span>
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
                <li>Please arrive on time for the event</li>
                <li>This email serves as your confirmation ticket</li>
                <li>If you need to make changes, please contact us at least 24 hours in advance</li>
                <li>Keep this email for your records</li>
              </ul>
            </div>

            <p style="margin-top: 30px;">Thank you for choosing ${venueName}. We look forward to seeing you at the event!</p>
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
    const managerSubject = `💰 New Event Payment - ${eventType || 'Event'} - ${formattedEventDate}`;
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
            <h1>💰 New Event Payment</h1>
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
              ${customerName ? `
              <div class="info-row">
                <span class="info-label">Name:</span>
                <span class="info-value">${customerName}</span>
              </div>
              ` : ''}
              <div class="info-row">
                <span class="info-label">Email:</span>
                <span class="info-value"><a href="mailto:${customerEmail}">${customerEmail}</a></span>
              </div>
            </div>

            <div class="info-section">
              <h3>Event Details</h3>
              <div class="info-row">
                <span class="info-label">Event Type:</span>
                <span class="info-value">${eventType || 'Event'}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Event Date:</span>
                <span class="info-value">${formattedEventDate}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Venue:</span>
                <span class="info-value">${venueName}</span>
              </div>
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
              <strong>Action Required:</strong> Please prepare for this event and ensure all details are noted.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send customer email - same pattern as reservation emails
    let customerInfo = null;
    if (customerEmail && customerEmail.trim() && customerEmail.includes('@')) {
      console.log('📤 Attempting to send customer email to:', customerEmail);
      try {
        customerInfo = await transporter.sendMail({
          from,
          to: customerEmail,
          subject: customerSubject,
          html: customerHtml
        });
        console.log('✅ Event payment confirmation email sent to customer:', customerInfo.messageId);
      } catch (customerEmailError) {
        console.error('❌ Failed to send customer email:', customerEmailError);
        console.error('❌ Customer email error details:', {
          message: customerEmailError.message,
          code: customerEmailError.code,
          response: customerEmailError.response
        });
        // Continue to send manager email even if customer email fails (same as reservation emails)
      }
    } else {
      console.warn('⚠️ No valid customer email available - skipping customer email');
      console.warn('⚠️ Customer email value:', customerEmail);
    }

    // Send manager email - always send (same as reservation emails)
    console.log('📤 Attempting to send manager email to:', managerEmail);
    let managerInfo = null;
    try {
      managerInfo = await transporter.sendMail({
        from,
        to: managerEmail,
        subject: managerSubject,
        html: managerHtml
      });
      console.log('✅ Event payment notification email sent to manager:', managerInfo.messageId);
    } catch (managerEmailError) {
      console.error('❌ Failed to send manager email:', managerEmailError);
      console.error('❌ Manager email error details:', {
        message: managerEmailError.message,
        code: managerEmailError.code,
        response: managerEmailError.response
      });
      // Throw error so it's caught by the outer try-catch
      throw managerEmailError;
    }

    console.log('✅ All emails sent successfully');
    return { customerInfo, managerInfo };
  } catch (error) {
    console.error('Error sending event payment confirmation emails:', error);
    logger.error('Failed to send event payment confirmation emails', {
      sessionId: session?.id || 'unknown',
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
      // Note: reservation_id column removed from payments table
      const amountPaid = session.amount_total / 100; // Convert from pence/cents to pounds/dollars

      // Get event details from mapping if eventId exists
      const eventId = session.metadata?.eventId || '';
      const eventDetails = eventId ? eventMapping[eventId] : null;
      const eventType = eventDetails ? eventDetails.title : (eventId ? 'event' : null);
      const eventDate = eventDetails?.date || null;

      const paymentIntentId = session.payment_intent || session.id; // Use session.id as fallback

      // Get customer email - prioritize metadata (from client form) over session.customer_email
      // The metadata contains the email from our form, which is what the user wants to use
      const customerEmail = session.metadata?.customerEmail || session.customer_email || '';
      console.log('📧 Email extraction from session:', {
        session_customer_email: session.customer_email,
        metadata_customerEmail: session.metadata?.customerEmail,
        final_email: customerEmail,
        note: 'Using metadata email (from client form) as primary source'
      });
      // Get customer name from metadata (may be empty for events)
      const customerName = session.metadata?.customerName || '';

      // Save payment to database using helper function
      console.log('💾 Attempting to save payment to database with data:', {
        paymentIntentId,
        amountPaid,
        currency: session.currency || 'gbp',
        eventType,
        eventDate,
        customerEmail,
        customerName,
        stripeSessionId: session.id
      });

      try {
        const saveResult = await savePaymentToDatabase({
          paymentIntentId,
          amountPaid,
          currency: session.currency || 'gbp',
          eventType,
          eventDate,
          customerEmail,
          customerName,
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
          paymentIntentId: paymentIntentId
        });
        logger.error('Failed to save payment to database (payment-success)', {
          sessionId: session.id,
          error: paymentError.message,
          code: paymentError.code,
          stack: paymentError.stack,
          timestamp: new Date().toISOString()
        });
        // Continue anyway to send emails, but log the error
      }

      // Note: Email sending is now handled by the client-side JavaScript calling /api/send-payment-email
      // This follows the same pattern as reservations for better error handling and user feedback
      console.log('✅ Payment saved successfully - email will be sent via API endpoint');

      // Log successful payment
      logger.info('Payment succeeded via Checkout', {
        sessionId: session.id,
        paymentIntentId: session.payment_intent,
        amount: session.amount_total / 100,
        currency: session.currency,
        customerEmail: session.customer_email,
        eventId: session.metadata?.eventId || null,
        timestamp: new Date().toISOString()
      });

      // Send success page
      const baseUrl = req.protocol + '://' + req.get('host');
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Payment Successful - XIX Restaurant</title>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <link rel="stylesheet" href="${baseUrl}/base.css">
          <link rel="stylesheet" href="${baseUrl}/navigation.css">
          <link rel="stylesheet" href="${baseUrl}/footer.css">
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
            <p class="success-details" id="status-message">Processing your confirmation email...</p>
            <a href="/xix" class="btn-primary" id="home-button" style="display: none;">Return to Home</a>
          </div>
          <script>
            // Same pattern as reservations - call API endpoint to send emails
            async function sendPaymentEmail() {
              const urlParams = new URLSearchParams(window.location.search);
              const sessionId = urlParams.get('session_id');
              
              if (!sessionId) {
                document.getElementById('status-message').textContent = 'Payment successful, but session ID is missing.';
                document.getElementById('home-button').style.display = 'inline-block';
                return;
              }

              try {
                console.log('📧 Calling /api/send-payment-email with session_id:', sessionId);
                
                const response = await fetch('/api/send-payment-email', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                  },
                  body: JSON.stringify({ session_id: sessionId }),
                  credentials: 'same-origin'
                });

                console.log('📧 Response status:', response.status);
                console.log('📧 Response ok:', response.ok);

                if (!response.ok) {
                  const errorData = await response.json().catch(() => ({}));
                  console.error('❌ API Error:', errorData);
                  const statusText = 'HTTP error! status: ' + response.status;
                  throw new Error(errorData.error || statusText);
                }

                const data = await response.json();
                console.log('✅ Payment email sent successfully:', data);
                
                document.getElementById('status-message').textContent = 'Your reservation has been confirmed. You will receive a confirmation email shortly.';
                document.getElementById('home-button').style.display = 'inline-block';
              } catch (error) {
                console.error('❌ Failed to send payment email:', error);
                document.getElementById('status-message').textContent = 'Payment successful! If you do not receive a confirmation email, please contact us.';
                document.getElementById('home-button').style.display = 'inline-block';
              }
            }

            // Call the function when page loads
            sendPaymentEmail();
          </script>
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

    // Even if there's an error, check if payment was successful via webhook
    // The webhook may have already saved the payment, so show success page instead of error
    // This prevents showing error when payment actually succeeded
    const { session_id } = req.query;
    if (session_id) {
      try {
        const session = await stripe.checkout.sessions.retrieve(session_id);
        if (session.payment_status === 'paid') {
          // Payment is actually paid, show success page even if there was an error
          console.log('⚠️ Error occurred but payment is paid - showing success page');
          const baseUrl = req.protocol + '://' + req.get('host');
          return res.send(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>Payment Successful - XIX Restaurant</title>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <link rel="stylesheet" href="${baseUrl}/base.css">
              <link rel="stylesheet" href="${baseUrl}/navigation.css">
              <link rel="stylesheet" href="${baseUrl}/footer.css">
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
                  color: #666;
                  margin-bottom: 2rem;
                }
                .btn-primary {
                  display: inline-block;
                  padding: 0.75rem 2rem;
                  background: var(--gold);
                  color: white;
                  text-decoration: none;
                  border-radius: 8px;
                  font-weight: 600;
                  transition: background 0.3s ease;
                }
                .btn-primary:hover {
                  background: #8B6F1A;
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
                <p class="success-details" id="status-message">Processing your confirmation email...</p>
                <a href="/xix" class="btn-primary" id="home-button" style="display: none;">Return to Home</a>
              </div>
              <script>
                // Same pattern as reservations - call API endpoint to send emails
                async function sendPaymentEmail() {
                  const urlParams = new URLSearchParams(window.location.search);
                  const sessionId = urlParams.get('session_id');
                  
                  if (!sessionId) {
                    document.getElementById('status-message').textContent = 'Payment successful, but session ID is missing.';
                    document.getElementById('home-button').style.display = 'inline-block';
                    return;
                  }

                  try {
                    console.log('📧 Calling /api/send-payment-email with session_id:', sessionId);
                    
                    const response = await fetch('/api/send-payment-email', {
                      method: 'POST',
                      headers: {
                        'Content-Type': 'application/json',
                      },
                      body: JSON.stringify({ session_id: sessionId }),
                      credentials: 'same-origin'
                    });

                    console.log('📧 Response status:', response.status);
                    console.log('📧 Response ok:', response.ok);

                    if (!response.ok) {
                      const errorData = await response.json().catch(() => ({}));
                      console.error('❌ API Error:', errorData);
                      const statusText = 'HTTP error! status: ' + response.status;
                      throw new Error(errorData.error || statusText);
                    }

                    const data = await response.json();
                    console.log('✅ Payment email sent successfully:', data);
                    
                    document.getElementById('status-message').textContent = 'Your reservation has been confirmed. You will receive a confirmation email shortly.';
                    document.getElementById('home-button').style.display = 'inline-block';
                  } catch (error) {
                    console.error('❌ Failed to send payment email:', error);
                    document.getElementById('status-message').textContent = 'Payment successful! If you do not receive a confirmation email, please contact us.';
                    document.getElementById('home-button').style.display = 'inline-block';
                  }
                }

                // Call the function when page loads
                sendPaymentEmail();
              </script>
            </body>
            </html>
          `);
        }
      } catch (retrieveError) {
        console.error('Could not retrieve session to verify payment:', retrieveError);
      }
    }

    // Only show error if payment is not confirmed as paid
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
        console.log('🔵 Webhook: Payment intent succeeded:', paymentIntent.id);
        console.log('Payment Intent details:', {
          id: paymentIntent.id,
          amount: paymentIntent.amount,
          currency: paymentIntent.currency,
          metadata: paymentIntent.metadata
        });

        // When using Stripe Checkout, payment_intent.succeeded doesn't include session metadata
        // We'll use payment intent data directly - the checkout.session.completed event will handle the full save
        // But we'll still save this as a backup in case checkout.session.completed doesn't fire

        // Extract data from payment intent
        // Note: reservation_id column removed from payments table
        const amountPaid = paymentIntent.amount / 100;

        // Get event details from mapping if eventId exists
        const eventId = paymentIntent.metadata?.eventId || '';
        const eventDetails = eventId ? eventMapping[eventId] : null;
        const eventType = eventDetails ? eventDetails.title : (eventId ? 'event' : null);
        const eventDate = eventDetails?.date || null;

        const customerEmail = paymentIntent.metadata?.customerEmail || paymentIntent.receipt_email || '';
        const customerName = paymentIntent.metadata?.customerName || '';
        const stripeSessionId = null; // We don't have session ID from payment intent alone

        console.log('📋 Payment Intent metadata:', paymentIntent.metadata);
        console.log('📋 Payment Intent receipt_email:', paymentIntent.receipt_email);

        console.log('💾 Webhook (Payment Intent): Attempting to save payment with data:', {
          paymentIntentId: paymentIntent.id,
          amountPaid,
          currency: paymentIntent.currency || 'gbp',
          eventType,
          customerEmail,
          customerName,
          stripeSessionId
        });

        // Save payment to database (even without session data - this is a backup)
        // The checkout.session.completed event should have all the data, but this ensures we save something
        try {
          const saveResult = await savePaymentToDatabase({
            paymentIntentId: paymentIntent.id,
            amountPaid,
            currency: paymentIntent.currency || 'gbp',
            eventType,
            eventDate,
            customerEmail,
            customerName,
            stripeSessionId
          });
          console.log('✅ Webhook (Payment Intent): Payment saved successfully:', saveResult);
        } catch (paymentError) {
          console.error('❌ Webhook (Payment Intent): Failed to save payment:', paymentError);
          console.error('❌ Error details:', {
            message: paymentError.message,
            code: paymentError.code,
            stack: paymentError.stack
          });
          logger.error('Failed to save payment in webhook (payment_intent.succeeded)', {
            paymentIntentId: paymentIntent.id,
            error: paymentError.message,
            code: paymentError.code,
            timestamp: new Date().toISOString()
          });
          // Don't throw - let the webhook return 200 so Stripe doesn't retry
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

        // Note: reservation_id column removed from payments table
        const amountPaid = session.amount_total / 100;

        // Get event details from mapping if eventId exists
        const eventId = session.metadata?.eventId || '';
        const eventDetails = eventId ? eventMapping[eventId] : null;
        const eventType = eventDetails ? eventDetails.title : (eventId ? 'event' : null);
        const eventDate = eventDetails?.date || null;

        const paymentIntentId = session.payment_intent || session.id;

        // Get customer email - prioritize metadata (from client form) over session.customer_email
        // The metadata contains the email from our form, which is what the user wants to use
        const customerEmail = session.metadata?.customerEmail || session.customer_email || '';
        console.log('📧 Email extraction from webhook session:', {
          session_customer_email: session.customer_email,
          metadata_customerEmail: session.metadata?.customerEmail,
          final_email: customerEmail,
          note: 'Using metadata email (from client form) as primary source'
        });
        // Get customer name from metadata (may be empty for events)
        const customerName = session.metadata?.customerName || '';

        console.log('💾 Webhook: Attempting to save payment with data:', {
          paymentIntentId,
          amountPaid,
          currency: session.currency || 'gbp',
          eventType,
          eventDate,
          customerEmail,
          customerName,
          stripeSessionId: session.id
        });

        // Save payment to database
        try {
          const saveResult = await savePaymentToDatabase({
            paymentIntentId,
            amountPaid,
            currency: session.currency || 'gbp',
            eventType,
            eventDate,
            customerEmail,
            customerName,
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

        // For event payments, no reservation is needed
        // Send payment confirmation emails for event payments
        console.log('📧 Webhook: Checking email sending conditions:', {
          hasCustomerEmail: !!customerEmail,
          customerEmail: customerEmail,
          eventType,
          eventDate
        });

        if (customerEmail) {
          try {
            console.log('📧 Webhook: Calling sendEventPaymentConfirmationEmails...');
            const emailResult = await sendEventPaymentConfirmationEmails(session, eventType, eventDate, customerEmail, customerName);
            console.log('✅ Webhook: Payment confirmation emails sent successfully:', emailResult);
          } catch (emailError) {
            console.error('❌ Webhook: Failed to send payment confirmation emails:', emailError);
            console.error('❌ Webhook: Email error stack:', emailError.stack);
            logger.error('Failed to send payment confirmation emails (webhook)', {
              sessionId: session.id,
              error: emailError.message,
              stack: emailError.stack,
              timestamp: new Date().toISOString()
            });
            // Continue anyway - payment is saved
          }
        } else {
          console.warn('⚠️ Webhook: No customer email available - skipping email send');
          console.warn('⚠️ Webhook: Email extraction details:', {
            session_customer_email: session.customer_email,
            metadata_customerEmail: session.metadata?.customerEmail
          });
        }

        console.log('✓ Webhook: Payment saved successfully');

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
    console.log('✅ Webhook processed successfully, returning 200 OK to Stripe');
    res.json({ received: true });
  } catch (error) {
    console.error('❌ CRITICAL ERROR processing webhook:', error);
    console.error('Error stack:', error.stack);
    logger.error('Webhook processing error', {
      eventType: event?.type || 'unknown',
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    // Still return success to prevent retries, but log the error
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

// Delete All Reservations Endpoint (Clear all reservations)
app.delete('/api/reservations/clear-all', (req, res) => {
  const secretKey = req.query.key;
  const expectedKey = process.env.ADMIN_SECRET_KEY;

  if (secretKey !== expectedKey) {
    return res.status(403).json({ error: 'Unauthorized access' });
  }

  // Get all reservations with Google Calendar event IDs before deleting
  db.all('SELECT id, google_calendar_event_id FROM reservations WHERE google_calendar_event_id IS NOT NULL', [], (err, reservations) => {
    if (err) {
      console.error('Error fetching reservations:', err);
      return res.status(500).json({ error: 'Failed to fetch reservations: ' + err.message });
    }

    const calendarEventIds = reservations.map(r => r.google_calendar_event_id).filter(Boolean);

    // Delete all reservations from database
    db.run('DELETE FROM reservations', [], function (deleteErr) {
      if (deleteErr) {
        console.error('Error deleting all reservations:', deleteErr);
        return res.status(500).json({ error: 'Failed to delete reservations: ' + deleteErr.message });
      }

      const deletedCount = this.changes;
      console.log(`✅ Deleted ${deletedCount} reservations from database`);

      // Delete Google Calendar events if calendar is configured
      if (calendarEventIds.length > 0 && calendar && process.env.GOOGLE_CALENDAR_ID) {
        const calendarId = process.env.GOOGLE_CALENDAR_ID;
        const deletePromises = calendarEventIds.map(eventId => {
          return calendar.events.delete({
            calendarId: calendarId,
            eventId: eventId
          }).catch((err) => {
            console.error(`⚠️ Error deleting Google Calendar event ${eventId}:`, err.message);
            return null; // Continue even if one fails
          });
        });

        Promise.all(deletePromises).then(() => {
          console.log(`✅ Deleted ${calendarEventIds.length} Google Calendar events`);
          res.json({
            success: true,
            message: `Deleted ${deletedCount} reservations and ${calendarEventIds.length} Google Calendar events`
          });
        });
      } else {
        res.json({
          success: true,
          message: `Deleted ${deletedCount} reservations`
        });
      }
    });
  });
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