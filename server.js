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
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Additional Security Imports
const ExpressBrute = require('express-brute');
const winston = require('winston');
const morgan = require('morgan');
const csrf = require('csurf');
const slowDown = require('express-slow-down');

dotenv.config();

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
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
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
  max: process.env.NODE_ENV === 'production' ? 20 : 100, // Very high limits
  message: {
    error: 'Too many reservation attempts. Please try again later.'
  }
});

// Mobile-specific rate limiting (more restrictive for mobile devices)
const mobileLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 50 : 200, // Lower limits for mobile
  message: {
    error: 'Too many requests from mobile device. Please try again later.'
  },
  skip: (req) => {
    const userAgent = req.get('User-Agent') || '';
    return !/Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
  }
});

// Request Size Limits
app.use(express.json({ limit: '10mb' })); // Limit JSON payloads to 10MB
app.use(express.urlencoded({ limit: '10mb', extended: true })); // Limit URL-encoded payloads

// DDoS Protection - Slow Down (More lenient for restaurant website)
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 200, // Allow 200 requests per 15 minutes (increased from 50)
  delayMs: () => 200, // Add 200ms delay per request above delayAfter (reduced from 500ms)
  maxDelayMs: 5000, // Maximum delay of 5 seconds (reduced from 20 seconds)
  // Removed onLimitReached as it's deprecated in express-rate-limit v7
});

// DDoS Protection - Brute Force Protection
const ExpressBruteStore = ExpressBrute.MemoryStore;
const store = new ExpressBruteStore();

const bruteForce = new ExpressBrute(store, {
  freeRetries: 20, // Number of free attempts (increased from 5)
  minWait: 2 * 60 * 1000, // 2 minutes (reduced from 5 minutes)
  maxWait: 10 * 60 * 1000, // 10 minutes (reduced from 15 minutes)
  lifetime: 12 * 60 * 60 * 1000, // 12 hours (reduced from 24 hours)
  onTooManyRequests: (req, res, next, nextValidRequestDate) => {
    logger.error('Brute force attack detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url,
      nextValidRequestDate: nextValidRequestDate,
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      error: 'Too many requests. Please try again later.',
      retryAfter: Math.round((nextValidRequestDate.getTime() - Date.now()) / 1000)
    });
  }
});

// CSRF Protection - DISABLED for mobile compatibility and dev tunnels
// const csrfProtection = csrf({
//   cookie: {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === 'production',
//     sameSite: 'strict'
//   },
//   ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
// });

// Apply security middleware
app.use(limiter);
app.use(mobileLimiter);
app.use('/api/reservations', reservationLimiter);
// Temporarily disabled DDoS protection for dev tunnel compatibility
// app.use(speedLimiter);
// app.use(bruteForce.prevent);

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

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

// app.get('/landing', (req, res) => {
//   console.log('LANDING ROUTE HIT - Serving landing.html');
//   res.sendFile(__dirname + '/landing.html');
// });

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

app.get('/payment', (req, res) => {
  res.sendFile(__dirname + '/payment.html');
});

// Stripe configuration endpoint
app.get('/api/stripe-config', (req, res) => {
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY
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
  const inputDate = new Date(date);
  const today = new Date();
  today.setHours(0, 0, 0, 0); // Reset time to start of day for accurate comparison

  return inputDate >= today;
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

  // Add payment-related columns
  db.run(`ALTER TABLE reservations ADD COLUMN payment_status TEXT DEFAULT 'pending'`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding payment_status column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN payment_intent_id TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding payment_intent_id column:', err.message);
    }
  });

  db.run(`ALTER TABLE reservations ADD COLUMN amount_paid DECIMAL(10,2)`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding amount_paid column:', err.message);
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
  const expectedKey = process.env.ADMIN_SECRET_KEY || 'xix-admin-2024';

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
  const expectedKey = process.env.ADMIN_SECRET_KEY || 'xix-admin-2024';

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
  const dayOfWeek = new Date(date).toLocaleDateString('en-US', { weekday: 'long' });

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

// CSRF token endpoint - DISABLED for mobile compatibility
// app.get('/api/csrf-token', csrfProtection, (req, res) => {
//   res.json({ csrfToken: req.csrfToken() });
// });

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

    const date = new Date(sanitizedReservation.date).toLocaleDateString('en-US', {
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

  // Get all reservations using the same logic as the reservations endpoint
  db.all('SELECT * FROM reservations ORDER BY created_at DESC', (err, allReservations) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }

    // Filter by date and venue in JavaScript
    const reservations = allReservations.filter(r =>
      r.date === date && r.venue === detectedVenue
    );

    // Get booked times - filter out null values
    const bookedTimes = reservations
      .map(r => r.time)
      .filter(time => time !== null && time !== undefined);

    // Filter out booked times
    const availableTimes = allTimeSlots.filter(time => !bookedTimes.includes(time));

    res.json({
      date: date,
      venue: detectedVenue,
      availableTimes: availableTimes,
      bookedTimes: bookedTimes,
      totalReservations: reservations.length
    });
  });
});

// Stripe Payment Gateway Integration
app.post('/api/create-payment', async (req, res) => {
  try {
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

// Webhook endpoint for Stripe events
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    logger.warn('Invalid webhook signature', {
      error: err.message,
      timestamp: new Date().toISOString()
    });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object;
      console.log('Payment succeeded:', paymentIntent.id);

      // Update reservation status in database
      if (paymentIntent.metadata.reservationId) {
        db.run(
          'UPDATE reservations SET payment_status = "paid", payment_intent_id = ? WHERE id = ?',
          [paymentIntent.id, paymentIntent.metadata.reservationId],
          (err) => {
            if (err) {
              console.error('Error updating reservation payment status:', err);
            } else {
              console.log('Reservation payment status updated');
            }
          }
        );
      }

      // Log successful payment
      logger.info('Payment succeeded', {
        paymentIntentId: paymentIntent.id,
        amount: paymentIntent.amount,
        currency: paymentIntent.currency,
        customerEmail: paymentIntent.metadata.customerEmail,
        reservationId: paymentIntent.metadata.reservationId,
        timestamp: new Date().toISOString()
      });
      break;

    case 'payment_intent.payment_failed':
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

    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({ received: true });
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
  const expectedKey = process.env.ADMIN_SECRET_KEY || 'xix-admin-2024';

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

// Serve static files (HTML, CSS, JS, images) - AFTER all explicit routes
// Disable default index.html serving to allow our explicit routes to work
app.use(express.static('.', { index: false }));

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
  console.log(`View reservations: http://localhost:${port}/api/reservations`);
  console.log(`Admin dashboard: http://localhost:${port}/admin?key=xix-admin-2024`);
});