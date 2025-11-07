# 📊 Database Access Guide

## How to Access Your Database Online (via cPanel)

You have several options to view and manage your SQLite database remotely:

---

## Option 1: Web-Based Database Viewer (Recommended) ✅

### Access URL:
```
https://xixlondon.co.uk/database-viewer
```

### Features:
- ✅ View all reservations
- ✅ View all payments (with reservation details)
- ✅ Switch between Reservations and Payments tables
- ✅ Export data to CSV or JSON
- ✅ View raw JSON data
- ✅ Refresh data in real-time
- ✅ No password required (public access)

### How to Use:
1. Go to `https://xixlondon.co.uk/database-viewer`
2. Click **"Reservations"** or **"Payments"** to switch tables
3. Click **"Refresh"** to reload data
4. Click **"Export to CSV"** or **"Export to JSON"** to download data

---

## Option 2: Admin Dashboard (Protected)

### Access URL:
```
https://xixlondon.co.uk/admin?key=YOUR_ADMIN_SECRET_KEY
```

### Setup:
1. Add `ADMIN_SECRET_KEY` to your `.env` file:
   ```env
   ADMIN_SECRET_KEY=your-secret-key-here
   ```
2. Replace `YOUR_ADMIN_SECRET_KEY` in the URL above with your actual key
3. Access the dashboard at the URL above

### Features:
- View statistics
- View reservations
- More detailed admin interface

---

## Option 3: API Endpoints (For Programmatic Access)

### Get All Reservations:
```
GET https://xixlondon.co.uk/api/reservations
```

### Get All Payments:
```
GET https://xixlondon.co.uk/api/payments/with-reservations
```

### Get Payments (Simple):
```
GET https://xixlondon.co.uk/api/payments
```

### Get Today's Reservations (Protected):
```
GET https://xixlondon.co.uk/admin/today?key=YOUR_ADMIN_SECRET_KEY
```

### Get All Reservations (Protected):
```
GET https://xixlondon.co.uk/admin/all?key=YOUR_ADMIN_SECRET_KEY
```

---

## Option 4: cPanel File Manager (Direct Database Access)

### Steps:
1. **Login to cPanel**
2. **File Manager** → Navigate to your app directory (e.g., `xixapp/`)
3. **Right-click** on `reservations.db`
4. **Download** to your computer
5. **Open in TablePlus** or any SQLite viewer

### ⚠️ Important:
- **Don't edit the database directly** while the server is running
- **Always backup** before making changes
- **Stop the Node.js app** before editing manually

---

## Option 5: SSH/Terminal Access

### Via cPanel Terminal:
1. **cPanel** → **Terminal** (or **SSH Access**)
2. Navigate to your app directory:
   ```bash
   cd ~/xixapp
   ```
3. Use SQLite command line:
   ```bash
   sqlite3 reservations.db
   ```
4. Run SQL commands:
   ```sql
   .tables                    -- List all tables
   SELECT * FROM reservations;  -- View reservations
   SELECT * FROM payments;      -- View payments
   .exit                     -- Exit SQLite
   ```

---

## 📋 Database Tables

### 1. `reservations` Table
- Contains all reservation details
- Columns: `id`, `name`, `email`, `phone`, `date`, `time`, `guests`, `venue`, `table_preference`, `occasion`, `special_requests`, `created_at`, etc.

### 2. `payments` Table
- Contains all payment information (separate from reservations)
- Columns: `id`, `reservation_id`, `payment_intent_id`, `amount_paid`, `currency`, `payment_status`, `event_type`, `customer_email`, `customer_name`, `stripe_session_id`, `created_at`, `updated_at`

---

## 🔒 Security Notes

### Public Access:
- ✅ `database-viewer.html` - **Public** (anyone can view)
- ✅ `/api/reservations` - **Public** (anyone can access)

### Protected Access:
- 🔒 `/admin/*` - Requires `ADMIN_SECRET_KEY`
- 🔒 `/api/payments` - Currently public (consider adding authentication if needed)

### Recommendations:
1. **Keep `ADMIN_SECRET_KEY` secret** - Don't share it publicly
2. **Consider password protection** for `database-viewer.html` if needed
3. **Regular backups** - Download `reservations.db` regularly
4. **Monitor access** - Check server logs for unusual activity

---

## 🛠️ Troubleshooting

### Database Viewer Not Loading:
1. Check if Node.js app is running
2. Check browser console for errors
3. Verify the API endpoint is accessible: `https://xixlondon.co.uk/api/reservations`
4. Make sure you're accessing `/database-viewer` (not `/database-viewer.html`)

### No Data Showing:
1. Check if database file exists: `reservations.db`
2. Check if tables are created (restart Node.js app if needed)
3. Check server logs for database errors

### Export Not Working:
1. Check browser console for errors
2. Try a different browser
3. Check if data is loaded (click "Refresh" first)

---

## 📝 Quick Reference

| Task | Method | URL |
|------|--------|-----|
| View Reservations | Web Viewer | `/database-viewer` |
| View Payments | Web Viewer | `/database-viewer` → Click "Payments" |
| Export Data | Web Viewer | Click "Export to CSV/JSON" |
| API Access | API | `/api/reservations` or `/api/payments` |
| Download DB | File Manager | Download `reservations.db` |
| SQL Queries | SSH | `sqlite3 reservations.db` |

---

**You're all set!** The easiest way is to use the web-based database viewer at `https://xixlondon.co.uk/database-viewer`.

