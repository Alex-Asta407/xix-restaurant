# SQLite Database Management on cPanel

## ✅ Good News: Database Updates Automatically!

The database schema is **automatically updated** when the server starts. The code includes `ALTER TABLE` statements that add missing columns if they don't exist.

### How It Works:

When `server.js` starts, it automatically:
1. Creates the `reservations` table if it doesn't exist
2. Adds missing columns (payment_status, payment_intent_id, etc.) if they don't exist
3. Handles errors gracefully (won't crash if columns already exist)

**You don't need to manually update the database!** Just restart the Node.js app on cPanel.

---

## 📍 SQLite Database Location on cPanel

### Where is the database file?

The database file is located in the **same directory as `server.js`**:

```
/home/xixlzmqv/xixapp/reservations.db
```

Or if you're using Git repository:
```
/home/xixlzmqv/repositories/xix-restaurant/reservations.db
```

### Important Notes:

1. **The database file is created automatically** when the server starts (if it doesn't exist)
2. **The file must be in the same directory as `server.js`**
3. **The app directory must have write permissions** for SQLite to work

---

## 🔧 Managing SQLite Database on cPanel

### Option 1: Via cPanel File Manager

1. **Login to cPanel**
2. **Open File Manager**
3. **Navigate to your app directory** (e.g., `xixapp` or `repositories/xix-restaurant`)
4. **Find `reservations.db`** file
5. **Right-click → Download** to backup
6. **Right-click → Edit** to view (but don't edit directly - use a SQLite tool)

### Option 2: Via SSH/Terminal

```bash
# Navigate to your app directory
cd /home/xixlzmqv/xixapp

# Check if database exists
ls -la reservations.db

# View database (if sqlite3 is installed)
sqlite3 reservations.db

# Inside sqlite3:
.tables                          # List all tables
.schema reservations             # View table structure
SELECT * FROM reservations;      # View all reservations
.quit                            # Exit sqlite3

# Backup database
cp reservations.db reservations.db.backup

# Check database size
ls -lh reservations.db
```

### Option 3: Via cPanel Terminal

1. **Login to cPanel**
2. **Open Terminal** (or SSH Access)
3. **Navigate to app directory**
4. **Use commands above**

---

## 🔄 Database Schema Updates

### Current Schema (Automatically Applied):

The following columns are automatically added when the server starts:

```sql
-- Basic columns (always present)
id, name, email, phone, date, time, guests
table_preference, occasion, special_requests
venue, event_type, menu_preference, entertainment
created_at

-- Email tracking (automatically added)
email_sent_to_customer
email_sent_to_manager

-- Payment tracking (automatically added)
payment_status          -- 'pending' or 'paid'
payment_intent_id       -- Stripe payment intent ID
amount_paid             -- Amount paid (optional)
```

### How to Verify Schema:

**Method 1: Check Server Logs**
When the server starts, check logs for:
- "Connected to SQLite database"
- Any "Error adding column" messages (should be none if everything is OK)

**Method 2: Use SQLite CLI**
```bash
sqlite3 reservations.db
.schema reservations
```

**Method 3: Use Admin Dashboard**
Visit: `https://yourdomain.com/admin?key=YOUR_ADMIN_KEY`
Or use the database viewer if available.

---

## 🚀 Deployment Steps

### Step 1: Upload Files to cPanel

1. Upload all files to your app directory
2. Make sure `server.js` is in the root of the app directory
3. The database file will be created automatically in the same directory

### Step 2: Set Permissions

Make sure the app directory has write permissions:

```bash
# Via SSH
cd /home/xixlzmqv/xixapp
chmod 755 .
chmod 644 server.js
# Database file will be created with correct permissions automatically
```

### Step 3: Restart Node.js App

1. **Login to cPanel**
2. **Go to "Setup Node.js App"**
3. **Click "Restart"** next to your app
4. **Check logs** for "Connected to SQLite database"

---

## 📊 Database Backup Strategy

### Automatic Backups (Recommended):

Create a backup script that runs daily:

```bash
#!/bin/bash
# backup-db.sh
DATE=$(date +%Y%m%d_%H%M%S)
cp /home/xixlzmqv/xixapp/reservations.db /home/xixlzmqv/backups/reservations_$DATE.db
# Keep only last 7 days
find /home/xixlzmqv/backups -name "reservations_*.db" -mtime +7 -delete
```

### Manual Backup via cPanel:

1. **File Manager** → Navigate to app directory
2. **Right-click** `reservations.db`
3. **Download** to your computer
4. **Keep backups** in a safe place

### Restore Database:

```bash
# Stop Node.js app first!
# Via SSH:
cd /home/xixlzmqv/xixapp
cp reservations.db reservations.db.old
cp /path/to/backup/reservations.db .
# Restart Node.js app
```

---

## ⚠️ Important Notes

### 1. **Database File Location**
- Must be in the **same directory as `server.js`**
- Path: `./reservations.db` (relative path)
- Full path: `/home/xixlzmqv/xixapp/reservations.db`

### 2. **Write Permissions**
- The app directory must have **write permissions**
- SQLite needs to create/modify the database file
- If you get "permission denied" errors, check directory permissions

### 3. **Database File Size**
- SQLite files can grow large over time
- Monitor file size: `ls -lh reservations.db`
- Consider archiving old reservations if needed

### 4. **Backup Regularly**
- **Database is critical** - contains all reservations
- Backup before major updates
- Keep backups in multiple locations

### 5. **Don't Edit Database Directly**
- Don't edit `reservations.db` file directly
- Use SQLite tools or admin dashboard
- Always backup before making changes

---

## 🔍 Troubleshooting

### Problem: "Error opening database"

**Solution:**
1. Check file permissions: `chmod 644 reservations.db`
2. Check directory permissions: `chmod 755 /home/xixlzmqv/xixapp`
3. Check if path is correct (database must be in same directory as server.js)

### Problem: "Database is locked"

**Solution:**
1. Make sure only one instance of the app is running
2. Check if database file is being accessed by another process
3. Restart the Node.js app

### Problem: "Column doesn't exist"

**Solution:**
1. Restart the Node.js app (schema updates run on startup)
2. Check server logs for errors
3. Manually verify schema: `sqlite3 reservations.db .schema`

### Problem: "Permission denied"

**Solution:**
```bash
# Via SSH
cd /home/xixlzmqv/xixapp
chmod 755 .
chmod 644 server.js
# Database will be created with correct permissions automatically
```

---

## 📝 Summary

✅ **Database updates automatically** - no manual SQL needed
✅ **Database file location** - same directory as `server.js`
✅ **Create on first run** - database is created automatically
✅ **Schema updates** - columns are added automatically on startup
✅ **Backup regularly** - important for data safety
✅ **Access via cPanel** - File Manager or SSH/Terminal

**You're all set!** Just restart your Node.js app on cPanel, and the database will be updated automatically.

