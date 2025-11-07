# Database Migration Guide: Payments Table

## ✅ Code Status: CORRECT

The code has been updated correctly:
- ✅ `payments` table creation code is in place (lines 503-523)
- ✅ Payment columns removed from `reservations` table creation
- ✅ All payment operations now use `payments` table
- ✅ `event_type` column included in `payments` table

## 🔍 Why You Still See Old Columns

### The Old Columns Are Still There Because:

1. **SQLite doesn't auto-remove columns** - Once a column exists, it stays there
2. **We only removed the code that ADDS them** - We didn't remove existing columns
3. **The old columns are harmless** - The code doesn't use them anymore, so they won't cause issues

### What You're Seeing:

```
reservations table (in your DB viewer):
- payment_status ✅ (old column - still exists, but code doesn't use it)
- payment_intent_id ✅ (old column - still exists, but code doesn't use it)
- amount_paid ✅ (old column - still exists, but code doesn't use it)
```

## 🚀 What Happens When You Restart Server

### Step 1: Server Starts
The code will:
1. ✅ Create `payments` table (if it doesn't exist)
2. ✅ Add `event_type` column to `payments` table (if it doesn't exist)
3. ✅ Create unique index on `payment_intent_id`

### Step 2: New Payments
- ✅ All new payments will be saved to `payments` table
- ✅ Old columns in `reservations` will remain empty (not used)

## 📋 To Verify Everything Works

### Option 1: Restart Your Local Server

1. **Stop your local server** (if running)
2. **Start it again**: `node server.js`
3. **Check logs** for:
   - "Connected to SQLite database"
   - "Payments table created/verified"
4. **Open DB Browser** and refresh:
   - You should see `payments` table in the list
   - Old columns in `reservations` will still be there (that's OK)

### Option 2: Check Database After Restart

In DB Browser for SQLite:
1. **Refresh** the database view
2. **Look for `payments` table** in the left panel
3. **Verify `payments` table structure**:
   - `id`
   - `reservation_id`
   - `payment_intent_id`
   - `amount_paid`
   - `currency`
   - `payment_status`
   - `event_type` ✅
   - `customer_email`
   - `customer_name`
   - `stripe_session_id`
   - `created_at`
   - `updated_at`

## 🧹 Optional: Remove Old Columns (Not Required)

If you want to clean up the `reservations` table and remove the old payment columns:

### Method 1: Using DB Browser for SQLite

1. **Open DB Browser**
2. **Go to "Execute SQL" tab**
3. **Run these commands** (one at a time):

```sql
-- Create new table without payment columns
CREATE TABLE reservations_new (
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
);

-- Copy data (excluding payment columns)
INSERT INTO reservations_new 
SELECT id, name, email, phone, date, time, guests, table_preference, 
       occasion, special_requests, venue, event_type, menu_preference, 
       entertainment, email_sent_to_customer, email_sent_to_manager, created_at
FROM reservations;

-- Drop old table
DROP TABLE reservations;

-- Rename new table
ALTER TABLE reservations_new RENAME TO reservations;
```

### Method 2: Leave Them (Recommended)

**Actually, you can just leave them!** They won't cause any problems:
- ✅ Code doesn't use them anymore
- ✅ They take minimal space
- ✅ No performance impact
- ✅ Safer to leave them than risk data loss

## ✅ Summary

**Current Status:**
- ✅ Code is correct - creates `payments` table
- ✅ Code doesn't use old payment columns anymore
- ⚠️ Old columns still exist in database (harmless)
- ⚠️ `payments` table will be created when server restarts

**What You Need to Do:**
1. **Restart your server** (local or production)
2. **Check that `payments` table is created**
3. **Old columns can stay** (they're harmless)

**The database will update automatically when you restart the server!**

