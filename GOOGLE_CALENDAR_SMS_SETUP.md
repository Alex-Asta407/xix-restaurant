# Google Calendar & SMS Integration Setup Guide

## 📋 Overview

This guide explains how to set up:
1. **Google Calendar Sync** - Two-way sync between your Google Calendar and database
2. **Booking Confirmation System** - 3-hour confirmation deadline with reminders
3. **SMS Reminders** (Optional) - SMS notifications via Twilio

---

## 🔵 Part 1: Google Cloud Setup (FREE)

### Why Google Cloud?
- **FREE** for basic API usage (Calendar API has generous free tier)
- Required to access Google Calendar API
- Takes ~10 minutes to set up

### Step-by-Step Setup:

1. **Go to Google Cloud Console**
   - Visit: https://console.cloud.google.com/
   - Sign in with: `akonstantinov582@gmail.com`

2. **Create a New Project**
   - Click "Select a project" → "New Project"
   - Name: "XIX Restaurant Calendar"
   - Click "Create"

3. **Enable Google Calendar API**
   - Go to "APIs & Services" → "Library"
   - Search: "Google Calendar API"
   - Click "Enable"

4. **Create Service Account** (Recommended for server-to-server)
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "Service Account"
   - Name: "xix-calendar-sync"
   - Click "Create and Continue"
   - Skip role assignment → "Done"

5. **Create Key for Service Account**
   - Click on the service account you just created
   - Go to "Keys" tab → "Add Key" → "Create new key"
   - Choose "JSON" → Download the file
   - **Save this file as `google-calendar-credentials.json`** in your project root
   - ⚠️ **DO NOT commit this file to GitHub** (add to `.gitignore`)

6. **Share Calendar with Service Account**
   - Open Google Calendar (https://calendar.google.com)
   - Click the ⚙️ Settings icon (top right) → "Settings"
   - In the **left sidebar**, find **"Settings for my calendars"** section
   - **Click on your main calendar** (`akonstantinov582@gmail.com`) - NOT "General" settings
   - In the **right panel**, you'll see calendar-specific settings for `akonstantinov582@gmail.com`
   - **Scroll down** past all these sections:
     - Notification settings
     - View options  
     - Show events from Gmail
     - Keyboard shortcuts
     - Offline
   - Keep scrolling until you see **"Share with specific people"** section (it's usually near the bottom)
   - Click **"Add people"** or the **"+"** button in that section
   - Paste this email address: `xix-calendar-sync@xix-restaurant-calendar.iam.gserviceaccount.com`
   - Set permission dropdown to **"Make changes to events"** (or "Editor")
   - Click **"Send"** or **"Add"**
   - ✅ You should see the service account email appear in the list with "Make changes to events" permission
   
   **Note:** If you don't see "Share with specific people", make sure you clicked on the calendar name (`akonstantinov582@gmail.com`) in the left sidebar, NOT "General" or any other option.

### Environment Variables to Add:
```env
GOOGLE_CALENDAR_ID=akonstantinov582@gmail.com
GOOGLE_CALENDAR_CREDENTIALS_PATH=./google-calendar-credentials.json
```

---

## 📱 Part 2: SMS Setup (Optional - Costs Money)

### Why Twilio?
- Most popular SMS service
- Easy integration
- Pay per SMS (~$0.0075 per message in UK)

### Cost Estimate:
- **100 SMS/month**: ~$0.75/month
- **500 SMS/month**: ~$3.75/month
- **1000 SMS/month**: ~$7.50/month

### Step-by-Step Setup:

1. **Sign up for Twilio**
   - Visit: https://www.twilio.com/try-twilio
   - Sign up with your email
   - Verify phone number

2. **Get Credentials**
   - Dashboard → "Account" → "API Keys & Tokens"
   - Copy:
     - Account SID
     - Auth Token
     - Phone Number (Twilio will assign you one)

3. **Environment Variables to Add:**
```env
TWILIO_ACCOUNT_SID=your_account_sid_here
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_PHONE_NUMBER=+1234567890
ENABLE_SMS_REMINDERS=true  # Set to false to disable SMS
```

---

## 🗄️ Database Changes

### New Columns Added to `reservations` table:
- `assigned_table` - Actual table number (e.g., "Table 1", "Table 2")
- `end_time` - Calculated end time (start + 2 hours, adjustable)
- `google_calendar_event_id` - Links DB record to Google Calendar event
- `confirmation_status` - 'pending', 'confirmed', 'cancelled'
- `confirmation_deadline` - DateTime when confirmation expires (3 hours before reservation)
- `confirmation_token` - Unique token for confirmation link
- `confirmed_at` - DateTime when customer confirmed
- `last_synced_at` - Last sync time with Google Calendar

### New Table: `tables`
- Stores 22 tables with capacity (2-6 people)
- Tracks table availability

---

## 🔄 How It Works

### Booking Flow:
1. Customer makes reservation → Assigned to best available table
2. Reservation saved to DB → Event created in Google Calendar
3. Confirmation email sent with link
4. **4-5 hours before**: Reminder email (and SMS if enabled)
5. **3 hours before**: Deadline - if not confirmed, auto-cancelled
6. Manager can extend time in Google Calendar → DB updates automatically

### Google Calendar Sync:
- **Every 10 minutes**: Server checks Google Calendar for changes
- If manager extends booking → Updates DB `end_time`
- Checks for conflicts → Alerts if table already booked
- Two-way sync: DB changes → Calendar updates

### Confirmation System:
- Customer receives email with confirmation link
- One-click confirmation button
- If not confirmed 3 hours before → Auto-cancelled
- Table becomes available again

---

## 🚀 Next Steps

1. **Set up Google Cloud** (follow Part 1 above)
2. **Download credentials JSON** file
3. **Add to `.env`** file
4. **Restart server** - Database will auto-update
5. **Test confirmation flow**

---

## 💡 Recommendations

### Start Simple:
1. ✅ **Email reminders only** (no SMS initially)
2. ✅ **Manual conflict resolution** (manager approves extensions)
3. ✅ **Test with 1-2 reservations** before going live

### Add Later:
- SMS reminders (if needed)
- Automatic conflict resolution
- Table reassignment logic

---

## 📞 Support

If you need help with setup:
1. Google Cloud: https://support.google.com/cloud
2. Twilio: https://support.twilio.com
3. Check server logs for errors

