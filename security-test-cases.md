# Security Test Cases for XIX Restaurant Website

## 🔒 Security Features Implemented

### 1. **Rate Limiting**
- **General API**: 100 requests per 15 minutes per IP
- **Reservations**: 5 reservation attempts per hour per IP
- **Test**: Try submitting more than 5 reservations in an hour

### 2. **Input Validation & Sanitization**

#### **Name Validation**
- ✅ Valid: "John Smith", "Mary O'Connor", "Jean-Pierre"
- ❌ Invalid: "J", "A" * 51, "John123", "John<script>alert('xss')</script>"

#### **Email Validation**
- ✅ Valid: "user@example.com", "test.email+tag@domain.co.uk"
- ❌ Invalid: "invalid-email", "@domain.com", "user@", "user@domain"

#### **Phone Validation**
- ✅ Valid: "+44 20 7123 4567", "020 7123 4567", "07796 817690"
- ❌ Invalid: "123", "abc", "+1 555 123 4567" (US number)

#### **Date Validation**
- ✅ Valid: Today to 3 months in advance
- ❌ Invalid: Yesterday, 4 months ahead, "invalid-date"

#### **Time Validation**
- ✅ Valid: "18:00", "19:30", "22:00"
- ❌ Invalid: "25:00", "18:60", "invalid-time"

#### **Guests Validation**
- ✅ Valid: 1-20 guests
- ❌ Invalid: 0, 21, "abc", negative numbers

#### **Special Requests Validation**
- ✅ Valid: Up to 500 characters
- ❌ Invalid: More than 500 characters

### 3. **XSS Prevention**
- All user inputs are sanitized using DOMPurify
- HTML tags and scripts are stripped from inputs
- Test: Try entering `<script>alert('xss')</script>` in any field

### 4. **SQL Injection Prevention**
- All database queries use parameterized statements
- User inputs are properly escaped
- Test: Try entering `'; DROP TABLE reservations; --` in any field

### 5. **Security Headers**
- Helmet.js provides security headers
- Content Security Policy (CSP) implemented
- XSS protection enabled

## 🧪 Test Scenarios

### **Scenario 1: Valid Reservation**
```
Name: John Smith
Email: john@example.com
Phone: +44 20 7123 4567
Date: 2024-01-15
Time: 19:00
Guests: 4
Table: Window Table
Occasion: Birthday
Special Requests: Please prepare a birthday cake
```
**Expected**: ✅ Success - Reservation confirmed

### **Scenario 2: Invalid Email**
```
Name: John Smith
Email: invalid-email
Phone: +44 20 7123 4567
Date: 2024-01-15
Time: 19:00
Guests: 4
```
**Expected**: ❌ Error - "Please provide a valid email address"

### **Scenario 3: XSS Attempt**
```
Name: <script>alert('xss')</script>
Email: test@example.com
Phone: +44 20 7123 4567
Date: 2024-01-15
Time: 19:00
Guests: 2
```
**Expected**: ❌ Error - "Name must be 2-50 characters and contain only letters, spaces, hyphens, apostrophes, and periods"

### **Scenario 4: SQL Injection Attempt**
```
Name: John'; DROP TABLE reservations; --
Email: test@example.com
Phone: +44 20 7123 4567
Date: 2024-01-15
Time: 19:00
Guests: 2
```
**Expected**: ❌ Error - "Name must be 2-50 characters and contain only letters, spaces, hyphens, apostrophes, and periods"

### **Scenario 5: Rate Limiting**
1. Submit 6 reservations within 1 hour
2. **Expected**: ❌ Error - "Too many reservation attempts. Please try again later."

### **Scenario 6: Past Date**
```
Name: John Smith
Email: test@example.com
Phone: +44 20 7123 4567
Date: 2023-01-01 (past date)
Time: 19:00
Guests: 2
```
**Expected**: ❌ Error - "Please select a valid date (today to 3 months in advance)"

## 🛡️ Security Benefits

1. **Prevents Spam**: Rate limiting stops automated attacks
2. **Data Integrity**: Validation ensures clean, consistent data
3. **XSS Protection**: Sanitization prevents malicious scripts
4. **SQL Injection Prevention**: Parameterized queries protect database
5. **User Experience**: Real-time validation provides immediate feedback
6. **Compliance**: Meets security best practices for web applications

## 📋 Installation Instructions

To install the new security dependencies:

```bash
npm install express-rate-limit helmet isomorphic-dompurify validator
```

The security features are automatically enabled when you start the server.
