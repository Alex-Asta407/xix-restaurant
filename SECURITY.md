# 🔒 Security Implementation Guide - XIX Restaurant

## 🛡️ Security Features Implemented

### 1. **DDoS Protection**
- **Express Slow Down**: Delays requests after 50 requests per 15 minutes
- **Express Brute**: Blocks IPs after 5 failed attempts with exponential backoff
- **Rate Limiting**: 100 requests per 15 minutes per IP (general), 5 reservations per hour

### 2. **Security Logging**
- **Winston Logger**: Comprehensive logging system
- **Security Events**: All security incidents logged to `logs/security.log`
- **HTTP Requests**: All requests logged with Morgan
- **Suspicious Activity**: Automatic detection and logging of malicious requests

### 3. **CSRF Protection**
- **CSRF Tokens**: All POST requests require valid CSRF tokens
- **Secure Cookies**: HTTP-only, secure, same-site cookies
- **Token Endpoint**: `/api/csrf-token` for frontend token retrieval

### 4. **Request Size Limits**
- **JSON Payloads**: Limited to 10MB
- **URL-encoded**: Limited to 10MB
- **Prevents**: Large payload attacks and memory exhaustion

### 5. **Input Validation & Sanitization**
- **DOMPurify**: XSS prevention through HTML sanitization
- **Validator**: Email, phone, and data format validation
- **Comprehensive**: All user inputs validated and sanitized

### 6. **Security Headers**
- **Helmet.js**: Security headers including CSP
- **Content Security Policy**: Restricts resource loading
- **XSS Protection**: Browser-level XSS prevention

## 📊 Security Monitoring

### **Log Files**
- `logs/security.log` - Security events and warnings
- `logs/error.log` - Application errors
- Console output - Real-time monitoring

### **Security Endpoints**
- `GET /api/csrf-token` - Get CSRF token for forms
- `GET /api/security/logs` - View security logs (admin only)

### **Monitored Events**
- ✅ Successful reservations
- ⚠️ Validation failures
- 🚨 Brute force attempts
- 🚨 DDoS attacks
- 🚨 Suspicious requests
- 🚨 Unauthorized access attempts

## 🔧 Configuration

### **Environment Variables**
```bash
NODE_ENV=production  # Enables stricter security
PORT=3001           # Server port
```

### **Rate Limiting**
- **General**: 100 requests/15 minutes
- **Reservations**: 5 attempts/hour (production), 50/hour (development)
- **DDoS**: 50 requests/15 minutes before delays

### **CSRF Protection**
- **Cookie**: HTTP-only, secure, same-site
- **Methods**: Applied to POST, PUT, DELETE requests
- **Excluded**: GET, HEAD, OPTIONS requests

## 🚨 Security Alerts

### **Automatic Logging**
The system automatically logs:
- Failed validation attempts
- Brute force attacks
- DDoS protection triggers
- Suspicious request patterns
- Unauthorized access attempts

### **Response Codes**
- `400` - Validation failed
- `403` - Access denied
- `429` - Rate limit exceeded
- `500` - Server error

## 📋 Security Checklist

### **Production Deployment**
- [ ] Set `NODE_ENV=production`
- [ ] Configure SSL/HTTPS
- [ ] Set up log rotation
- [ ] Monitor security logs
- [ ] Configure firewall rules
- [ ] Set up backup procedures

### **Regular Maintenance**
- [ ] Review security logs weekly
- [ ] Update dependencies monthly
- [ ] Test security features quarterly
- [ ] Backup logs and database
- [ ] Monitor for new vulnerabilities

## 🔍 Testing Security Features

### **Rate Limiting Test**
```bash
# Test rate limiting
for i in {1..110}; do curl -X GET http://localhost:3001/; done
```

### **CSRF Protection Test**
```bash
# Test CSRF protection
curl -X POST http://localhost:3001/api/send-reservation-email \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@example.com"}'
```

### **Input Validation Test**
```bash
# Test XSS protection
curl -X POST http://localhost:3001/api/send-reservation-email \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(\"xss\")</script>","email":"test@example.com"}'
```

## 📞 Security Incident Response

### **If Security Breach Detected**
1. Check security logs immediately
2. Identify affected systems
3. Block malicious IPs if needed
4. Review and update security measures
5. Document incident and response

### **Emergency Contacts**
- System Administrator: [Your Contact]
- Security Team: [Security Contact]
- Hosting Provider: [Provider Contact]

## 🔄 Security Updates

### **Dependencies**
Regularly update security packages:
```bash
npm audit
npm audit fix
npm update
```

### **Security Patches**
- Monitor security advisories
- Apply patches promptly
- Test in development first
- Deploy during maintenance windows

---

**Last Updated**: $(date)
**Version**: 1.0.0
**Security Level**: High
