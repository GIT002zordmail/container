// Input Sanitization Module
const crypto = require('crypto');

class Sanitizer {
  // Sanitize string for logging (mask sensitive data)
  sanitizeForLogging(str) {
    if (!str || typeof str !== 'string') return str;
    
    // Mask API keys
    str = str.replace(/sk_[a-zA-Z0-9_]{20,}/g, 'sk_***MASKED***');
    // Mask tokens
    str = str.replace(/Bearer [a-zA-Z0-9_.-]{20,}/g, 'Bearer ***MASKED***');
    // Mask passwords
    str = str.replace(/password["']?\s*[:=]\s*["'][^"']*["']/gi, 'password="***MASKED***"');
    // Mask authorization headers
    str = str.replace(/authorization["']?\s*[:=]\s*["'][^"']*["']/gi, 'authorization="***MASKED***"');
    // Mask credit card patterns
    str = str.replace(/\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/g, '****-****-****-****');
    
    return str;
  }

  // Sanitize object for logging
  sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    
    const sanitized = JSON.parse(JSON.stringify(obj));
    const sensitiveFields = ['password', 'secret', 'token', 'apiKey', 'authorization', 'cookie', 'session'];
    
    const maskField = (field) => {
      if (sanitized[field]) {
        sanitized[field] = '***MASKED***';
      }
    };
    
    sensitiveFields.forEach(maskField);
    return sanitized;
  }

  // Sanitize HTML to prevent XSS
  sanitizeHTML(html) {
    if (!html || typeof html !== 'string') return html;
    return html
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  // Sanitize SQL input (basic prevention)
  sanitizeSQL(input) {
    if (!input || typeof input !== 'string') return input;
    // Single quote escape
    return input.replace(/'/g, "''");
  }
}

module.exports = new Sanitizer();
