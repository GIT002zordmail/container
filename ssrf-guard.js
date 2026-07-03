// SSRF (Server-Side Request Forgery) Protection Module
const url = require('url');

class SSRFGuard {
  constructor() {
    // Private IP ranges to block
    this.privateRanges = [
      /^localhost$/i,
      /^127\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^::1$/,
      /^fc00:/i,
      /^fe80:/i,
      /^0\.0\.0\.0$/,
      /^255\.255\.255\.255$/
    ];

    this.blockedTLDs = ['.local', '.internal', '.test', '.localhost', '.internal', '.corp'];
  }

  validateRequestURL(targetUrl) {
    if (!targetUrl) {
      throw new Error('URL is required');
    }

    try {
      const parsed = typeof targetUrl === 'string' ? new URL(targetUrl) : targetUrl;
      const hostname = parsed.hostname.toLowerCase();

      // Check private IP ranges
      for (const pattern of this.privateRanges) {
        if (pattern.test(hostname)) {
          throw new Error(`Private IP address blocked: ${hostname}`);
        }
      }

      // Check blocked TLDs
      for (const tld of this.blockedTLDs) {
        if (hostname.endsWith(tld)) {
          throw new Error(`Blocked TLD: ${tld}`);
        }
      }

      // Check for URL encoding tricks
      if (/%2e%2e%2f/i.test(targetUrl)) {
        throw new Error('URL encoded path traversal detected');
      }

      return true;
    } catch (error) {
      throw new Error(`Invalid URL: ${error.message}`);
    }
  }
}

module.exports = new SSRFGuard();
