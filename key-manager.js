// API Key Management Module
const crypto = require('crypto');

class APIKeyManager {
  constructor() {
    this.keys = new Map();
  }

  createKey(options = {}) {
    const key = 'sk_' + crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresIn = options.expiresIn || 90 * 24 * 60 * 60 * 1000;

    return {
      key,
      created: now,
      expires: now + expiresIn,
      scopes: options.scopes || ['read'],
      name: options.name || 'api-key',
      enabled: true
    };
  }

  validateKey(key) {
    const keyData = this.keys.get(key);
    
    if (!keyData) {
      return {
        valid: false,
        reason: 'Key not found'
      };
    }

    if (!keyData.enabled) {
      return {
        valid: false,
        reason: 'Key is disabled'
      };
    }

    if (keyData.expires && Date.now() > keyData.expires) {
      return {
        valid: false,
        reason: 'Key expired'
      };
    }

    return {
      valid: true,
      scopes: keyData.scopes || [],
      reason: null
    };
  }

  rotateKey(currentKey) {
    const newKey = this.createKey({ scopes: ['read', 'write'] });
    this.keys.set(newKey.key, newKey);
    return newKey.key;
  }
}

module.exports = APIKeyManager;
