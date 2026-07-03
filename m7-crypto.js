// M7 Cryptography Module - Quantum-safe encryption and HMAC operations
const crypto = require('crypto');

class M7Crypto {
  // Create per-request HMAC signature
  createPerRequestSignature(secret, payload, metadata = {}) {
    try {
      const normalizedSecret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
      const nonce = metadata.nonce || crypto.randomBytes(32);
      const timestamp = metadata.timestamp || Date.now();
      const method = metadata.method || 'POST';
      const path = metadata.path || '/';
      const info = metadata.info || 'm7-per-request-signature-v1';

      const dataToSign = Buffer.concat([
        Buffer.from(payload, 'utf8'),
        nonce,
        Buffer.from(timestamp.toString()),
        Buffer.from(method),
        Buffer.from(path),
        Buffer.from(info)
      ]);

      const signature = crypto.createHmac('sha256', normalizedSecret)
        .update(dataToSign)
        .digest('hex');

      return {
        signature,
        metadata: {
          nonce: nonce.toString('hex'),
          timestamp,
          method,
          path,
          algorithm: 'hmac-sha256-hkdf-v1'
        }
      };
    } catch (error) {
      console.error('[M7-CRYPTO] Signature creation failed:', error.message);
      return null;
    }
  }

  // Verify per-request HMAC signature
  verifyPerRequestSignature(signature, payload, secret, metadata = {}) {
    try {
      const normalizedSecret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
      const nonce = metadata.nonce ? Buffer.from(metadata.nonce, 'hex') : Buffer.alloc(32);
      const timestamp = metadata.timestamp || Date.now();
      const method = metadata.method || 'POST';
      const path = metadata.path || '/';
      const info = metadata.info || 'm7-per-request-signature-v1';

      const dataToSign = Buffer.concat([
        Buffer.from(payload, 'utf8'),
        nonce,
        Buffer.from(timestamp.toString()),
        Buffer.from(method),
        Buffer.from(path),
        Buffer.from(info)
      ]);

      const expectedSignature = crypto.createHmac('sha256', normalizedSecret)
        .update(dataToSign)
        .digest('hex');

      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );
    } catch (error) {
      console.error('[M7-CRYPTO] Signature verification failed:', error.message);
      return false;
    }
  }

  // Normalize secret to Buffer
  normalizeSecret(secret) {
    if (Buffer.isBuffer(secret)) return secret;
    return Buffer.from(secret, 'utf8');
  }

  // Encrypt payload with AES-256-GCM
  encryptPayload(plaintext, key, keyVersion = 1) {
    try {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const tag = cipher.getAuthTag();

      return {
        encrypted: true,
        iv: iv.toString('hex'),
        data: encrypted,
        tag: tag.toString('hex'),
        keyVersion,
        algorithm: 'aes-256-gcm'
      };
    } catch (error) {
      console.error('[M7-CRYPTO] Encryption failed:', error.message);
      return null;
    }
  }

  // Decrypt payload with AES-256-GCM
  decryptPayload(encryptedData, key) {
    try {
      if (!encryptedData.iv || !encryptedData.data || !encryptedData.tag) {
        throw new Error('Invalid encrypted data format');
      }

      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
      let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      console.error('[M7-CRYPTO] Decryption failed:', error.message);
      return null;
    }
  }

  // Check if data is encrypted envelope
  isEncryptedEnvelope(data) {
    if (!data || typeof data !== 'object') return false;
    return data.encrypted === true && data.iv && data.data && data.tag;
  }

  // Build request body for forwarding
  buildBody(body) {
    if (!body) return '';
    if (typeof body === 'string') return body;
    try {
      return JSON.stringify(body);
    } catch (e) {
      console.error('[M7-CRYPTO] Body serialization failed:', e.message);
      return '';
    }
  }

  // Check if request should be encrypted
  shouldEncryptRequest(req, rules = []) {
    if (!rules || rules.length === 0) return false;
    // Implement custom encryption rules based on request path/method
    return false; // Default: no encryption unless explicitly configured
  }
}

module.exports = new M7Crypto();
