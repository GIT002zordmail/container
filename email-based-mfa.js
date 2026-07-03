// Email-Based Multi-Factor Authentication Module
const crypto = require('crypto');

class EmailBasedMFA {
  constructor() {
    this.users = new Map();
    this.otpCache = new Map();
    this.otpExpiry = 15 * 60 * 1000; // 15 minutes
  }

  generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
  }

  requestNewAPIKey(userData) {
    const otp = this.generateOTP();
    const expiryTime = Date.now() + this.otpExpiry;

    this.otpCache.set(userData.email, {
      otp,
      expiresAt: expiryTime,
      userData
    });

    return { otp, expiresIn: '15 minutes' };
  }

  requestKeyRotation(email) {
    const otp = this.generateOTP();
    const expiryTime = Date.now() + this.otpExpiry;

    this.otpCache.set(email, {
      otp,
      expiresAt: expiryTime,
      email
    });

    return { otp, expiresIn: '15 minutes' };
  }

  verifyAndActivateKey(email, otp) {
    const cached = this.otpCache.get(email);

    if (!cached || cached.otp !== otp) {
      throw new Error('Invalid OTP');
    }

    if (Date.now() > cached.expiresAt) {
      throw new Error('OTP expired');
    }

    const apiKey = 'sk_' + crypto.randomBytes(32).toString('hex');
    
    if (!this.users.has(email)) {
      this.users.set(email, {});
    }

    this.users.get(email).apiKey = apiKey;
    this.otpCache.delete(email);

    return {
      apiKey,
      expiresIn: '90 days'
    };
  }

  getUserByEmail(email) {
    return this.users.get(email) || null;
  }
}

module.exports = EmailBasedMFA;
