// Path Traversal Prevention Module - NON-SLOPPY IMPLEMENTATION
const path = require('path');

class PathValidator {
  constructor() {
    // Sensitive directory/file names that should NEVER be accessible
    this.sensitiveNames = [
      '.env',
      '.git',
      '.ssh',
      '.aws',
      '.docker',
      'docker',
      'kubernetes',
      'secret',
      'private',
      'credential',
      'key',
      'password',
      'config',
      '.config',
      'secrets',
      'vault',
      '.vault',
      'cert',
      'certificate',
      'tls',
      'ssl',
      'pem',
      'pfx',
      'p12',
      'jwk',
      'oauth',
      'token',
      'apikey',
      'api_key',
      'access_token',
      'refresh_token',
      'session',
      'cookie',
      'auth',
      'passwd',
      'shadow',
      'sudoers',
      'etc/shadow',
      'etc/passwd',
      'root',
      'admin',
      'system32',
      'windows',
      'registry',
      'var/log',
      'var/www',
      'opt',
      'proc',
      'sys'
    ];
  }

  validateFilePath(userPath, baseDir) {
    // FIX #1: Validate input parameters exist
    if (!userPath || !baseDir) {
      throw new Error('Path validation: missing parameters');
    }

    if (typeof userPath !== 'string' || typeof baseDir !== 'string') {
      throw new Error('Path validation: paths must be strings');
    }

    // FIX #2: Convert to string to prevent object injection
    const userPathStr = String(userPath).trim();
    const baseDirStr = String(baseDir).trim();

    // FIX #3: Check for NULL bytes (immediate block)
    if (userPathStr.includes('\0')) {
      throw new Error('Path traversal: null bytes detected');
    }

    // FIX #4: Case-insensitive check for URL-encoded traversal sequences
    const lowerUserPath = userPathStr.toLowerCase();
    if (/%2e%2e|%2f|%5c|%252e|%252f|%255c/.test(lowerUserPath)) {
      throw new Error('Path traversal: encoded sequences detected');
    }

    // FIX #5: Normalize to handle both \\ and / separators
    const normalized = path.normalize(userPathStr);

    // FIX #6: Check for standard directory traversal patterns
    if (/\.\.[\\/]|[\\/]\.\./.test(normalized)) {
      throw new Error('Path traversal: .. traversal detected');
    }

    // FIX #7: Prevent absolute paths (CRITICAL)
    if (path.isAbsolute(normalized)) {
      throw new Error('Path traversal: absolute paths not allowed');
    }

    // FIX #8: Resolve both base directory and full path
    const resolvedBaseDir = path.resolve(baseDirStr);
    const fullPath = path.resolve(resolvedBaseDir, normalized);

    // FIX #9: Verify resolved path stays within base directory (CRITICAL)
    if (!fullPath.startsWith(resolvedBaseDir + path.sep) && fullPath !== resolvedBaseDir) {
      throw new Error('Path traversal: resolved path outside base directory');
    }

    // FIX #10: Case-insensitive sensitive name blacklist check
    const lowerFullPath = fullPath.toLowerCase();
    for (const sensitivePattern of this.sensitiveNames) {
      const lowerPattern = sensitivePattern.toLowerCase();
      
      // Check if sensitive name appears as a directory or filename
      const pathParts = lowerFullPath.split(path.sep);
      if (pathParts.some(part => part === lowerPattern || part.includes(lowerPattern))) {
        throw new Error(`Path traversal: access to sensitive directory/file blocked (${sensitivePattern})`);
      }
    }

    // FIX #11: Additional check for suspicious patterns
    const suspiciousPatterns = [
      /\.\./, // Any remaining ..
      /~/, // Home directory expansion
      /\$/, // Variable expansion
      /`/, // Command substitution
      /\|/, // Pipe operator
      /;/, // Command separator
      /&/ // Background operator
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(normalized)) {
        throw new Error('Path traversal: suspicious characters detected');
      }
    }

    return fullPath;
  }

  isPathAllowed(filePath, allowedDirs = []) {
    // FIX #12: Validate inputs
    if (!filePath || typeof filePath !== 'string') {
      return false;
    }

    if (!Array.isArray(allowedDirs) || allowedDirs.length === 0) {
      return false;
    }

    // FIX #13: Resolve the file path once
    let resolvedPath;
    try {
      resolvedPath = path.resolve(filePath);
    } catch (error) {
      console.error('[PATH-VALIDATOR] Path resolution failed:', error.message);
      return false;
    }

    // FIX #14: Check against each allowed directory
    for (const allowedDir of allowedDirs) {
      if (typeof allowedDir !== 'string') {
        continue;
      }

      try {
        const resolvedAllowedDir = path.resolve(allowedDir);
        
        // Use path.sep for OS-specific separator
        if (resolvedPath === resolvedAllowedDir || 
            resolvedPath.startsWith(resolvedAllowedDir + path.sep)) {
          return true;
        }
      } catch (error) {
        console.error('[PATH-VALIDATOR] Allowed dir resolution failed:', error.message);
        continue;
      }
    }

    return false;
  }
}

module.exports = new PathValidator();
