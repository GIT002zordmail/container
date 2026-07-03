// Security Error Handler Module
class SecurityErrorHandler {
  static sanitizeError(error, isDevelopment = false) {
    if (isDevelopment) {
      return {
        error: error.message || 'An error occurred',
        stack: error.stack
      };
    }

    // Production: hide internal error details
    const code = error.code || 'UNKNOWN';
    
    let message = 'An error occurred';
    let statusCode = 500;

    if (code === 'ENOENT') {
      message = 'Resource not found';
      statusCode = 404;
    } else if (code === 'EACCES') {
      message = 'Access denied';
      statusCode = 403;
    } else if (error.message && error.message.includes('timeout')) {
      message = 'Request timeout';
      statusCode = 408;
    }

    return {
      error: message,
      statusCode
    };
  }
}

module.exports = SecurityErrorHandler;
