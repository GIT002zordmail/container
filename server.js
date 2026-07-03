/**
 * LAN Proxy Server - HTTP/HTTPS Proxy with Middleware Support
 * Supports: ES Modules, Dynamic Imports, SOCKS5 Tunneling
 */

import { createProxyMiddleware } from 'http-proxy-middleware';
import http from 'http';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ════════════════════════════════════════════════════════════════
// CONFIGURATION
// ════════════════════════════════════════════════════════════════

const CONFIG = {
    port: process.env.PORT || process.env.PROXY_PORT || 8789,
    host: process.env.HOST || '0.0.0.0',
    logLevel: process.env.LOG_LEVEL || 'info',
    apiKey: process.env.PROXY_API_KEY || '',
    tlsCertPath: process.env.TLS_CERT_PATH || '/app/certs/server.crt',
    tlsKeyPath: process.env.TLS_KEY_PATH || '/app/certs/server.key',
    socksUrl: process.env.SOCKS_PROXY_URL || 'socks5://cloudflared-socks:8888',
    flaresolverrUrl: process.env.FLARESOLVERR_URL || 'http://flaresolverr:8191',
};

// ════════════════════════════════════════════════════════════════
// LOGGING UTILITIES
// ════════════════════════════════════════════════════════════════

const logger = {
    info: (msg) => console.log(`[INFO] ${new Date().toISOString()} ${msg}`),
    warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} ${msg}`),
    error: (msg) => console.error(`[ERROR] ${new Date().toISOString()} ${msg}`),
    debug: (msg) => CONFIG.logLevel === 'debug' && console.log(`[DEBUG] ${new Date().toISOString()} ${msg}`),
};

// ════════════════════════════════════════════════════════════════
// MIDDLEWARE CONFIGURATION
// ════════════════════════════════════════════════════════════════

/**
 * Create proxy middleware for FlareSolverr
 */
const createFlaresolverrProxy = () => {
    return createProxyMiddleware({
        target: CONFIG.flaresolverrUrl,
        changeOrigin: true,
        pathRewrite: {
            '^/flaresolverr': '',
        },
        logLevel: CONFIG.logLevel,
        onError: (err, req, res) => {
            logger.error(`FlareSolverr proxy error: ${err.message}`);
            res.status(502).json({ error: 'FlareSolverr service unavailable', details: err.message });
        },
        onProxyRes: (proxyRes, req, res) => {
            logger.debug(`FlareSolverr response: ${proxyRes.statusCode}`);
        },
    });
};

/**
 * Create proxy middleware for SOCKS5 tunnel
 */
const createSocksProxy = () => {
    return createProxyMiddleware({
        target: CONFIG.socksUrl,
        changeOrigin: true,
        pathRewrite: {
            '^/socks': '',
        },
        logLevel: CONFIG.logLevel,
        onError: (err, req, res) => {
            logger.error(`SOCKS proxy error: ${err.message}`);
            res.status(502).json({ error: 'SOCKS tunnel unavailable', details: err.message });
        },
    });
};

// ════════════════════════════════════════════════════════════════
// REQUEST HANDLERS
// ════════════════════════════════════════════════════════════════

/**
 * Health check endpoint
 */
const healthCheck = (req, res) => {
    res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        port: CONFIG.port,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
    });
};

/**
 * Status endpoint
 */
const statusHandler = (req, res) => {
    res.status(200).json({
        service: 'LAN Proxy',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        configuration: {
            port: CONFIG.port,
            host: CONFIG.host,
            logLevel: CONFIG.logLevel,
            flaresolverr: CONFIG.flaresolverrUrl,
            socks: CONFIG.socksUrl,
        },
        uptime: process.uptime(),
        pid: process.pid,
    });
};

/**
 * API Key validation middleware
 */
const validateApiKey = (req, res, next) => {
    if (!CONFIG.apiKey) {
        logger.warn('API key validation disabled (PROXY_API_KEY not set)');
        return next();
    }

    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey) {
        logger.warn(`Request missing API key from ${req.ip}`);
        return res.status(401).json({ error: 'Missing API key' });
    }

    if (apiKey !== CONFIG.apiKey) {
        logger.warn(`Invalid API key attempt from ${req.ip}`);
        return res.status(403).json({ error: 'Invalid API key' });
    }

    logger.debug(`Valid API key from ${req.ip}`);
    next();
};

/**
 * Request logging middleware
 */
const requestLogger = (req, res, next) => {
    const startTime = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info(`${req.method} ${req.url} ${res.statusCode} ${duration}ms from ${req.ip}`);
    });
    next();
};

// ════════════════════════════════════════════════════════════════
// INITIALIZE HTTP SERVER
// ════════════════════════════════════════════════════════════════

const createServer = () => {
    const flaresolverrProxy = createFlaresolverrProxy();
    const socksProxy = createSocksProxy();

    const requestHandler = (req, res) => {
        // Logging
        requestLogger(req, res, () => {
            // Health check endpoint (no auth required)
            if (req.url === '/health' || req.url === '/health/') {
                return healthCheck(req, res);
            }

            // Status endpoint (no auth required)
            if (req.url === '/status' || req.url === '/status/') {
                return statusHandler(req, res);
            }

            // API key validation for protected routes
            validateApiKey(req, res, () => {
                // Route to FlareSolverr
                if (req.url.startsWith('/flaresolverr')) {
                    return flaresolverrProxy(req, res);
                }

                // Route to SOCKS proxy
                if (req.url.startsWith('/socks')) {
                    return socksProxy(req, res);
                }

                // Default 404
                res.statusCode = 404;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: 'Not found', path: req.url }));
            });
        });
    };

    return requestHandler;
};

// ════════════════════════════════════════════════════════════════
// LOAD TLS CERTIFICATES
// ════════════════════════════════════════════════════════════════

const loadTlsCertificates = () => {
    try {
        if (fs.existsSync(CONFIG.tlsCertPath) && fs.existsSync(CONFIG.tlsKeyPath)) {
            logger.info('Loading TLS certificates...');
            const cert = fs.readFileSync(CONFIG.tlsCertPath);
            const key = fs.readFileSync(CONFIG.tlsKeyPath);
            logger.info('✓ TLS certificates loaded successfully');
            return { cert, key };
        } else {
            logger.warn('TLS certificates not found:');
            logger.warn(`  - Cert: ${CONFIG.tlsCertPath}`);
            logger.warn(`  - Key: ${CONFIG.tlsKeyPath}`);
            logger.warn('Server will run on HTTP only');
            return null;
        }
    } catch (err) {
        logger.error(`Failed to load TLS certificates: ${err.message}`);
        return null;
    }
};

// ════════════════════════════════════════════════════════════════
// START SERVER
// ════════════════════════════════════════════════════════════════

const startServer = async () => {
    const requestHandler = createServer();

    // Try HTTPS if certificates available, fall back to HTTP
    const tlsCerts = loadTlsCertificates();
    let server;

    if (tlsCerts) {
        server = https.createServer(tlsCerts, requestHandler);
        logger.info('HTTPS server created');
    } else {
        server = http.createServer(requestHandler);
        logger.info('HTTP server created (no TLS certificates)');
    }

    // Handle server errors
    server.on('error', (err) => {
        logger.error(`Server error: ${err.message}`);
        if (err.code === 'EADDRINUSE') {
            logger.error(`Port ${CONFIG.port} is already in use`);
            process.exit(1);
        }
    });

    // Start listening
    server.listen(CONFIG.port, CONFIG.host, () => {
        const protocol = tlsCerts ? 'HTTPS' : 'HTTP';
        logger.info('');
        logger.info('╔════════════════════════════════════════════════════════╗');
        logger.info(`║ 🚀 LAN PROXY SERVER STARTED                            ║`);
        logger.info('╚════════════════════════════════════════════════════════╝');
        logger.info(`Protocol: ${protocol}`);
        logger.info(`Address: ${CONFIG.host}:${CONFIG.port}`);
        logger.info(`Log Level: ${CONFIG.logLevel}`);
        logger.info('');
        logger.info('Available endpoints:');
        logger.info(`  - GET  /health              : Health check`);
        logger.info(`  - GET  /status              : Service status`);
        logger.info(`  - POST /flaresolverr/*      : FlareSolverr proxy`);
        logger.info(`  - POST /socks/*             : SOCKS5 tunnel proxy`);
        logger.info('');
    });

    // Handle graceful shutdown
    process.on('SIGTERM', () => {
        logger.info('SIGTERM received - shutting down gracefully...');
        server.close(() => {
            logger.info('Server closed');
            process.exit(0);
        });
    });

    process.on('SIGINT', () => {
        logger.info('SIGINT received - shutting down gracefully...');
        server.close(() => {
            logger.info('Server closed');
            process.exit(0);
        });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
        logger.error(`Uncaught Exception: ${err.message}`);
        logger.error(err.stack);
        process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
        logger.error(`Unhandled Rejection at ${promise}:`, reason);
        process.exit(1);
    });
};

// Start the server
startServer().catch((err) => {
    logger.error(`Failed to start server: ${err.message}`);
    process.exit(1);
});
