// Health Check Response Builder Module
async function buildHealthPayload(options = {}) {
  const {
    initQuantumProxy,
    checkTunnelHealth,
    getEncryptionCapabilitySummary,
    req,
    serviceName
  } = options;

  try {
    // Initialize quantum proxy if available
    let quantumReady = false;
    if (initQuantumProxy) {
      try {
        await initQuantumProxy();
        quantumReady = true;
      } catch (error) {
        console.warn('[HEALTH] Quantum proxy initialization failed:', error.message);
      }
    }

    // Get encryption capabilities
    const encryption = getEncryptionCapabilitySummary ? 
      getEncryptionCapabilitySummary(req) : 
      {
        mode: 'classical',
        pqcAvailable: false,
        hybridFallback: true,
        classicalFallback: true
      };

    // Check tunnel health
    let tunnelStatus = {
      enabled: false,
      healthy: false,
      mode: 'disabled'
    };

    if (checkTunnelHealth) {
      try {
        tunnelStatus = await checkTunnelHealth();
      } catch (error) {
        console.warn('[HEALTH] Tunnel health check failed:', error.message);
      }
    }

    return {
      status: 'ok',
      service: serviceName || 'proxy-service',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      nodeVersion: process.version,
      environment: {
        nodeEnv: process.env.NODE_ENV || 'production'
      },
      security: {
        encryption: {
          mode: encryption.mode,
          pqcAvailable: encryption.pqcAvailable,
          hybridFallback: encryption.hybridFallback,
          classicalFallback: encryption.classicalFallback
        },
        quantumReady,
        tlsVersion: req && req.socket ? req.socket.tlsVersion : 'unknown'
      },
      tunnel: tunnelStatus,
      memory: {
        heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        external: Math.round(process.memoryUsage().external / 1024 / 1024)
      }
    };
  } catch (error) {
    console.error('[HEALTH] Failed to build payload:', error.message);
    return {
      status: 'error',
      service: serviceName || 'proxy-service',
      timestamp: new Date().toISOString(),
      error: error.message
    };
  }
}

module.exports = { buildHealthPayload };
