// Tunnel Health Monitoring Module
const http = require('http');
const https = require('https');

function createTunnelHealthController(options = {}) {
  const state = {
    enabled: options.enabled || false,
    mode: options.mode || 'disabled',
    gateway: options.gateway || '127.0.0.1:8888',
    timeoutMs: options.timeoutMs || 30000,
    maxFailures: options.maxFailures || 3,
    failureCount: 0,
    isHealthy: false,
    lastCheck: null,
    lastError: null
  };

  return {
    state,

    async checkHealth(options = {}) {
      const gateway = options.gateway || state.gateway;
      const timeoutMs = options.timeoutMs || state.timeoutMs;

      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          state.failureCount++;
          state.isHealthy = false;
          state.lastError = 'Health check timeout';
          state.lastCheck = Date.now();
          resolve(state);
        }, timeoutMs);

        try {
          const client = http.get(`http://${gateway}/health`, { timeout: timeoutMs }, (res) => {
            clearTimeout(timeout);
            
            if (res.statusCode === 200 || res.statusCode === 204) {
              state.failureCount = 0;
              state.isHealthy = true;
              state.lastError = null;
            } else {
              state.failureCount++;
              state.isHealthy = state.failureCount < state.maxFailures;
              state.lastError = `HTTP ${res.statusCode}`;
            }
            
            state.lastCheck = Date.now();
            resolve(state);
            res.resume();
          });

          client.on('error', (err) => {
            clearTimeout(timeout);
            state.failureCount++;
            state.isHealthy = state.failureCount < state.maxFailures;
            state.lastError = err.message;
            state.lastCheck = Date.now();
            resolve(state);
          });
        } catch (err) {
          clearTimeout(timeout);
          state.failureCount++;
          state.isHealthy = false;
          state.lastError = err.message;
          state.lastCheck = Date.now();
          resolve(state);
        }
      });
    },

    getStatusSnapshot() {
      return { ...state };
    }
  };
}

module.exports = { createTunnelHealthController };
