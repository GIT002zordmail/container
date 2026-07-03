// FlareSolverr Request Builder Module
function buildFlareSolverrRequest(req, options = {}) {
  const body = req.body || {};
  const cmd = body.cmd || 'request.post';

  // Extract URL from request
  let url = body.url || body.target || body.destination || 'https://example.com';

  return {
    cmd,
    url,
    maxTimeout: options.tunnelTimeout || 30000,
    proxy: options.proxyUrl || undefined,
    session: body.session || undefined,
    cookies: body.cookies || [],
    headers: body.headers || {},
    returnRawHtml: body.returnRawHtml !== false,
    returnHeaders: body.returnHeaders !== false,
    downloader: body.downloader || 'chrome'
  };
}

module.exports = { buildFlareSolverrRequest };
