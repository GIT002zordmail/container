// ECH (Encrypted Client Hello) Status Module
function applyEchHeaders(res) {
  // ECH status headers
  res.set('X-ECH-Supported', 'true');
  res.set('X-ECH-Status', 'available');
  res.set('X-TLS-Version', 'TLSv1.3');
  return res;
}

module.exports = { applyEchHeaders };
