const crypto = require('crypto');

/**
 * Helper: Base64url encode (no padding)
 */
function base64urlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '') 
    .replace(/\+/g, '-') 
    .replace(/\//g, '_'); 
}

/**
 * Helper: Base64url decode
 */
function base64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString();
}

/**
 * Creates a JWT token.
 * @param {object} payload
 * @param {string} secret
 * @param {number} expiresInSeconds
 * @returns {string}
 */
function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const fullPayload = { ...payload, exp };

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(fullPayload));

  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${data}.${signature}`;
}

/**
 * Verifies a JWT token.
 * @param {string} token
 * @param {string} secret
 * @returns {object}
 * @throws if invalid or expired
 */
function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (signature !== expectedSignature) {
    throw new Error('Invalid signature');
  }

  const payload = JSON.parse(base64urlDecode(encodedPayload));
  const currentTime = Math.floor(Date.now() / 1000);
  if (payload.exp && currentTime >= payload.exp) {
    throw new Error('Token expired');
  }

  return payload;
}

module.exports = {
  signJWT,
  verifyJWT,
};
