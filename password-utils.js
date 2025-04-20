const crypto = require('crypto');

/**
 * hashes a plain text password using PBKDF2.
 * @param {string} password
 * @returns {string} 
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

/**
 * verifing the plain text password using the  stored salt:hash string.
 * @param {string} password
 * @param {string} storedHash
 * @returns {boolean}
 */
function verifyPassword(password, storedHash) {
  const [salt, originalHash] = storedHash.split(':');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  const originalBuffer = Buffer.from(originalHash, 'hex');
  return crypto.timingSafeEqual(hash, originalBuffer);
}

module.exports = {
  hashPassword,
  verifyPassword,
};

