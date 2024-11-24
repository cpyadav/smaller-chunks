const jwt = require('jsonwebtoken');

/**
 * Generates an access token with a short expiry.
 * @param {number|string} userId - The user's ID
 * @returns {string} - Signed JWT access token
 */
const generateAccessToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET, // Ensure this is stored securely in your environment
    { expiresIn: '1h' } // 15 minutes for access token
  );
};

/**
 * Generates a refresh token with a longer expiry.
 * @param {number|string} userId - The user's ID
 * @returns {string} - Signed JWT refresh token
 */
const generateRefreshToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_REFRESH_SECRET, // Separate secret for refresh tokens
    { expiresIn: '7d' } // 7 days for refresh token
  );
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
};
