const jwt = require('jsonwebtoken');
const { errorResponse } = require('../utils/responseHelpers'); // Assuming you have a utility for responses

// Middleware to verify access token and attach user ID to request
exports.protect = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  
  // Check if authorization header exists and is properly formatted
  if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
    return errorResponse(res, 'Access token required', 401);
  }

  // Extract token from the header
  const accessToken = authorizationHeader.split(' ')[1];

  try {
    // Verify the token using the secret
    const decodedToken = jwt.verify(accessToken, process.env.JWT_SECRET);

    // Attach userId to the request object for downstream use
    req.userId = decodedToken.id;

    // Proceed to the next middleware or route handler
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return errorResponse(res, 'Access token expired', 401);
    }
    return errorResponse(res, 'Invalid access token', 403);
  }
};
