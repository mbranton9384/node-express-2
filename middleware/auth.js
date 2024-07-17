/** Middleware for handling req authorization for routes. */

const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');

/** Authorization Middleware: Requires user is logged in. */

function requireLogin(req, res, next) {
  try {
    if (req.curr_username) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}

/** Authorization Middleware: Requires user is logged in and is staff. */

function requireAdmin(req, res, next) {
  try {
    if (req.curr_admin) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}

/** Authentication Middleware: put user on request
 *
 * If there is a token, verify it, get payload (username/admin),
 * and store the username/admin on the request, so other middleware/routes
 * can use it.
 *
 * It's fine if there's no token---if not, don't set anything on the
 * request.
 *
 * If the token is invalid, an error will be raised.
 *
 **/

function authUser(req, res, next) {
  try {
    const token = req.body._token || req.query._token;

    if (token) {
      // Verify and decode the token
      jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
          // If token verification fails, return 401 Unauthorized
          return next({ status: 401, message: 'Unauthorized' });
        } else {
          // Token is valid, set properties on request object
          req.curr_username = decoded.username;
          req.curr_admin = decoded.admin;
          return next();
        }
      });
    } else {
      // No token provided, continue to next middleware
      return next();
    }
  } catch (err) {
    // Handle other errors if any
    return next(err);
  }
}


function requireAdminOrSelf(req, res, next) {
  try {
    if (req.curr_admin || req.params.username === req.curr_username) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}
// end

module.exports = {
  requireLogin,
  requireAdmin,
  authUser,
  requireAdminOrSelf
};
