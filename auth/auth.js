const jwt = require('jsonwebtoken');
require('dotenv').config();

const authorize = (roles = []) => {
    if (typeof roles === 'string') roles = [roles];

    return (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        // 🟢 FIX 1: Respond with 401 Unauthorized for missing token
        if (!token) {
            // Inform the client that authentication is required
            return res.status(401).json({ message: 'No token provided. Authentication required.' });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            // 🟢 FIX 2: Respond with 401 Unauthorized for invalid token
            if (err) {
                // The client should redirect to login upon receiving this 401
                return res.status(401).json({ message: 'Token is invalid or expired.' });
            }

            // 🚫 Role not allowed (This part was correct)
            if (roles.length && !roles.includes(user.role)) {
                return res.status(403).json({ message: 'Access denied — insufficient permissions' });
            }

            req.user = user;
            next();
        });
    };
};

module.exports = authorize;