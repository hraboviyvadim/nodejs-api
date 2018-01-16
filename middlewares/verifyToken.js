const jwt = require('jsonwebtoken');
const config = require('../config/config');

const verifyToken = (req, res, next) => {
  const token = req.body.token || req.query.token || req.headers['x-access-token'];
  if(token) {
    jwt.verify(token, config.jwt_secret, (err, decoded) => {
      if(err) {
        return res.json({error: true, message: 'token verification failed!'});
      }
      req.decoded = decoded;
      next();
    })
  } else {
    return res.status(403).json({
      error: true,
      message: 'no token verification'
    })
  }
};

module.exports = verifyToken;