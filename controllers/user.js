const express = require('express');
const router = express.Router();
const passport = require('../auth');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const config = require('../config/config');

router.post('/signup', (req, res) => {
  User.create(req.body, (err, result) => {
    if (err) {
      res.send(err);
    } else {
      res.status(400).send(result);
    }
  });
});
router.post('/login', passport.authenticate('local'), (req, res) => {
  if(req.user) {
    const payload = {
      displayName: req.user.displayName,
      email: req.user.email
    };
    const token = jwt.sign(payload, config.jwt_secret, {
      expiresIn: 1440 // expirtes in 1 hour
    });
    res.status(200).json({error: false, user: req.user.displayName, token: token});
  } else {
    res.status(401).send('Login failed!');
  }
});

module.exports = router;