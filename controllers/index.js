const express = require('express');
const router = express.Router();
const verifyToken = require('../middlewares').verifyToken;

router.use('/user', require('./user'));
router.use('/api', verifyToken, require('./api'));

module.exports = router;