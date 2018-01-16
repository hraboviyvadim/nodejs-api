const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.json(req.decoded);
});
router.get('/protected', function (req, res) {
  if(!req.decoded) {
    res.send('No such user');
  } else {
    res.json('Hello ' + req.decoded.displayName);
  }
});

module.exports = router;