// express.js server
const express = require('express');
const bodyParser = require('body-parser');
// passport.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');

// Mongo database
const mongoose = require('mongoose');
const crypto = require('crypto');

// constants
const port = process.env.PORT || 3000;
const jwtsecret = 'mysecretkey';

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
// const server = app.listen({host: 'localhost', port}, () => {
const server = app.listen(port, () => {
  console.log('We are live on ' + server.address().address + ':' + server.address().port);
});

mongoose.Promise = Promise;
const dbURL = process.env.MONGODB_URI || 'mongodb://admin:admin@ds125774.mlab.com:25774/test_db';
const dbOptions = {
  promiseLibrary: Promise,
  useMongoClient: true,
};
mongoose.set('debug', true);
mongoose.connect(dbURL, dbOptions).then(() => {
  console.log(`Connection to MongoDB opened successfully!`);
});

// user modal for DB
const userSchema = new mongoose.Schema({
  displayName: {
    type: String,
    unique: true,
    required: [true, 'can\'t be blank'],
    match: [/^[a-zA-Z0-9]+$/, 'is invalid'],
    index: true
  },
  email: {
    type: String,
    required: [true, "can't be blank"],
    match: [/\S+@\S+\.\S+/, 'is invalid'],
    index: true
  },
  passwordHash: String,
  salt: String
}, {timestamps: true});

userSchema.virtual('password').set(function(password) {
  this._plainPassword = password;
  if(password) {
    this.salt = crypto.randomBytes(128).toString('base64');
    //this.passwordHash = crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha512');
    this.passwordHash = password;
  } else {
    this.salt = undefined;
    this.passwordHash = undefined;
  }
});
userSchema.virtual('password').get(function() {
  return this._plainPassword;
});
userSchema.methods.checkPassword = function (password) {
  if (!password) return false;
  if (!this.passwordHash) return false;
  //return crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha512') === this.passwordHash;
  return password === this.passwordHash;
};
const User = mongoose.model('User', userSchema);

// passport strategies
passport.serializeUser(function(user, done) {
  done(null, user);
});


passport.deserializeUser(function(email, done) {
  User.findOne({email: email}, function(err,user){
    err ? done(err) : done(null,user);
  });
});
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  session: false
}, function (email, password, done) {
  User.findOne({email: email}, (err, user) => {
    if (err) {
      return done(err);
    }
    if(!user || !user.checkPassword(password)) {
      return done(null, false, {
        message: 'This user doesnt exist or password is incorrect'
      });
    }
    return done(null, user);
  });
}));

const verifyToken = (req, res, next) => {
  const token = req.body.token || req.query.token || req.headers['x-access-token'];
  if(token) {
    jwt.verify(token, jwtsecret, (err, decoded) => {
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

// Auth API
app.get('/', (req, res) => {
  res.send('Hello, world!');
});
app.post('/user', (req, res) => {
  User.create(req.body, (err, result) => {
    if (err) {
      res.send(err);
    } else {
      res.status(400).send(result);
    }
  });
});
app.post('/login', passport.authenticate('local'), (req, res) => {
  if(req.user) {
    const payload = {
      displayName: req.user.displayName,
      email: req.user.email
    };
    const token = jwt.sign(payload, jwtsecret);
    res.status(200).json({error: false, user: req.user.displayName, token: token});
  } else {
    res.status(401).send('Login failed!');
  }
});
app.get('/protected', verifyToken, function (req, res) {
  if(!req.decoded) {
    res.send('No such user');
  } else {
      res.json('Hello ' + req.decoded.displayName);
  }
});