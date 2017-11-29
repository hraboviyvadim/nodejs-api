// express.js server
const express = require('express');
const bodyParser = require('body-parser');
// passport.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');

// Mongo database
const mongoose = require('mongoose');
const crypto = require('crypto');

// constants
const port = 3000;
const jwtsecret = 'mysecretkey';

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
const server = app.listen({host: 'localhost', port}, () => {
  console.log('We are live on ' + server.address().address + ':' + server.address().port);
});

mongoose.Promise = Promise;
const dbOptions = {
  promiseLibrary: Promise,
  useMongoClient: true,
};
mongoose.set('debug', true);
mongoose.connect('mongodb://admin:admin@ds125774.mlab.com:25774/test_db', dbOptions).then(() => {
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
    this.passwordHash = crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha1');
  } else {
    this.salt = undefined;
    this.passwordHash = undefined;
  }
});
userSchema.virtual('password').get(function() {
  return this._plainPassword;
});
userSchema.methods.checkPAssword = function (password) {
  if (!password) return false;
  if (!this.passwordHash) return false;
  return crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha1') === this.passwordHash;
};
const User = mongoose.model('User', userSchema);

// passport strategies
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  session: false
}, function (email, password, done) {
  User.findOne({email}, (err, user) => {
    if (err) {
      return done(err);
    }
    if(!user || !user.checkPAssword(password)) {
      return done(null, false, {
        message: 'This user doesnt exist or password is incorrect'
      });
    }
    return done(null, user);
  });
}));
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwtsecret
};
passport.use(new JwtStrategy(jwtOptions, function (payload, done) {
  User.findById(payload.id, (err, user) => {
    if (err) {
      return done(err);
    }
    if(user) {
      done(null, user);
    } else {
      done(null, false);
    }
  })
}));

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
app.post('/login', passport.authenticate('local', (err, user) => {
  if (err) {
    return err;
  } else {
    if(user) {
      const payload = {
        id: user.id,
        displayName: user.displayName,
        email: user.email
      };
      const token = jwt.sign(payload, jwtsecret);
      return {user: user.displayName, token: 'JWT ' + token};
    } else {
      return 'Login failed!';
    }
  }
}));
app.get('/custom', passport.authenticate('jwt'), function (err, user) {
  if(err) {
    return err;
  } else {
    if (user) {
      return 'Hello ' + user.displayName;
    } else {
      return 'No such user';
    }
  }
});