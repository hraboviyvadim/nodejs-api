const passport = require('passport');
const crypto = require('crypto');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');

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

module.exports = passport;