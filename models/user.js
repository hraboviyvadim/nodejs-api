const mongoose = require('mongoose');
const crypto = require('crypto');

// user modal for DB
const userSchema = new mongoose.Schema({
  displayName: {
    type: String,
    unique: true,
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

module.exports = mongoose.model('User', userSchema);