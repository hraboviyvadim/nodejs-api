// express.js server
const express = require('express');
const bodyParser = require('body-parser');
const config = require('./config/config');
// Mongo database
const mongoose = require('mongoose');
const passport = require('./auth');
const controllers = require('./controllers');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(controllers);
const server = app.listen(config.server.port, () => {
  console.log('We are live on ' + server.address().address + ':' + server.address().port);
});

mongoose.Promise = Promise;
mongoose.set('debug', true);
mongoose.connect(config.db.uri, config.db.options).then(() => {
  console.log(`Connection to MongoDB opened successfully!`);
});
