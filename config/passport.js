const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;
const validatePassword = require('../lib/passwordUtils').validatePassword;

// TODO: passport.use();
const verifyCallback = (username, password, cb) => {
  User.findOne({ username: username })
    .then((user) => {
      if (!user) {
        return cb(null, false);
      }

      // Function defined at bottom of app.js
      const isValid = validatePassword(password, user.hash, user.salt);

      if (isValid) {
        return cb(null, user);
      } else {
        return cb(null, false);
      }
    })
    .catch((err) => {
      cb(err);
    });
};

// Can customize field names using 1st arg of LocalStrategy Constructor
// const customFieldNames = { username: 'uname', password: 'pwd'}
// const strategy = new LocalStrategy(customFieldNames, verifyCallback);
const strategy = new LocalStrategy(verifyCallback);

passport.use(strategy);

// user from session to db?
passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});

// user from db to session?
passport.deserializeUser(function (id, cb) {
  User.findById(id, function (err, user) {
    if (err) {
      return cb(err);
    }
    cb(null, user);
  });
});
