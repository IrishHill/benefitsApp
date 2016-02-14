var _ = require('lodash');
var passport = require('passport');
var request = require('request');
var LocalStrategy = require('passport-local').Strategy;
var OpenIDStrategy = require('passport-openid').Strategy;
var OAuthStrategy = require('passport-oauth').OAuthStrategy;
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var IntuitStrategy = require('passport-intuit-oauth').Strategy
var User = require('../models/User');

var secrets = require('./secrets');

var INTUIT_CONSUMER_KEY = "qyprdsRlGX5ZlnKq03lWgHeSWyrmfl";
var INTUIT_CONSUMER_SECRET = "Ij3fAwUmBYIr2PMU0uWYt0fCU390obyK0hKou06e";

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: 'email' }, function(email, password, done) {
  email = email.toLowerCase();
  User.findOne({ email: email }, function(err, user) {
    if (!user) {
      return done(null, false, { message: 'Email ' + email + ' not found'});
    }
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Invalid email or password.' });
      }
    });
  });
}));

/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a provider id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */

/** 
* Sign in with Intuit.
*/
passport.use(new IntuitStrategy({
    consumerKey: INTUIT_CONSUMER_KEY,
    consumerSecret: INTUIT_CONSUMER_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/intuit/callback"
  },
  function(token, tokenSecret, profile, done) {
    User.findOrCreate({ intuitId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));





/**
 * Login Required middleware.
 */
exports.isAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

/**
 * Authorization Required middleware.
 */
exports.isAuthorized = function(req, res, next) {
  var provider = req.path.split('/').slice(-1)[0];

  if (_.find(req.user.tokens, { kind: provider })) {
    next();
  } else {
    res.redirect('/auth/' + provider);
  }
};
