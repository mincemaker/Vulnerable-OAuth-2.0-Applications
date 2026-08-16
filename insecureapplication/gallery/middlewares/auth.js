const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const BasicStrategy = require('passport-http').BasicStrategy;
const ClientPasswordStrategy = require(
    'passport-oauth2-client-password').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;
const login = require('connect-ensure-login');
const bcryptjs = require('bcryptjs');

const users = require('../db/users');
const clients = require('../db/clients');
const oauth = require('../db/oauth');

// Replaces passport-local-mongoose's User.createStrategy(): verifies
// username/password against the SQLite-stored bcrypt hash.
passport.use(new LocalStrategy(function(username, password, done) {
  let user;
  try {
    user = users.getUserByUsername(username);
  } catch (err) {
    return done(err);
  }
  if (!user) {
    return done(null, false);
  }
  if (!bcryptjs.compareSync(password, user.password_hash)) {
    return done(null, false);
  }
  return done(null, user);
}));
passport.serializeUser(function(user, done) {
  done(null, user._id);
});
passport.deserializeUser(function(id, done) {
  try {
    done(null, users.getUserById(id));
  } catch (err) {
    done(err);
  }
});

/**
 * BasicStrategy
 *
 * This strategy is  used to authenticate registered OAuth clients.  They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens. While this approach is not recommended by
 * the specification, in practice it is quite common.
 */
passport.use(new BasicStrategy(
    function(username, password, done) {
      let client;
      try {
        client = clients.getClient(username);
      } catch (err) {
        return done(err);
      }
      if (!client) {
        return done(null, false);
      }
      // vulnerability: this function MUST implement rate limiting
      // to protect against bruteforce attacks - RFC6749#section-2.3.1
      if (client.client_secret !== password) {
        return done(null, false);
      }
      return done(null, client);
    }
));

passport.use(new ClientPasswordStrategy(
    function(clientID, clientSecret, done) {
      let client;
      try {
        client = clients.getClient(clientID);
      } catch (err) {
        return done(err);
      }
      if (!client) {
        return done(null, false);
      }
      // vulnerability: this function MUST implement rate limiting
      // to protect against bruteforce attacks - RFC6749#section-2.3.1
      if (client.client_secret !== clientSecret) {
        return done(null, false);
      }
      return done(null, client);
    }
));

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate either users or clients based on an
 * access token (aka a bearer token).  If a user, they must have previously
 * authorized a client application, which is issued an access token to make
 * requests on behalf of the authorizing user.
 */
passport.use(new BearerStrategy(
    function(accessToken, done) {
      // insecure: logs access token
      console.log(accessToken);
      let token;
      try {
        token = oauth.getAccessToken(accessToken);
      } catch (err) {
        return done(err);
      }
      // vulnerability: logs access token
      console.log('TOKEN: ' + JSON.stringify(token));
      if (!token) {
        return done(null, false);
      }
      // check expiration
      if (oauth.isExpired(token)) {
        return done(null, false);
      }

      // userid in token
      if (token.user_id != null) {
        let user;
        try {
          user = users.getUserById(token.user_id);
        } catch (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false);
        }
        let info = {scope: token.scope};
        done(null, user, info);
      } else {
        // The request came from a client only since userID is null
        // therefore the client is passed back instead of a user
        let client;
        try {
          client = clients.getClient(token.client_id);
        } catch (err) {
          return done(err);
        }
        if (!client) {
          return done(null, false);
        }
        let info = {scope: token.scope};
        done(null, client, info);
      }
    }
));

/**
 * Either logged in via the connect middlewere or via a bearer token :)
 * @param {*} req request
 * @param {*} res response
 * @param {*} next next middleware
 */
function ensureLoggedInApi(req, res, next) {
  console.log('ensuredloggedin');
  if (req.query.access_token || req.headers['Authorization']) {
    isBearerAuthenticated(req, res, next);
  } else {
    login.ensureLoggedIn()(req, res, next);
  }
}

/**
 * ensure scope
 * @param {*} scope to be enforced
 * @return {*} result of next middleware
 */
function ensureScope(scope) {
  return ensureScope[scope] || (ensureScope[scope] = function(req, res, next) {
    // request not made via oauth
    if (!req.authInfo || !req.authInfo.scope) {
      return next();
    }
    // if the user did not set a scope, then req.authInfo.scope is *
    // if the requirement is no scope, then scope is *
    if (req.authInfo.scope === '*' || scope === '*') {
      return next();
    }
    reqscope = req.authInfo.scope.split(',');
    if (reqscope.indexOf(scope) <= -1) {
      return res.status(403).end('Forbidden');
    }
    return next();
  });
}

isBearerAuthenticated = passport.authenticate('bearer', {session: false});

exports = module.exports = {
  isClientAuthenticated: passport.authenticate(
      ['basic', 'oauth2-client-password'],
      {session: false}
  ),
  isBearerAuthenticated: isBearerAuthenticated,
  isLocalAuthenticated: passport.authenticate(
      'local',
      {
        successReturnToOrRedirect: '/',
        failureRedirect: '/login',
      }
  ),
  ensureLoggedIn: ensureLoggedInApi,
  ensureScope: ensureScope,
};
