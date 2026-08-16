const oauth2orize = require('oauth2orize');
const url = require('url');
const qs = require('querystring');

const clients = require('../db/clients');
const users = require('../db/users');
const oauth = require('../db/oauth');
const config = require('../config/config');

// oauth2orize's grant modules parse a space/comma-separated scope string
// into an array; SQLite bind parameters can't be arrays, so this joins it
// back into a comma-separated string for storage -- exactly what Mongoose
// did automatically when an array was assigned to a String-typed field.
function scopeToString(scope) {
  return Array.isArray(scope) ? scope.join(',') : scope;
}

// create OAuth 2.0 server
let server = oauth2orize.createServer();
// Register serialialization and deserialization functions.
// serialialization and deserialization functions.
//
// When a client redirects a user to an user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.
server.serializeClient(function(client, done) {
  return done(null, client.client_id);
});
server.deserializeClient(function(id, done) {
  try {
    return done(null, clients.getClient(id));
  } catch (err) {
    return done(err);
  }
});

// Register supported grant types.
// secure: scope is used
// More info: https://tools.ietf.org/html/rfc6819#section-5.1.5.1
// when not used: everything is allowed
server.grant(oauth2orize.grant.code({scopeSeperator: [' ', ',']}, grantcode));
// alternative
// server.grant(
//    oauth2orize.grant.authorizationCode(
//        {scopeSeperator: [' ', ',']}, grantcode
//    )
// );

// insecure: scope not used
// server.grant(oauth2orize.grant.code(grantcode));

// response_types_supported (see wellknown() below) has always advertised
// "token" and "code token" alongside "code", but until now no grant was
// ever registered for them, so oauth2orize's own request parser rejected
// both with an unhandled 501 unsupported_response_type -- the advertised
// support was never real. Registering these two closes that gap the same
// way insecureapplication-go/gallery-idp's grantAndRedirect does: neither
// grant restricts which client may request it (see PoC8 in
// doc/OAuth2_PoC_Verification_Report.md), and consistent with RFC 6749
// §4.2.2, the implicit grant never issues a refresh_token.
//
// Implicit Grant: response_type=token, access_token only, delivered via
// the redirect URI fragment.
server.grant(oauth2orize.grant.token({scopeSeperator: [' ', ',']}, granttoken));
// Hybrid grant: response_type=code token, both an authorization_code and
// an access_token, also delivered via the fragment. oauth2orize ships no
// bundled module for this (only lib/grant/code.js and lib/grant/token.js),
// so it's hand-rolled below as hybridGrant(), following the same
// request/response/error module shape as the bundled ones.
server.grant(hybridGrant(granthybrid));

// Exchange authorization codes for access tokens.
server.exchange(oauth2orize.exchange.authorizationCode(exchangecode));
// alternative:
// server.exchange(oauth2orize.exchange.code(exchangecode));

server.exchange(oauth2orize.exchange.refreshToken(exchangerefreshtoken));

/**
 * Makes an authorization decision
 * @param {*} req request
 * @param {*} done callback function
 * @return {*} result of invoking the callback function
 */
function decision(req, done) {
  // vulnerability when commented out: no scope is used
  // More info: https://tools.ietf.org/html/rfc6819#section-5.1.5.1
  return done(null, {scope: req.oauth2.req.scope});
  // return done(null);
}

//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

/**
 * Grants authorization code
 * @param {*} client client for which to grant the code
 * @param {*} redirectURI redirect uri at which to deliver the code
 * @param {*} user the suer for which to grant the code
 * @param {*} response response msg
 * @param {*} done callback function
 */
function grantcode(client, redirectURI, user, response, done) {
  // vulnerability: weak authorization codes
  let code = Math.floor(Math.random() * (100000-1) +1);
  try {
    oauth.createAuthCode(code, client.client_id, user._id, redirectURI, scopeToString(response.scope));
  } catch (err) {
    return done(err);
  }
  done(null, code);
}

/**
 * Grants an access token directly (Implicit Grant, response_type=token).
 * Mirrors grantcode() but skips the authorization_code step entirely, and
 * -- per RFC 6749 §4.2.2 -- never issues a refresh_token, since there is no
 * client authentication anywhere in this flow.
 * @param {*} client client for which to grant the token
 * @param {*} user the user for which to grant the token
 * @param {*} ares approved scope, as parsed from the original request
 * @param {*} done callback function
 */
function granttoken(client, user, ares, done) {
  // vulnerability: weak access tokens, same generator as grantcode/exchangecode
  let token = Math.floor(Math.random() * (100000-1) +1) + '';
  try {
    oauth.createAccessToken(token, client.client_id, user._id, scopeToString(ares.scope));
  } catch (err) {
    return done(err);
  }
  done(null, token);
}

/**
 * Grants both an authorization code and an access token
 * (response_type=code token). Mirrors grantcode() + granttoken() combined.
 * @param {*} client client for which to grant the code+token
 * @param {*} redirectURI redirect uri at which to deliver the code
 * @param {*} user the user for which to grant the code+token
 * @param {*} ares approved scope, as parsed from the original request
 * @param {*} done callback function
 */
function granthybrid(client, redirectURI, user, ares, done) {
  let code = Math.floor(Math.random() * (100000-1) +1);
  let token = Math.floor(Math.random() * (100000-1) +1) + '';
  let scope = scopeToString(ares.scope);
  try {
    oauth.createAuthCode(code, client.client_id, user._id, redirectURI, scope);
    oauth.createAccessToken(token, client.client_id, user._id, scope);
  } catch (err) {
    return done(err);
  }
  done(null, code, token);
}

/**
 * Encodes params into the URL fragment of txn.redirectURI and redirects
 * there. Authorization responses that carry a token are delivered this way
 * per RFC 6749 §4.2.2 -- oauth2orize ships this exact logic for its bundled
 * "token" grant (lib/response/fragment.js), but doesn't expose it publicly,
 * so hybridGrant() below needs its own copy.
 * @param {*} txn oauth2orize transaction (req.oauth2)
 * @param {*} res response
 * @param {*} params params to encode into the fragment
 */
function respondFragment(txn, res, params) {
  let parsed = url.parse(txn.redirectURI);
  parsed.hash = qs.stringify(params);
  res.redirect(url.format(parsed));
}

/**
 * Builds an oauth2orize grant module for response_type=code token. There is
 * no bundled equivalent (oauth2orize only ships lib/grant/code.js and
 * lib/grant/token.js), so this follows the same
 * {name, request, response, error} shape those two use, registered via
 * `server.grant(hybridGrant(issue))`.
 * @param {*} issue grant callback: (client, redirectURI, user, ares, done)
 * @return {*} oauth2orize grant module
 */
function hybridGrant(issue) {
  function request(req) {
    let clientID = req.query.client_id;
    let redirectURI = req.query.redirect_uri;
    let scope = req.query.scope;
    let state = req.query.state;
    if (!clientID) {
      throw new oauth2orize.AuthorizationError(
          'Missing required parameter: client_id', 'invalid_request');
    }
    if (scope) {
      let separated = scope.split(' ');
      if (separated.length == 1) {
        separated = scope.split(',');
      }
      scope = separated.length > 1 ? separated : [scope];
    }
    return {clientID: clientID, redirectURI: redirectURI, scope: scope, state: state};
  }

  function response(txn, res, complete, next) {
    if (!txn.res.allow) {
      let params = {error: 'access_denied'};
      if (txn.req && txn.req.state) {
        params.state = txn.req.state;
      }
      return respondFragment(txn, res, params);
    }
    issue(txn.client, txn.redirectURI, txn.user, txn.res, function(err, code, accessToken) {
      if (err) {
        return next(err);
      }
      let params = {code: code, access_token: accessToken, token_type: 'Bearer'};
      if (txn.req && txn.req.state) {
        params.state = txn.req.state;
      }
      complete(function(err) {
        if (err) {
          return next(err);
        }
        return respondFragment(txn, res, params);
      });
    });
  }

  function errorHandler(err, txn, res, next) {
    let params = {error: err.code || 'server_error'};
    if (err.message) {
      params.error_description = err.message;
    }
    if (txn.req && txn.req.state) {
      params.state = txn.req.state;
    }
    return respondFragment(txn, res, params);
  }

  // A string (not an array) is required here: oauth2orize's UnorderedList
  // splits a string on spaces internally, but server.grant()'s "sig:
  // grant(mod)" branch re-checks `typeof mod.name == 'object'` on whatever
  // is passed through -- and an array *is* typeof 'object' in JS, so an
  // array name would silently be mistaken for another module object and
  // never get registered.
  return {name: 'code token', request: request, response: response, error: errorHandler};
}

/**
 * Rejects a request whose response_type isn't exactly "code", "token", or
 * "code token" (in either order) before oauth2orize ever sees it.
 * oauth2orize's own request parser already rejects unrecognized
 * response_type values, but does so by calling next(err) with no
 * error-handling middleware registered on this route (see routes/oauth.js),
 * which surfaces as a raw 501/400 framework error page instead of the RFC
 * 6749 §4.1.2.1 / §4.2.2.1 redirect (invalid_request /
 * unsupported_response_type) a client actually expects.
 * @param {*} req request
 * @param {*} res response
 * @param {*} next next middleware
 * @return {*} result of invoking next(), or the error redirect
 */
function validateResponseType(req, res, next) {
  let responseType = req.query.response_type;
  let redirectURI = req.query.redirect_uri;
  let state = req.query.state;

  let errorCode = null;
  if (!responseType) {
    errorCode = 'invalid_request';
  } else {
    let parts = responseType.split(' ').filter(Boolean);
    let allSupported = parts.length > 0 && parts.every(function(p) {
      return p === 'code' || p === 'token';
    });
    if (!allSupported) {
      errorCode = 'unsupported_response_type';
    }
  }
  if (!errorCode) {
    return next();
  }

  let params = {error: errorCode};
  if (state) {
    params.state = state;
  }
  let wantsToken = (responseType || '').split(' ').indexOf('token') !== -1;
  let separator = wantsToken ? '#' : '?';
  return res.redirect(redirectURI + separator + qs.stringify(params));
}

// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.
/**
 * Token endpoint
 * @param {*} client client ID
 * @param {*} code authorization code
 * @param {*} redirectURI redirect URI
 * @param {*} done callback function
 */
function exchangecode(client, code, redirectURI, done) {
  // insecure: logging of authorization codes
  console.log('Authorization Code: ' + code);

  // vulnerability: authorization code can be used more than once
  // vulnerability: expiry of authorization code is not validated
  // vulnerability: redirectURI is not validated (open redirect)
  let authCode;
  try {
    authCode = oauth.getAuthCode(code);
  } catch (err) {
    return done(new oauth2orize.TokenError('Error while accessing the token database.', 'server_error'));
  }
  if (authCode == null) {
    return done(new oauth2orize.AuthorizationError('Invalid Authorization Code.', 'access_denied'));
  }

  // vulnerability: weak access tokens
  let token = Math.floor(Math.random() * (100000-1) +1);
  // vulnerability: the token is logged
  console.log('Access Token: ' + token);
  let refreshtoken = Math.floor(Math.random() * (100000-1) +1) + '';
  let needsrefresh = authCode.scope != null && authCode.scope.includes('offline_access');

  try {
    oauth.createAccessToken(token, authCode.client_id, authCode.user_id, authCode.scope);
    if (needsrefresh) {
      oauth.createRefreshToken(refreshtoken, authCode.client_id, authCode.user_id, authCode.scope);
    }
  } catch (err) {
    return done(new oauth2orize.TokenError('Error while accessing the token database.', 'server_error'));
  }
  return done(null, token, needsrefresh ? refreshtoken : null);
}

/**
 * Exchanges a refresh token for an access token
 * @param {*} client client ID
 * @param {*} mytoken refresh token
 * @param {*} scope scope required
 * @param {*} done callback invoked when done
 */
function exchangerefreshtoken(client, mytoken, scope, done) {
  // insecure: logs refresh tokens
  console.log('Refresh Token: ' + mytoken);
  // insecure: not a strong access token
  let accesstoken = Math.floor(Math.random() * (100000-1) +1) + '';

  // NOTE: the original here used a raw MongoClient with a hand-built
  // `$where` query (`this.token == ` + mytoken, string-concatenated
  // straight from the request) as a NoSQL-injection demo -- sending
  // refresh_token=this.token made the predicate always-true and dumped
  // every refresh token in the collection. SQLite has no equivalent to
  // $where's arbitrary-server-side-JS predicate, so that demo doesn't
  // port; see insecureapplication-go/z-ai/gallery-sqlite-plan.md and
  // insecureapplication/attacker/app.js's now-commented-out /hashtokens.
  // What's left is a plain, still-vulnerable lookup: PoC6 (refresh token
  // not bound to client) is unaffected.
  let refreshToken;
  try {
    refreshToken = oauth.getRefreshToken(mytoken);
  } catch (err) {
    return done(new oauth2orize.TokenError('Error while accessing the token database.', 'server_error'));
  }
  if (refreshToken == null) {
    return done(new oauth2orize.AuthorizationError('Invalid Refresh Token.', 'access_denied'));
  }
  try {
    // insecure: the new access token inherits whatever scope the refresh
    // token carried, regardless of which client is redeeming it (PoC6).
    oauth.createAccessToken(accesstoken, refreshToken.client_id, refreshToken.user_id, refreshToken.scope);
  } catch (err) {
    return done(new oauth2orize.TokenError('Error while accessing the token database.', 'server_error'));
  }
  return done(null, accesstoken, null);
}

// user authorization endpoint
//
// The validate callback is responsible for validating the client making the
// authorization request.  Once validated, the `done` callback must be
// invoked with a `client` instance, as well as the `redirectURI` to which the
// user will be redirected after an authorization decision is obtained.
/**
 * Validate authorization
 * @param {*} clientID client ID
 * @param {*} redirectURI redirect URI
 * @param {*} done callback function
 */
function authorizationValidate(clientID, redirectURI, done) {
  let client;
  try {
    client = clients.getClient(clientID);
  } catch (err) {
    return done(err);
  }
  // vulnerability: redirectURI is not validated
  if (client != null) {
    return done(null, client, redirectURI);
  }
  return done(null, false);
}

/**
 * Auto-approve function
 * @param {*} client client id
 * @param {*} user user
 * @param {*} done callback function
 * @return {*} returns the result of the callback function
 */
function authorizationAutoapprove(client, user, done) {
  if (client.trusted) {
    // Auto-approve
    return done(null, true);
  }
  // Otherwise ask user
  done(null, false);
}

/**
 * Renders the dialog
 * @param {*} req request
 * @param {*} res response
 */
function renderdialog(req, res) {
  let scopeMap = config.scopemap;
  res.render('dialog', {
    transactionID: req.oauth2.transactionID,
    user: req.user,
    client: req.oauth2.client,
    scopeMap: scopeMap,
    scope: req.oauth2.req.scope,
  }
  );
}

/**
 * Returns information about the access token.
 * @param {*} req request
 * @param {*} res response
 */
function tokeninfo(req, res) {
  let accessToken = req.query.access_token;
  let token;
  try {
    token = oauth.getAccessToken(accessToken);
  } catch (err) {
    res.status(400);
    return res.json({error: 'invalid_token'});
  }
  if (token == null) {
    res.status(400);
    return res.json({error: 'invalid_token'});
  }
  let creationDate = Math.floor(oauth.parseCreatedAt(token.created_at));
  const expirationLeft = Math.floor(
      (
        // creation date in seconds since epoch
        creationDate
        // expiry time in seconds; e.g. 3600
        + token.expires_in
        // current time in seconds since epoch
        - Math.floor(Date.now()/1000)
      )
  );
  let client;
  try {
    client = clients.getClient(token.client_id);
  } catch (err) {
    res.status(400);
    return res.json({error: 'invalid_token'});
  }
  if (client == null) {
    res.status(400);
    return res.json({error: 'invalid_token'});
  }
  let user;
  try {
    user = users.getUserById(token.user_id);
  } catch (err) {
    res.status(400);
    return res.json({error: 'invalid_token'});
  }
  if (user == null) {
    res.status(400);
    return res.json({error: 'invalid_token'});
  }
  return res.json({
    iss: req.headers.host, // insecure: JSON injection
    sub: token.user_id,
    aud: client.client_id,
    azp: client.client_id,
    exp: expirationLeft,
    iat: creationDate,
    name: user.username,
  });
}

/**
 * See  https://connect2id.com/products/server/docs/api/discovery#oauth-config
 * @param {*} req request
 * @param {*} res response
 * @return {*} configuration
 */
function wellknown(req, res) {
  // pre-existing bug fix: these were unqualified assignments (no
  // let/const), which silently tried to reassign the module-level
  // `const config = require('../config/config')` imported at the top of
  // this file -- every call threw "TypeError: Assignment to constant
  // variable" and this endpoint 500'd unconditionally. Fixed by scoping
  // these locally and renaming the response object so it no longer shadows
  // the import; no behavioral change to the (still-vulnerable) content.
  let host = req.headers.host;
  let protocol = req.protocol;
  let fullhost = protocol + '://' + host;
  let wellKnownConfig = {
    'issuer': fullhost, // insecure: JSON injection
    'token_endpoint': fullhost+'/token',
    'introspection_endpoint': fullhost+'/token/introspect',
    'revocation_endpoint': '',
    'authorization_endpoint': fullhost+'/login',
    'userinfo_endpoint': '',
    'registration_endpoint': '',
    'jwks_uri': '',
    'scopes_supported': ['profile', 'view_gallery', 'offline_access'],
    'response_types_supported': ['code', 'token', 'code token'],
    'response_modes_supported': ['query', 'form_post'],
    'grant_types_supported': ['authorization_code', 'refresh_token'],
    'code_challenge_methods_supported': [],
    'acr_values_supported': [],
    'subject_types_supported': ['public'],
    'token_endpoint_auth_methods_supported': [
      'client_secret_basic',
      'client_secret_post',
    ],
    'token_endpoint_auth_signing_alg_values_supported': [],
    'id_token_signing_alg_values_supported': [],
    'userinfo_signing_alg_values_supported': [],
    'display_values_supported': ['page'],
    'claim_types_supported': ['normal'],
    'claims_supported': ['sub', 'iss', 'name'],
    'ui_locales_supported': ['en'],
    'claims_parameter_supported': true,
    'request_parameter_supported': false,
    'request_uri_parameter_supported': false,
    'require_request_uri_registration': false,
  };
  return res.json(wellKnownConfig);
}

exports = module.exports = {
  decision: server.decision(decision),
  renderdialog: renderdialog,
  validateResponseType: validateResponseType,
  authorization: server.authorization(
      authorizationValidate,
      authorizationAutoapprove
  ),
  token: server.token(),
  errorHandler: server.errorHandler(),
  tokeninfo: tokeninfo,
  wellknown: wellknown,
};
