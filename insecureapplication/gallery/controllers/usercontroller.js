const util = require('./util');
const users = require('../db/users');
const passport = require('passport');
const bcryptjs = require('bcryptjs');

// vulnerability: user enumeration: user can get list of all user profiles
// by enumerating over req.params.name

/**
 * Returns the user profile
 * @param {*} req request
 * @param {*} res response
 */
function getProfile(req, res) {
  let userid = req.params.name;
  if (userid === 'me') {
    userid = req.user.username;
  }
  let founduser;
  try {
    founduser = users.getUserByUsername(userid);
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return renderUser(req, res, founduser);
}

/**
 * Creates a new user via passport local strategy
 * @param {*} req request
 * @param {*} res response
 */
function createProfile(req, res) {
  // vulnerability: vulnerable to username enumeration
  // - error message states when the user already exists
  // vulnerability: usernames of deleted users can be chosen
  let id;
  try {
    let hash = bcryptjs.hashSync(req.body.password, 10);
    id = users.createUser({
      username: req.body.username,
      name: req.body.username,
      email: req.body.email,
      passwordHash: hash,
    });
  } catch (err) {
    return util.renderError(req, res, err, 'register');
  }
  // log the newly-created user in directly (already-verified credentials,
  // no need to re-run them through the local strategy)
  req.login(users.getUserById(id), function(err) {
    if (err) {
      return util.renderError(req, res, err, 'register');
    }
    req.session.save(function(err) {
      if (err) {
        return util.renderError(req, res, err, 'register');
      }
      return res.redirect('/');
    });
  });
}

/**
 * Function to update the profile of a user
 * @param {*} req request
 * @param {*} res response
 */
function updateProfile(req, res) {
  // vulnerability: vulnerable to username enumeration -
  // error message states when the user already exists
  // vulnerability: usernames of deleted users can be chosen
  let userid = req.params.name;
  try {
    // vulnerability: mass assignment
    users.updateUserFields(userid, req.body);
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return util.renderMessage(req, res, null, 204);
}

/**
 * Function to delete a user
 * @param {*} req request
 * @param {*} res response
 */
function deleteProfile(req, res) {
  let userid = req.params.name;
  // vulnerability: usernames of deleted users can be chosen
  try {
    users.deleteUser(userid);
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return util.renderMessage(req, res, 'Successfully Deleted.', 200);
}

/**
 * Function to get users
 * @param {*} req request
 * @param {*} res response
 */
function getUsers(req, res) {
  let foundUsers;
  try {
    foundUsers = users.listUsers();
  } catch (err) {
    return util.renderError(req, res, err, 'error');
  }
  return renderUsers(req, res, foundUsers);
}

/**
 * Function to render users
 * @param {*} req request
 * @param {*} res response
 * @param {*} users users
 * @return {*} rendered users
 */
function renderUsers(req, res, users) {
  if (!users || users.length == 0) {
    return util.renderMessage(req, res, 'No Users Found.', 404);
  }
  return res.format({
    // if accept: text/html render a page
    'text/html': function() {
      res.render('users', {
        user: req.user,
        users: users,
      });
    },
    // if json: render a json response
    'application/json': function() {
      res.status(200).send({users});
    },
    // other formats are not supported
    'default': function() {
      res.status(406).send('Not Acceptable');
    },
  });
}

/**
 * Renders a given user
 * @param {*} req request
 * @param {*} res response
 * @param {*} founduser user
 * @return {*} rendered user
 */
function renderUser(req, res, founduser) {
  return res.format({
    // if accept: text/html render a page
    'text/html': function() {
      res.render('user', {
        user: req.user,
        founduser: founduser,
      });
    },
    // if json: render a json response
    'application/json': function() {
      res.status(200).send({founduser});
    },
    // other formats are not supported
    'default': function() {
      res.status(406).send('Not Acceptable');
    },
  });
}

exports = module.exports = {
  getProfile: getProfile,
  updateProfile: updateProfile,
  deleteProfile: deleteProfile,
  getUsers: getUsers,
  createProfile: createProfile,
};
