// This is the entry point of an insecure Gallery application.
// It is an express application
const express = require('express');
const expressSession = require('express-session');
// that uses bodyarser and cookieParser to parse requests
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
// stores data in SQLite (node:sqlite, built into Node -- no separate DB
// server, no native npm build step). See
// insecureapplication-go/z-ai/gallery-sqlite-plan.md for why this replaced
// MongoDB/Mongoose.
const db = require('./db/db');
const seed = require('./db/seed');
// authentication happens with passport and passport strategies
const passport = require('passport');
// during dev, it uses the errorhandler package. Erros are logged  with morgan.
const logger = require('morgan');
const errorhandler = require('errorhandler');
// an utility class to load static files in an OS independent way.
let path = require('path');

// our configuration file
const config = require('./config/config.json');

// initialize the SQLite database: open (creating the file if needed), run
// migrations, then self-seed the same fixture data mongo-seed used to
// restore on every container start.
db.open(process.env.SQLITE_DB_PATH || path.join(__dirname, config.sqlite.file));
db.runMigrations();
seed.seed(path.join(__dirname, 'public', 'uploads'));

// initialize express
let app = express();

// intialize the view engine used by express
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// initialize the bodyparsers and session mechanism
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(expressSession({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
}));
// initialize passport
app.use(passport.initialize());
app.use(passport.session());

// pretty print json results
app.set('json spaces', 2);

// serve content from public directory
app.use(express.static(path.join(__dirname, 'public')));

// include all the routes
const routes = require('./routes/index');
app.use('/', routes);

// error handling and logging
app.use(logger('dev')); // development logging
app.use(errorhandler({log: true}));

// listen to requests on a given port
app.listen(3005, function() {
  console.log('Gallery Application listening on '+
    this.address().address +':'+this.address().port);
});
module.exports = app;
