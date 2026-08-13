const express = require('express');
const expressSession = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');
const oauth2 = require('simple-oauth2');
const gallery = require('./config/gallery.json');
const RestClient = require('node-rest-client').Client;

let galleryConfig = JSON.parse(JSON.stringify(gallery));
if (process.env.GALLERY_URL) {
  galleryConfig.oauth.auth.tokenHost = process.env.GALLERY_URL;
}
if (process.env.CLIENT_ID) {
  galleryConfig.oauth.client.id = process.env.CLIENT_ID;
}
if (process.env.CLIENT_SECRET) {
  galleryConfig.oauth.client.secret = process.env.CLIENT_SECRET;
}

let client = oauth2.create(galleryConfig.oauth);
let app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(expressSession({
  secret: process.env.SESSION_SECRET || 'changethistoconfigfile', // externalized via env
  resave: false,
  saveUninitialized: false,
}));

// view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// serve content from public directory
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function(req, res) {
  res.render('index', {});
});

app.post('/photoprint', function(req, res) {
  let redirectUri = req.protocol + '://' + req.get('Host') + '/callback';
  let authorizationUrl = client.authorizationCode.authorizeURL({
    redirect_uri: redirectUri,
    scope: gallery.scope,
  });

  let browserHost = process.env.GALLERY_BROWSER_URL || (req.protocol + '://' + req.get('Host').replace(/^photoprint/, 'gallery').replace(/:3000$/, ':3005'));
  if (process.env.GALLERY_BROWSER_URL) {
    authorizationUrl = authorizationUrl.replace(galleryConfig.oauth.auth.tokenHost, process.env.GALLERY_BROWSER_URL);
  } else if (!req.get('Host').startsWith('photoprint:')) {
    // nip.io または localhost 等での自動置き換え
    authorizationUrl = authorizationUrl.replace(galleryConfig.oauth.auth.tokenHost, browserHost);
  }

  res.redirect(authorizationUrl);
});

app.get('/callback', function(req, res) {
  let code = req.query.code;
  console.log('code: ' + code);

  let redirectUri = req.protocol + '://' + req.get('Host') + '/callback';

  const tokenConfig = {
    code: code,
    redirect_uri: redirectUri,
  };
  client.authorizationCode.getToken(tokenConfig,
      function(error, result) {
        if (error) {
          return res.send('Access Token Error: ' + error.message);
        }
        let token = client.accessToken.create(result);
        console.log('Token: ' + JSON.stringify(token));
        // store token in session
        req.session.access_token = token.token.access_token;
        res.redirect('/selectphotos');
      }
  );
});

app.get('/selectphotos', function(req, res) {
  new RestClient().get(
      gallery.oauth.auth.tokenHost + gallery.photos + '?access_token=' +
          req.session.access_token, // url
      {headers: {'Accept': 'application/json'}},
      function(images, response) {
        req.session.images = images.images;
        return res.render('selectphotos', {
          images: images.images,
          basepath: gallery.oauth.auth.tokenHost + gallery.photos + '/',
        });
      }
  );
});

app.post('/confirm', function(req, res) {
  res.render('confirm');
});

app.post('/order', function(req, res) {
  let totalprice = 0;
  let price = 0.10;
  let selectedphotos = [];
  for (let photo in req.body) {
    if (photo != null && photo != undefined) {
      selectedphotos.push(req.session.images[photo]);
      totalprice += price;
    }
  }
  res.render('order', {
    selectedphotos: selectedphotos,
    totalprice: totalprice,
    price: price,
    basepath: gallery.oauth.auth.tokenHost + gallery.photos + '/',
  });
});

app.listen(3000, function() {
  console.log('Printing Application listening on http://localhost:3000');
});
