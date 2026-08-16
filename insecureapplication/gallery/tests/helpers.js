// Shared helpers for the gallery/photoprint integration test suites
// (integration.oauth.test.js, integration.pocs.test.js). Node built-ins
// only (fetch, URLSearchParams) -- no devDependencies.
//
// Run against a real, already-running stack:
//   cd insecureapplication
//   docker compose down
//   CLIENT_ID=photoprint CLIENT_SECRET=secret docker compose up -d --build gallery mongodb mongoseed photoprint
//   cd gallery
//   GALLERY_URL=http://localhost:3005 PHOTOPRINT_URL=http://localhost:3000 \
//     CLIENT_ID=photoprint CLIENT_SECRET=secret node --test tests/
//
// A shell with stale GALLERY_URL/PHOTOPRINT_URL/CLIENT_ID/CLIENT_SECRET
// exported will silently override the intended defaults for both the
// `docker compose` variable substitution above AND this file's env
// reads -- always pass them explicitly.

const GALLERY = process.env.GALLERY_URL || 'http://localhost:3005';
const PHOTOPRINT = process.env.PHOTOPRINT_URL || 'http://localhost:3000';
const CLIENT_ID = process.env.CLIENT_ID || 'photoprint';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'secret';
const MALICIOUS_CLIENT_ID = process.env.MALICIOUS_CLIENT_ID || 'maliciousclient';
const MALICIOUS_CLIENT_SECRET = process.env.MALICIOUS_CLIENT_SECRET || 'secret';
const REDIRECT_URI = process.env.PHOTOPRINT_CALLBACK || `${PHOTOPRINT}/callback`;

function makeJar() {
  const cookies = new Map();
  return {
    header() {
      return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    },
    capture(res) {
      for (const raw of res.headers.getSetCookie ? res.headers.getSetCookie() : []) {
        const [pair] = raw.split(';');
        const eq = pair.indexOf('=');
        cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
    },
  };
}

async function fetchNoRedirect(jar, url, options = {}) {
  const res = await fetch(url, {
    ...options,
    redirect: 'manual',
    headers: {...(options.headers || {}), Cookie: jar.header()},
  });
  jar.capture(res);
  return res;
}

async function login(jar, username = 'koen', password = 'password') {
  const res = await fetchNoRedirect(jar, `${GALLERY}/login`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({username, password}),
  });
  if (res.status !== 302) {
    throw new Error(`login(${username}) expected 302, got ${res.status}`);
  }
  return res;
}

// Registers a brand-new gallery user (random username) with an empty photo
// gallery, and returns a jar already logged in as them (registration
// auto-authenticates, see controllers/usercontroller.js's createProfile).
async function registerFreshUser(jar) {
  const username = `poctest_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const res = await fetchNoRedirect(jar, `${GALLERY}/users`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      username,
      password: 'testpass123',
      passwordrepeat: 'testpass123',
      email: `${username}@example.com`,
    }),
  });
  if (res.status !== 302) {
    throw new Error(`registerFreshUser expected 302, got ${res.status}`);
  }
  return username;
}

// Drives GET /oauth/authorize -> (dialog) -> POST /oauth/authorize/decision
// and returns the decision response (a redirect back to redirect_uri).
async function authorize(jar, responseType, extra = {}) {
  const authURL = `${GALLERY}/oauth/authorize?` + new URLSearchParams({
    response_type: responseType,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'view_gallery',
    state: 's1',
    ...extra,
  });
  const dialogRes = await fetchNoRedirect(jar, authURL);

  if (dialogRes.status === 302) {
    // response_type was rejected before the dialog (invalid_request /
    // unsupported_response_type) -- nothing to decide.
    return dialogRes;
  }
  if (dialogRes.status !== 200) {
    throw new Error(`authorize dialog expected 200, got ${dialogRes.status}`);
  }
  const html = await dialogRes.text();
  const tx = /name="transaction_id"[^>]*value="([^"]*)"/.exec(html);
  if (!tx) {
    throw new Error('transaction_id not found in dialog HTML');
  }

  return fetchNoRedirect(jar, `${GALLERY}/oauth/authorize/decision`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      transaction_id: tx[1],
      scope: extra.scope || 'view_gallery',
      allow: 'Allow',
    }),
  });
}

// Full happy-path helper: log in (or register a fresh user) + authorize +
// decision, returning the resulting authorization code.
async function getAuthorizationCode(jar, extra = {}) {
  const res = await authorize(jar, 'code', extra);
  const {params} = locationParams(res);
  const code = params.get('code');
  if (!code) {
    throw new Error(`no code in redirect: ${res.headers.get('location')}`);
  }
  return code;
}

async function exchangeCode(code, {clientId = CLIENT_ID, clientSecret = CLIENT_SECRET, redirectUri = REDIRECT_URI} = {}) {
  const res = await fetch(`${GALLERY}/oauth/token`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
    }),
  });
  return res;
}

function locationParams(res) {
  const loc = res.headers.get('location');
  if (!loc) {
    throw new Error('expected a Location header');
  }
  const sepIndex = Math.min(
      ...['?', '#'].map((c) => (loc.includes(c) ? loc.indexOf(c) : Infinity)),
  );
  if (!Number.isFinite(sepIndex)) {
    throw new Error(`redirect has neither ? nor #: ${loc}`);
  }
  return {
    fragment: loc[sepIndex] === '#',
    params: new URLSearchParams(loc.slice(sepIndex + 1)),
    raw: loc,
  };
}

module.exports = {
  GALLERY, PHOTOPRINT, CLIENT_ID, CLIENT_SECRET,
  MALICIOUS_CLIENT_ID, MALICIOUS_CLIENT_SECRET, REDIRECT_URI,
  makeJar, fetchNoRedirect, login, registerFreshUser, authorize,
  getAuthorizationCode, exchangeCode, locationParams,
};
