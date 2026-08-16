// Integration safety net for insecureapplication/gallery, written ahead of
// the Node 8 -> Node 22+ base image bump so the OAuth flows (including the
// response_type=token/"code token" grants added in
// controllers/oauthcontroller.js, and the well-known/introspection
// endpoints) can be re-run unchanged before and after to confirm nothing
// regressed. See helpers.js for how to run this against a live stack.

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  GALLERY, CLIENT_ID, REDIRECT_URI,
  makeJar, fetchNoRedirect, login, authorize, exchangeCode, locationParams,
} = require('./helpers');

test('authorization code flow (baseline, unaffected by the grant additions)', async (t) => {
  const jar = makeJar();
  await login(jar);

  const res = await authorize(jar, 'code');
  const {fragment, params} = locationParams(res);
  assert.equal(fragment, false, 'code flow must use the query string');
  assert.equal(params.get('state'), 's1');
  const code = params.get('code');
  assert.ok(code, 'expected a code');

  const tokenRes = await exchangeCode(code);
  assert.equal(tokenRes.status, 200);
  const tok = await tokenRes.json();
  assert.ok(tok.access_token, 'expected an access_token in the exchange response');

  const photosRes = await fetch(`${GALLERY}/photos/koen?access_token=${tok.access_token}`, {
    headers: {Accept: 'application/json'},
  });
  assert.equal(photosRes.status, 200);
  const photos = await photosRes.json();
  assert.ok(Array.isArray(photos.images) && photos.images.length >= 2,
      'expected koen\'s seeded photos');
});

test('response_type=token issues an implicit grant via the fragment, no refresh_token', async (t) => {
  const jar = makeJar();
  await login(jar);

  const res = await authorize(jar, 'token', {scope: 'view_gallery offline_access'});
  const {fragment, params} = locationParams(res);
  assert.equal(fragment, true, 'implicit grant must use the fragment');
  assert.equal(params.get('state'), 's1');
  assert.ok(params.get('access_token'), 'expected an access_token');
  assert.equal(params.get('code'), null, 'implicit grant must not include a code');
  assert.equal(params.get('refresh_token'), null,
      'RFC 6749 §4.2.2: implicit grant must never include a refresh_token, even with offline_access scope');
  assert.equal(params.get('token_type'), 'Bearer');

  const photosRes = await fetch(`${GALLERY}/photos/koen?access_token=${params.get('access_token')}`, {
    headers: {Accept: 'application/json'},
  });
  assert.equal(photosRes.status, 200, 'the implicit-grant token must actually work at the resource server');
});

test('response_type=code token issues both a code and an access_token via the fragment', async (t) => {
  const jar = makeJar();
  await login(jar);

  const res = await authorize(jar, 'code token');
  const {fragment, params} = locationParams(res);
  assert.equal(fragment, true, 'hybrid grant must use the fragment');
  assert.ok(params.get('code'), 'expected a code');
  assert.ok(params.get('access_token'), 'expected an access_token');
  assert.equal(params.get('refresh_token'), null);
});

test('missing response_type -> invalid_request redirect (not a raw 4xx/5xx page)', async (t) => {
  const jar = makeJar();
  await login(jar);

  const res = await authorize(jar, '');
  assert.equal(res.status, 302);
  const {fragment, params} = locationParams(res);
  assert.equal(fragment, false);
  assert.equal(params.get('error'), 'invalid_request');
  assert.equal(params.get('state'), 's1');
});

test('unsupported response_type -> unsupported_response_type redirect', async (t) => {
  const jar = makeJar();
  await login(jar);

  const res = await authorize(jar, 'id_token');
  assert.equal(res.status, 302);
  const {params} = locationParams(res);
  assert.equal(params.get('error'), 'unsupported_response_type');
});

test('denying an implicit grant request returns access_denied via the fragment', async (t) => {
  const jar = makeJar();
  await login(jar);

  const dialogRes = await fetchNoRedirect(jar, `${GALLERY}/oauth/authorize?` + new URLSearchParams({
    response_type: 'token',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'view_gallery',
    state: 's1',
  }));
  const html = await dialogRes.text();
  const tx = /name="transaction_id"[^>]*value="([^"]*)"/.exec(html);

  const res = await fetchNoRedirect(jar, `${GALLERY}/oauth/authorize/decision`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({transaction_id: tx[1], cancel: 'Deny'}),
  });
  const {fragment, params} = locationParams(res);
  assert.equal(fragment, true);
  assert.equal(params.get('error'), 'access_denied');
});

test('.well-known/oauth-authorization-server and openid-configuration are served and now honestly advertise code/token/code token', async (t) => {
  for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']) {
    const res = await fetch(`${GALLERY}${path}`);
    assert.equal(res.status, 200, path);
    const meta = await res.json();
    assert.ok(meta.token_endpoint.endsWith('/token'), `${path} token_endpoint`);
    assert.deepEqual(
        [...meta.response_types_supported].sort(),
        ['code', 'code token', 'token'].sort(),
        `${path} response_types_supported`,
    );
    // Load-bearing claim this whole test file exists to keep honest: every
    // advertised response_type must actually work (see the tests above).
  }
});

test('GET /token/introspect reports a live access_token', async (t) => {
  const jar = makeJar();
  await login(jar);
  const code = await (async () => {
    const res = await authorize(jar, 'code');
    return locationParams(res).params.get('code');
  })();
  const tokenRes = await exchangeCode(code);
  const tok = await tokenRes.json();

  const res = await fetch(`${GALLERY}/token/introspect?access_token=${tok.access_token}`);
  assert.equal(res.status, 200);
  const info = await res.json();
  assert.equal(info.aud, CLIENT_ID);
  assert.equal(info.azp, CLIENT_ID);
  assert.equal(info.name, 'koen');
});
