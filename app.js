// app.js
const express     = require('express');
const urlModule   = require('url');
const querystring = require('querystring');
const crypto      = require('crypto');
const Unblocker   = require('unblocker');
const youtube     = require('unblocker/examples/youtube/youtube.js');

const SECRET_KEY = Buffer.from(
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'hex'
);
const PREFIX = '/proxy/';

/**
 * 暗号化文字列 → プレーンテキスト URL
 */
function decryptPath(encrypted) {
  // URL-safe Base64 → 標準 Base64
  let b64 = encrypted.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const data = Buffer.from(b64, 'base64');
  const iv   = data.slice(0, 16);
  const ct   = data.slice(16);
  const dec  = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, iv);
  let plain = dec.update(ct, undefined, 'utf8');
  plain    += dec.final('utf8');
  return plain;
}

/**
 * プレーンテキスト URL → 暗号化文字列
 */
function encryptPath(urlStr) {
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
  const ctBuf  = Buffer.concat([cipher.update(urlStr, 'utf8'), cipher.final()]);
  const combined = Buffer.concat([iv, ctBuf]);
  let b64 = combined.toString('base64');
  // URL-safe に変換
  b64 = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return b64;
}

/**
 * /proxy/<暗号化 or 平文URL> を判別して復号 or 通過させる
 */
function decryptMiddleware(req, res, next) {
  if (!req.url.startsWith(PREFIX)) {
    return next();
  }
  // /proxy/ 以降を split
  const rest = req.url.slice(PREFIX.length);
  const [token, qs = ''] = rest.split('?');
  let originalUrl;

  // 平文の http:// または https:// で始まる場合はそのまま通す
  if (/^https?:\/\//i.test(token)) {
    originalUrl = token;
  }
  else {
    // 暗号化文字列として復号
    try {
      originalUrl = decryptPath(token);
    } catch (e) {
      return res.status(400).send('Invalid encrypted URL');
    }
  }

  // 再構築して次に渡す
  req.url = PREFIX + originalUrl + (qs ? '?' + qs : '');
  next();
}

const app = express();

// 1. 暗号化URLの復号化ミドルウェア
app.use(decryptMiddleware);

// 2. Unblocker: prefix=/proxy/
const unblocker = new Unblocker({
  prefix: PREFIX,
  requestMiddleware: [ youtube.processRequest ]
});
app.use(unblocker);

// 3. 静的ファイル提供
app.use('/', express.static(__dirname + '/public'));

// 4. no-js 対応：?url=<入力> → 暗号化してリダイレクト
app.get('/no-js', (req, res) => {
  const site = querystring.parse(
    urlModule.parse(req.url).query
  ).url;
  if (!site) {
    return res.redirect('/');
  }
  const enc = encryptPath(site);
  res.redirect(PREFIX + enc);
});

// 固定ポート 8080
const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}/`);
})
.on('upgrade', unblocker.onUpgrade);  // WebSocket 対応
