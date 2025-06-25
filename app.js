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
 * encrypted: URL-safe Base64 形式の暗号化済文字列
 * → 復号して元のプレーンテキスト URL を返す
 */
function decryptPath(encrypted) {
  // URL-safe → 標準 Base64
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
 * urlStr: プレーンテキスト URL
 * → 暗号化＋IV添付＋URL-safe Base64 文字列を返す
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
 * ミドルウェア：リクエスト URL が /proxy/<encrypted> なら先に復号
 */
function decryptMiddleware(req, res, next) {
  if (req.url.startsWith(PREFIX)) {
    // クエリ以降は切り離し
    const rest = req.url.slice(PREFIX.length);
    const [encPart, qs = ''] = rest.split('?');
    try {
      const originalUrl = decryptPath(encPart);
      // /proxy/ プレフィックスをつけて復号後 URL を挿入
      req.url = PREFIX + originalUrl + (qs ? '?' + qs : '');
    } catch (e) {
      return res.status(400).send('Invalid encrypted URL');
    }
  }
  next();
}

const app = express();
const unblocker = new Unblocker({
  prefix: PREFIX,
  requestMiddleware: [ youtube.processRequest ]
});

// 1) 暗号化 URL を復号
app.use(decryptMiddleware);

// 2) Unblocker がプロキシ
app.use(unblocker);

// 3) 静的ファイル
app.use('/', express.static(__dirname + '/public'));

// JS 無効ユーザー向け：no-js?url=... を受け取って暗号化 URL にリダイレクト
app.get('/no-js', (req, res) => {
  const site = querystring.parse(
    urlModule.parse(req.url).query
  ).url;
  if (!site) return res.redirect('/');
  const enc = encryptPath(site);
  res.redirect(PREFIX + enc);
});

// ポート固定（環境変数不使用）
const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}/`);
})
.on('upgrade', unblocker.onUpgrade);
