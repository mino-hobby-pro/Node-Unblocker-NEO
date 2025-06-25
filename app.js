// app.js
const express = require('express');
const url = require('url');
const querystring = require('querystring');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const Unblocker = require('unblocker');
const youtube = require('unblocker/examples/youtube/youtube.js');

const app = express();

// ── 暗号化設定 ──
const ALGORITHM = 'aes-256-cbc';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 必ず32バイト（＝64文字）の16進を設定
const IV_LENGTH = 16; // AES-CBCのIVは16バイト

// URLセーフBase64
function base64urlEncode(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// トークン → 元URL に復号
function decryptUrlToken(token) {
  const data = base64urlDecode(token);
  const iv = data.slice(0, IV_LENGTH);
  const encrypted = data.slice(IV_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

// ── Google Analytics 挿入ミドル ──
const GA_ID = process.env.GA_ID || null;
function addGa(html) {
  if (!GA_ID) return html;
  const ga = [
    "<script>",
    "  var _gaq = _gaq || [];",
    "  _gaq.push(['_setAccount','" + GA_ID + "']);",
    "  _gaq.push(['_trackPageview']);",
    "  (function(){",
    "    var ga=document.createElement('script');",
    "    ga.src=('https:'==document.location.protocol?'https://ssl':'http://www')+'.google-analytics.com/ga.js';",
    "    ga.async=true;",
    "    document.head.appendChild(ga);",
    "  })();",
    "</script>"
  ].join("\n");
  return html.replace('</body>', ga + '\n</body>');
}
function googleAnalyticsMiddleware(data) {
  if (data.contentType && data.contentType.includes('text/html')) {
    data.stream = data.stream.pipe(new Transform({
      decodeStrings: false,
      transform(chunk, enc, next) {
        this.push(addGa(chunk.toString()));
        next();
      }
    }));
  }
}

// ── 暗号化トークン復号ミドルウェア（unblockerより前にマウント） ──
app.use((req, res, next) => {
  if (!req.url.startsWith('/proxy/')) return next();
  // /proxy/<token>?<質問文字列> → token 部分だけ抜き出し
  const pathAndQs = req.url.slice('/proxy/'.length);
  const [token, qs] = pathAndQs.split('?');
  let original;
  try {
    original = decryptUrlToken(decodeURIComponent(token));
  } catch (e) {
    return res.status(400).send('無効な暗号化URLです');
  }
  // 復号後のURL（たとえば https://example.com/foo?bar）
  // を /proxy/ 以下に再構築
  req.url = '/proxy/' + original + (qs ? '?' + qs : '');
  next();
});

// ── Unblocker 設定 ──
const unblocker = new Unblocker({
  prefix: '/proxy/',
  requestMiddleware: [ youtube.processRequest ],
  responseMiddleware: [ googleAnalyticsMiddleware ]
});
app.use(unblocker);

// ── 静的ファイル ──
app.use('/', express.static(path.join(__dirname, 'public')));

// ── JS無効時フォールバック ──
app.get('/no-js', (req, res) => {
  const site = querystring.parse(url.parse(req.url).query).url;
  // ここは暗号化しない簡易版
  res.redirect('/proxy/' + encodeURIComponent(site));
});

// ── サーバー起動 ──
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Node Unblocker listening at http://localhost:${port}/`);
}).on('upgrade', unblocker.onUpgrade);
