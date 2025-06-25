// app.js
const express       = require('express');
const urlModule     = require('url');
const querystring   = require('querystring');
const Unblocker     = require('unblocker');
const { Transform } = require('stream');
const youtube       = require('unblocker/examples/youtube/youtube.js');

const app = express();

//─── Google Analytics を埋め込むヘルパー ─────────────────────────
const GA_ID = process.env.GA_ID || null;
function addGa(html) {
  if (!GA_ID) return html;
  const ga = [
    '<script type="text/javascript">',
    '  var _gaq = [];',
    `  _gaq.push(['_setAccount', '${GA_ID}']);`,
    '  _gaq.push([\'_trackPageview\']);',
    '  (function() {',
    "    var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;",
    "    ga.src = (document.location.protocol === 'https:' ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';",
    "    var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);",
    '  })();',
    '</script>'
  ].join('\n');
  return html.replace('</body>', ga + '\n</body>');
}

function googleAnalyticsMiddleware(data) {
  if (data.contentType === 'text/html') {
    data.stream = data.stream.pipe(new Transform({
      decodeStrings: false,
      transform(chunk, enc, next) {
        this.push(addGa(chunk.toString()));
        next();
      }
    }));
  }
}

//─── Unblocker 設定 ───────────────────────────────────────────
const unblockerConfig = {
  prefix: '/proxy/',
  requestMiddleware:  [ youtube.processRequest ],
  responseMiddleware: [ googleAnalyticsMiddleware ],
};
const unblocker = new Unblocker(unblockerConfig);

//─── 単純シーザー復号（全文字 code-1） ────────────────────────
function caesarDecrypt(str) {
  return Array.from(str).map(c =>
    String.fromCharCode(c.charCodeAt(0) - 1)
  ).join('');
}

//─── 事前復号ミドルウェア ─────────────────────────────────────
app.use((req, res, next) => {
  const prefix = unblockerConfig.prefix;
  if (req.url.startsWith(prefix)) {
    // /proxy/{encryptedUrl} の {encryptedUrl} 部分を取り出して復号
    const encrypted = decodeURIComponent(req.url.slice(prefix.length));
    const decrypted = caesarDecrypt(encrypted);
    // 復号した文字列を再設定
    req.url = prefix + decrypted;
  }
  next();
});

//─── Unblocker を挟む位置にこそ「app.use(unblocker)」────────────────
app.use(unblocker);

//─── 静的ファイル配信 ─────────────────────────────────────────
app.use('/', express.static(__dirname + '/public'));

//─── JS無効時のリダイレクト用（暗号化して /proxy/ へ）──────────
app.get('/no-js', (req, res) => {
  // クエリ ?url=... から取り出す
  const site = querystring.parse(urlModule.parse(req.url).query).url || '';
  // シーザー暗号化（全文字 code+1）
  const encrypted = Array.from(site).map(c =>
    String.fromCharCode(c.charCodeAt(0) + 1)
  ).join('');
  // URL エンコードして /proxy/ へ飛ばす
  res.redirect(unblockerConfig.prefix + encodeURIComponent(encrypted));
});

//─── サーバ起動 & WebSocket（Upgrade）────────────────────────
const PORT = process.env.PORT || process.env.VCAP_APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`node-unblocker listening on http://localhost:${PORT}/`);
}).on('upgrade', unblocker.onUpgrade);
