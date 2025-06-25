// app.js
const express       = require('express');
const urlModule     = require('url');
const querystring   = require('querystring');
const Unblocker     = require('unblocker');
const { Transform } = require('stream');
const youtube       = require('unblocker/examples/youtube/youtube.js');

const app = express();
const PREFIX = '/proxy/';

//─── Google Analytics 埋め込み ───────────────────────
const GA_ID = process.env.GA_ID || null;
function addGa(html) {
  if (!GA_ID) return html;
  const ga = [
    '<script type="text/javascript">',
    '  var _gaq = [];',
    `  _gaq.push(['_setAccount', '${GA_ID}']);`,
    '  _gaq.push([\'_trackPageview\']);',
    '  (function() {',
    "    var ga = document.createElement('script'); ga.type='text/javascript'; ga.async=true;",
    "    ga.src=(document.location.protocol==='https:'?'https://ssl':'http://www')+'.google-analytics.com/ga.js';",
    "    var s=document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga,s);",
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

//─── Unblocker 設定 ───────────────────────────────
const unblocker = new Unblocker({
  prefix: PREFIX,
  requestMiddleware:  [ youtube.processRequest ],
  responseMiddleware: [ googleAnalyticsMiddleware ],
});

//─── Caesar 復号 (charCode -1) ────────────────────
function caesarDecrypt(str) {
  return Array.from(str).map(c =>
    String.fromCharCode(c.charCodeAt(0) - 1)
  ).join('');
}

//─── 復号ミドルウェア：必ず unblocker の前に ──────────
app.use((req, res, next) => {
  // パスが /proxy/... なら
  if (req.path.startsWith(PREFIX)) {
    // ?以降を分離
    const [encPart, qs=''] = req.url.slice(PREFIX.length).split('?');
    // URLデコード → Caesar復号
    const decrypted = caesarDecrypt(decodeURIComponent(encPart));
    // 復号後の URL を再セット
    req.url = PREFIX + decrypted + (qs ? ('?' + qs) : '');
  }
  next();
});

//─── Unblocker を挟む ────────────────────────────
app.use(unblocker);

//─── 静的ファイル ─────────────────────────────────
app.use('/', express.static(__dirname + '/public'));

//─── JS無効時リダイレクト (/no-js) ──────────────
app.get('/no-js', (req, res) => {
  const site = querystring.parse(urlModule.parse(req.url).query).url || '';
  // 全文字コード +1 で Caesar 暗号
  const encrypted = Array.from(site).map(c =>
    String.fromCharCode(c.charCodeAt(0) + 1)
  ).join('');
  res.redirect(PREFIX + encodeURIComponent(encrypted));
});

//─── 起動 & WebSocket ───────────────────────────
const PORT = process.env.PORT || process.env.VCAP_APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`listening on http://localhost:${PORT}/`);
}).on('upgrade', unblocker.onUpgrade);
