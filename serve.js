#!/usr/bin/env node
/**
 * serve.js — plain static file server, zero dependencies.
 *
 * Needed for two things:
 *  1. isolated-captcha-test.html requiring http(s):// instead of file:// (some vendor
 *     widgets refuse to fully initialize when loaded from a file:// origin as a basic
 *     anti-tampering check — see the console-error diagnosis in captcha/NOTES.md before
 *     assuming this is the fix).
 *  2. Standing in for static.geetest.com's widget bundle, when isolated-captcha-test-local.html
 *     is configured with `staticServers: ["localhost:PORT"]` (see its own comments): the
 *     real /load and /verify calls still go to GeeTest's real servers unmodified, but the
 *     WIDGET SCRIPT ITSELF gets requested from this server instead — so it can be swapped
 *     for sources/gcaptcha4_rekeyed.js (the REAL, still-obfuscated bundle, with just its one
 *     RSA modulus argument literal swapped for a locally generated key — see that file's own
 *     header for why this is built from the raw obfuscated source rather than
 *     gcaptcha4_deobfuscated.js, whose own deobfuscation script turned out to corrupt the
 *     module system). Everything gcaptcha4.js references by its own hardcoded absolute URLs
 *     (css, fonts, icons) still resolves straight to the real CDN, untouched by this.
 *
 * USAGE: node serve.js [port]   (default 8788)
 *        then open http://localhost:8788/isolated-captcha-test.html
 *        then open http://localhost:8788/isolated-captcha-test-local.html
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.argv[2]) || 8788;
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.jpg': 'image/jpeg',
};

// Real gcaptcha4.js is fetched at `${static_path}${js}` from /load's response (currently
// "/v4/static/v1.9.7-fc2ddc/js/gcaptcha4.js"); gct4.js at `gct_path` (currently under
// "/v4/gct/"). Matched by shape rather than the exact versioned path, since static_path's
// version suffix can change release to release.
function localOverrideFor(urlPath) {
  if (urlPath.endsWith('/js/gcaptcha4.js')) return path.join(ROOT, 'sources', 'gcaptcha4_rekeyed.js');
  if (/\/gct\/.*\.js$/.test(urlPath)) return path.join(ROOT, 'sources', 'gct4.js');
  return null;
}

http.createServer((req, res) => {
  const urlPath = decodeURIComponent(req.url.split('?')[0]);
  const file = urlPath === '/' ? '/isolated-captcha-test.html' : urlPath;
  const fullPath = localOverrideFor(urlPath) || path.join(ROOT, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
  fs.readFile(fullPath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found: ' + file); return; }
    const ext = path.extname(fullPath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, () => {
  console.log(`[serve] http://localhost:${PORT}/isolated-captcha-test.html`);
  console.log(`[serve] http://localhost:${PORT}/isolated-captcha-test-local.html`);
});
