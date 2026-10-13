/**
 * PromptShield AI - Lightweight Test Harness Server
 * 
 * Zero dependencies. Runs on Node.js to serve the test harness and static assets.
 * Compatible with all test harness URLs:
 * - http://localhost:8080/
 * - http://localhost:8080/test-harness.html
 * - http://localhost:8080/sandbox/test-harness.html
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8080;
const rootDir = path.resolve(__dirname, '..');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  // Normalize pathname
  let reqPath = decodeURI(req.url.split('?')[0]);

  let targetFile = null;

  if (reqPath === '/' || reqPath === '/test-harness.html') {
    targetFile = path.join(rootDir, 'extension', 'sandbox', 'test-harness.html');
  } else if (reqPath.startsWith('/sandbox/')) {
    targetFile = path.join(rootDir, 'extension', 'sandbox', reqPath.replace('/sandbox/', ''));
  } else if (reqPath.startsWith('/content/')) {
    targetFile = path.join(rootDir, 'extension', 'content', reqPath.replace('/content/', ''));
  } else if (reqPath.startsWith('/tests/')) {
    targetFile = path.join(rootDir, 'tests', reqPath.replace('/tests/', ''));
  } else {
    // Try resolving directly from root or extension
    const tryDirect = path.join(rootDir, reqPath);
    const tryExtension = path.join(rootDir, 'extension', reqPath);
    if (fs.existsSync(tryDirect) && fs.statSync(tryDirect).isFile()) {
      targetFile = tryDirect;
    } else if (fs.existsSync(tryExtension) && fs.statSync(tryExtension).isFile()) {
      targetFile = tryExtension;
    }
  }

  if (targetFile && fs.existsSync(targetFile) && fs.statSync(targetFile).isFile()) {
    const ext = path.extname(targetFile).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(targetFile, (err, data) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal Server Error');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end(`Not Found: ${reqPath}`);
  }
});

server.listen(PORT, () => {
  console.log(`[PromptShield Sandbox] Server active at http://localhost:${PORT}/`);
  console.log(`[PromptShield Sandbox] Serving test harness from extension/sandbox/test-harness.html`);
});
