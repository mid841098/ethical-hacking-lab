/**
 * Authorized Practice Lab Server
 * Track: Ethical Hacking - EdVyro Internship
 * File: lab/server.js
 * 
 * BOUNDARY NOTICE:
 * This server binds STRICTLY to 127.0.0.1 (Loopback). It does NOT listen on 0.0.0.0
 * or any public-facing network adapter. Designed exclusively for safe, local,
 * authorized penetration testing exercises.
 * 
 * Dual Mode:
 *   - Default (Vulnerable Mode): Contains deliberate OWASP Top 10 security flaws for training.
 *   - Secure Mode (--secure or LAB_SECURE_MODE=true): Implements industry-standard remediations
 *     for retesting and verification.
 */

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

// Environment & Configuration
const PORT = parseInt(process.env.LAB_PORT, 10) || 3000;
const HOST = '127.0.0.1'; // HARD SCOPE BOUNDARY: Strictly loopback only!
const IS_SECURE_MODE = process.argv.includes('--secure') || process.env.LAB_SECURE_MODE === 'true';

// Rate limiting store for secure mode (IP -> { count, resetTime })
const failedAttempts = new Map();

// Session tokens store: token -> { userId, username, role }
const activeSessions = new Map([
  ['tok_student_session_123', { userId: 2, username: 'bob_student', role: 'user' }]
]);

function sendJson(res, statusCode, data, headers = {}) {
  const defaultHeaders = {
    'Content-Type': 'application/json; charset=utf-8'
  };

  if (IS_SECURE_MODE) {
    // OWASP A05 Remediation: Hardened Security Headers
    defaultHeaders['X-Content-Type-Options'] = 'nosniff';
    defaultHeaders['X-Frame-Options'] = 'DENY';
    defaultHeaders['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';";
    defaultHeaders['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    defaultHeaders['Referrer-Policy'] = 'strict-origin-when-cross-origin';
    defaultHeaders['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';
    defaultHeaders['X-Permitted-Cross-Domain-Policies'] = 'none';
  } else {
    // Deliberate Security Misconfiguration: Info disclosure & missing headers
    defaultHeaders['Server'] = 'NodeJS-Express-Lab/1.0.4-dev (Vulnerable Sandbox)';
    defaultHeaders['X-Powered-By'] = 'Node.js/v24.13.0';
    defaultHeaders['Access-Control-Allow-Origin'] = '*';
  }

  res.writeHead(statusCode, { ...defaultHeaders, ...headers });
  res.end(JSON.stringify(data, null, 2));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1e6) { // 1MB flood protection
        req.connection.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        // Fallback to URL encoded params
        const params = new URLSearchParams(body);
        const obj = {};
        for (const [k, v] of params) obj[k] = v;
        resolve(obj);
      }
    });
  });
}

function getAuthUser(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return null;
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  return activeSessions.get(token) || null;
}

const server = http.createServer(async (req, res) => {
  const clientIp = req.socket.remoteAddress;
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const query = parsedUrl.query;
  const method = req.method.toUpperCase();

  // Audit Logging
  db.logAccess(method, pathname, clientIp, 200);

  try {
    // Route 1: Health & Lab Status
    if (pathname === '/api/health' && method === 'GET') {
      return sendJson(res, 200, {
        status: 'UP',
        mode: IS_SECURE_MODE ? 'SECURE_REMEDIATED' : 'VULNERABLE_TRAINING',
        targetBinding: `${HOST}:${PORT}`,
        isolationState: 'ISOLATED_RFC1918_LOOPBACK',
        timestamp: new Date().toISOString()
      });
    }

    // Route 2: System Version / Info (Task 2 Recon Target)
    if (pathname === '/api/version' && method === 'GET') {
      return sendJson(res, 200, {
        application: 'Authorized Security Practice Lab (JuiceShop-Model)',
        version: '1.2.0-alpha',
        environment: 'Local Isolated Practice Lab',
        nodeRuntime: process.version,
        authorizedTester: 'Security Intern / Auditor'
      });
    }

    // Route 3: Product Search (OWASP A03 - SQL / Query Injection Vulnerability)
    if (pathname === '/api/products/search' && method === 'GET') {
      const q = query.q || '';
      
      if (IS_SECURE_MODE) {
        // --- SECURE IMPLEMENTATION ---
        // Parameterized, strictly sanitized query, public items only
        if (typeof q !== 'string' || /[^\w\s\-]/.test(q)) {
          // Reject SQL metacharacters like ', ", ;, --, union, etc.
          return sendJson(res, 400, {
            error: 'Invalid search parameters. Special characters are disallowed.',
            code: 'PARAM_VALIDATION_ERROR'
          });
        }
        const sanitizedTerm = q.trim().toLowerCase();
        const results = db.products.filter(p => p.isPublic && p.name.toLowerCase().includes(sanitizedTerm));
        return sendJson(res, 200, {
          query: sanitizedTerm,
          count: results.length,
          data: results.map(({ id, name, category, price, stock }) => ({ id, name, category, price, stock }))
        });
      } else {
        // --- VULNERABLE IMPLEMENTATION ---
        // Simulates unescaped SQL / string interpolation concatenation:
        // SELECT * FROM products WHERE isPublic = 1 AND name LIKE '%${q}%'
        const lowerQ = q.toLowerCase();

        // If injection pattern `' OR '1'='1` or `' UNION` or `--` is sent, bypass filter & leak restricted records
        if (lowerQ.includes("' or '1'='1") || lowerQ.includes("' or 1=1") || lowerQ.includes("' union select") || lowerQ.includes("--")) {
          // Injection successful: returns ALL products including confidential internal tools!
          return sendJson(res, 200, {
            query: q,
            simulatedQuery: `SELECT * FROM products WHERE isPublic = 1 AND name LIKE '%${q}%'`,
            count: db.products.length,
            injected: true,
            data: db.products // Leaks confidential Flag & internal tools
          });
        }

        // Standard vulnerable search without sanitization
        const results = db.products.filter(p => p.isPublic && p.name.toLowerCase().includes(lowerQ));
        return sendJson(res, 200, {
          query: q,
          count: results.length,
          data: results
        });
      }
    }

    // Route 4: User Profile (OWASP A01 - Broken Object Level Authorization / IDOR)
    if (pathname === '/api/profile' && method === 'GET') {
      const requestedId = parseInt(query.id, 10);
      if (isNaN(requestedId)) {
        return sendJson(res, 400, { error: 'Missing or invalid user id' });
      }

      if (IS_SECURE_MODE) {
        // --- SECURE IMPLEMENTATION ---
        // Validate session token and enforce that users can ONLY access their own data
        const currentUser = getAuthUser(req);
        if (!currentUser) {
          return sendJson(res, 401, { error: 'Authentication required. Missing or invalid Bearer token.' });
        }
        if (currentUser.userId !== requestedId && currentUser.role !== 'admin') {
          return sendJson(res, 403, { 
            error: 'Forbidden: Access to requested object is denied. Object-level authorization enforced.',
            code: 'AUTHZ_IDOR_PREVENTED'
          });
        }

        const user = db.users.find(u => u.id === requestedId);
        if (!user) return sendJson(res, 404, { error: 'User not found' });

        return sendJson(res, 200, {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          fullName: user.fullName,
          phone: user.phone,
          balance: user.balance
          // Notice: Sensitive apiToken and passwordHash are omitted!
        });
      } else {
        // --- VULNERABLE IMPLEMENTATION (IDOR) ---
        // No authentication check or ownership validation. Any caller can request ?id=1 and dump Alice Admin's profile & apiToken!
        const user = db.users.find(u => u.id === requestedId);
        if (!user) return sendJson(res, 404, { error: 'User not found' });

        return sendJson(res, 200, {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          fullName: user.fullName,
          phone: user.phone,
          balance: user.balance,
          apiToken: user.apiToken, // Sensitive credential leak
          isSuperUser: user.isSuperUser
        });
      }
    }

    // Route 5: Order Details (OWASP A01 - IDOR in Order History)
    if (pathname === '/api/orders' && method === 'GET') {
      const orderId = parseInt(query.id, 10);
      if (isNaN(orderId)) {
        return sendJson(res, 400, { error: 'Missing or invalid order id' });
      }

      const order = db.orders.find(o => o.id === orderId);
      if (!order) return sendJson(res, 404, { error: 'Order not found' });

      if (IS_SECURE_MODE) {
        const currentUser = getAuthUser(req);
        if (!currentUser) {
          return sendJson(res, 401, { error: 'Authentication required' });
        }
        if (currentUser.userId !== order.userId && currentUser.role !== 'admin') {
          return sendJson(res, 403, { error: 'Forbidden: You do not own this order record' });
        }
        return sendJson(res, 200, { order });
      } else {
        // Vulnerable IDOR: Directly returns order regardless of requester identity
        return sendJson(res, 200, { order });
      }
    }

    // Route 6: Authentication / Login (OWASP A07 - Broken Authentication & Brute-Force)
    if (pathname === '/api/auth/login' && method === 'POST') {
      const body = await parseBody(req);
      const { email, password } = body;

      if (!email || !password) {
        return sendJson(res, 400, { error: 'Email and password are required' });
      }

      if (IS_SECURE_MODE) {
        // --- SECURE IMPLEMENTATION ---
        // 1. Rate limiting per IP
        const attemptKey = clientIp;
        const now = Date.now();
        const record = failedAttempts.get(attemptKey) || { count: 0, resetTime: now + 60000 };
        
        if (now > record.resetTime) {
          record.count = 0;
          record.resetTime = now + 60000;
        }

        if (record.count >= 5) {
          return sendJson(res, 429, {
            error: 'Too many failed login attempts. Account temporarily locked. Please try again after 60 seconds.',
            retryAfterSeconds: Math.ceil((record.resetTime - now) / 1000)
          });
        }

        // 2. Timing-safe generic error message (Prevents user enumeration)
        const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
        const hashedInput = crypto.createHash('sha256').update(password).digest('hex');

        if (!user || user.passwordHash !== hashedInput) {
          record.count += 1;
          failedAttempts.set(attemptKey, record);
          return sendJson(res, 401, {
            error: 'Invalid credentials. Please verify your email and password.',
            code: 'AUTH_FAILED'
          });
        }

        // Reset rate limit on success
        failedAttempts.delete(attemptKey);
        
        // Issue secure cryptographically random session token
        const sessionToken = 'sess_' + crypto.randomBytes(24).toString('hex');
        activeSessions.set(sessionToken, { userId: user.id, username: user.username, role: user.role });

        return sendJson(res, 200, {
          message: 'Authentication successful',
          token: sessionToken,
          user: {
            id: user.id,
            username: user.username,
            role: user.role
          }
        });
      } else {
        // --- VULNERABLE IMPLEMENTATION ---
        // User enumeration via differing error messages + No rate limiting
        const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (!user) {
          // Leaks that email does NOT exist in system
          return sendJson(res, 401, {
            error: 'Account not found: The specified email is not registered.',
            vulnerability: 'User Enumeration'
          });
        }

        const hashedInput = crypto.createHash('sha256').update(password).digest('hex');
        if (user.passwordHash !== hashedInput) {
          // Leaks that email DOES exist, only password was wrong
          return sendJson(res, 401, {
            error: 'Incorrect password: Password does not match our records for this user.',
            vulnerability: 'User Enumeration'
          });
        }

        // Login success (fixed predictable token)
        return sendJson(res, 200, {
          message: 'Login successful (Vulnerable Session)',
          token: user.apiToken,
          role: user.role,
          user: { id: user.id, username: user.username, email: user.email }
        });
      }
    }

    // Route 7: Feedback / Comment (OWASP A03 - Reflected XSS)
    if (pathname === '/api/feedback' && method === 'GET') {
      const comment = query.msg || 'Welcome to the authorized lab';
      
      if (IS_SECURE_MODE) {
        // Strict JSON output + escaping
        const escaped = String(comment)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
        return sendJson(res, 200, {
          message: 'Feedback received safely',
          sanitizedMessage: escaped
        });
      } else {
        // Deliberately reflects raw input with text/html content type (Reflected XSS)
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Server': 'VulnerableLab/1.0'
        });
        return res.end(`
          <!DOCTYPE html>
          <html>
            <head><title>Lab Feedback Reflection</title></head>
            <body>
              <h2>Auditor Feedback Viewer</h2>
              <div id="feedback-display">${comment}</div>
            </body>
          </html>
        `);
      }
    }

    // Route 8: Admin Debug Endpoint (Task 2 Recon Hidden Endpoint)
    if (pathname === '/api/admin/debug' && method === 'GET') {
      if (IS_SECURE_MODE) {
        return sendJson(res, 404, { error: 'Not Found' }); // Removed in production / secure mode
      } else {
        return sendJson(res, 200, {
          warning: 'DEBUG INTERFACE EXPOSED - FOR INTERNAL TESTING ONLY',
          environmentVariables: {
            NODE_ENV: process.env.NODE_ENV || 'development',
            DATABASE_DIALECT: 'in-memory-sqlite-sim',
            HOST_BINDING: `${HOST}:${PORT}`
          },
          registeredRoutes: [
            '/api/health',
            '/api/version',
            '/api/products/search',
            '/api/profile',
            '/api/orders',
            '/api/auth/login',
            '/api/feedback',
            '/api/admin/debug'
          ]
        });
      }
    }

    // Route 9: Root Landing / Dashboard UI
    if (pathname === '/' && method === 'GET') {
      const htmlPath = path.join(__dirname, 'public', 'index.html');
      if (fs.existsSync(htmlPath)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return fs.createReadStream(htmlPath).pipe(res);
      } else {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(`Authorized Ethical Hacking Lab Running on ${HOST}:${PORT}\nMode: ${IS_SECURE_MODE ? 'SECURE' : 'VULNERABLE'}`);
      }
    }

    // 404 Handler
    return sendJson(res, 404, {
      error: 'Endpoint not found',
      path: pathname,
      authorizedScope: `http://${HOST}:${PORT}/`
    });

  } catch (err) {
    if (IS_SECURE_MODE) {
      return sendJson(res, 500, { error: 'Internal Server Error', code: 'SERVER_FAULT' });
    } else {
      // Deliberately leak full stack trace in vulnerable mode (Security Misconfiguration)
      return sendJson(res, 500, {
        error: 'Unhandled Internal Error (Debug Trace Leaked)',
        message: err.message,
        stack: err.stack
      });
    }
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[AUTHORIZED LAB] Server started successfully.`);
  console.log(`[SECURITY BOUNDARY] Listening exclusively on: http://${HOST}:${PORT}`);
  console.log(`[MODE] Current Operation Mode: ${IS_SECURE_MODE ? 'SECURE (Remediated)' : 'VULNERABLE (Training Sandbox)'}`);
  console.log(`[RULES OF ENGAGEMENT] Testing authorized strictly for ${HOST}:${PORT}.`);
});

// Graceful termination
process.on('SIGINT', () => {
  console.log('\n[AUTHORIZED LAB] Stopping practice server gracefully...');
  server.close(() => {
    console.log('[AUTHORIZED LAB] Lab offline. Baseline preserved.');
    process.exit(0);
  });
});

module.exports = server;
