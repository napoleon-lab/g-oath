// server.js
require('dotenv').config();

const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const axios = require('axios');
const cookieSession = require('cookie-session');
const { v4: uuidv4 } = require('uuid');
const querystring = require('querystring');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');

// Setup winston logger with daily rotation
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new DailyRotateFile({
      filename: 'logs/server-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '7d'
    })
  ]
});

// If not in production, also log to console
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}


const SSL_KEY_PATH = process.env.SSL_KEY_PATH;
const SSL_CERT_PATH = process.env.SSL_CERT_PATH;
let credentials = null;
if (fs.existsSync(SSL_KEY_PATH) && fs.existsSync(SSL_CERT_PATH)) {
  const privateKey = fs.readFileSync(SSL_KEY_PATH, 'utf8');
  const certificate = fs.readFileSync(SSL_CERT_PATH, 'utf8');
  credentials = { key: privateKey, cert: certificate };
}

const PORT = process.env.PORT || 8321;
const REDIRECT_PORT = process.env.REDIRECT_PORT || PORT;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const DOMAIN = process.env.DOMAIN || 'localhost';
const PROTOCOL = credentials ? 'https' : 'http';
const REDIRECT_URI = process.env.REDIRECT_URI || `${PROTOCOL}://${DOMAIN}:${REDIRECT_PORT}/callback`;
const SCOPE = process.env.SCOPE || 'https://www.googleapis.com/auth/calendar.readonly';

const app = express();

// body parsing para JSON y form-urlencoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// logger middleware
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const ms = Date.now() - start;
    logger.info(`${req.method} ${req.originalUrl} -> ${res.statusCode} [${ms}ms]`);
  });

  next();
});

// Session con configuración más permisiva para OAuth.
app.use(cookieSession({
  name: 'sess',
  keys: [process.env.SESSION_KEY || 'replace_me_with_strong_random'],
  maxAge: 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: !!credentials, // secure only if HTTPS
  sameSite: credentials ? 'none' : 'lax',
  domain: DOMAIN
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 10, // limit each IP to 10 auth requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Store temporal para estados OAuth (evita problemas de sesión)
const stateStore = {}; // { state: { userId, timestamp, return_url, redirect_uri } }

// Cleanup de estados viejos cada 10 minutos
setInterval(() => {
  const now = Date.now();
  Object.keys(stateStore).forEach(state => {
    if (now - stateStore[state].timestamp > 10 * 60 * 1000) {
      delete stateStore[state];
    }
  });
}, 10 * 60 * 1000);

// Helper: build Google auth URL
function buildAuthUrl(state) {
  const params = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPE,
    access_type: 'offline',
    prompt: 'consent',
    state
  };
  return `https://accounts.google.com/o/oauth2/v2/auth?${querystring.stringify(params)}`;
}

// Helper: validar redirect loopback seguro
function isValidLoopbackRedirect(uri) {
  try {
    const u = new URL(uri);
    const isLocal = (u.hostname === '127.0.0.1' || u.hostname === 'localhost');
    const hasPort = !!u.port; // exigir puerto explícito
    const okPath = (u.pathname === '/callback' || u.pathname === '/');
    const okProtocol = (u.protocol === 'http:'); // loopback http
    return isLocal && hasPort && okPath && okProtocol;
  } catch (e) {
    return false;
  }
}

// Inicio de auth: el widget redirige al usuario aquí
app.get('/auth', authLimiter, (req, res) => {
  const state = req.query.state || uuidv4();
  const return_url = req.query.return_url || '/';
  const clientRedirect = req.query.redirect_uri; // lo que envía la app

  // validar redirect local (si se envía)
  let savedRedirect = null;
  if (clientRedirect) {
    if (isValidLoopbackRedirect(clientRedirect)) {
      savedRedirect = clientRedirect;
    } else {
      logger.warn(`[AUTH] Invalid redirect_uri rejected: ${clientRedirect}`);
      return res.status(400).send('Invalid redirect_uri');
    }
  }

  // Guardar en memory el estado y (opcional) la redirect_uri provista por la app
  stateStore[state] = {
    timestamp: Date.now(),
    return_url,
    redirect_uri: savedRedirect // puede ser null
  };

  // guardamos también en sesión como backup
  req.session.oauth_state = state;
  req.session.return_url = return_url;
  if (savedRedirect) req.session.redirect_uri = savedRedirect;

  logger.info(`[AUTH] Generated state: ${state}, return_url: ${return_url}, redirect: ${savedRedirect ? 'saved' : 'none'}`);

  const url = buildAuthUrl(state);
  res.redirect(url);
});

// Callback que google llama
app.get('/callback', authLimiter, async (req, res) => {
  const { code, state, error } = req.query;

  logger.info(`[CALLBACK] Received - code: ${code ? 'present' : 'missing'}, state: ${state}, error: ${error || 'none'}`);
  logger.debug(`[CALLBACK] Session state: ${req.session.oauth_state}`);
  logger.debug(`[CALLBACK] State store has: ${stateStore[state] ? 'found' : 'not found'}`);

  // Si Google devolvió error
  if (error) {
    logger.error(`[CALLBACK] Google OAuth error: ${error}`);
    return res.status(400).send(`Authentication error: ${error}`);
  }

  if (!code || !state) {
    logger.error('[CALLBACK] Missing code or state');
    return res.status(400).send('Missing code or state parameter');
  }

  // Verificar estado (primero en memoria, luego en sesión)
  const stateInfo = stateStore[state];
  const validState = stateInfo || (state === req.session.oauth_state);

  if (!validState) {
    logger.error(`[CALLBACK] Invalid state. Received: ${state}, Expected: ${req.session.oauth_state}`);
    return res.status(400).send('Invalid state parameter - possible CSRF attack');
  }

  try {
    logger.info('[CALLBACK] Exchanging code for token...');

    const tokenResp = await axios.post('https://oauth2.googleapis.com/token', querystring.stringify({
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code'
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const tokenData = tokenResp.data;
    logger.info('[CALLBACK] Token exchange succeeded (tokens received, not logged).');

    // Obtener info del usuario de Google (intentar)
    let userEmail = 'unknown';
    // try {
    //   const userInfoResp = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
    //     headers: { Authorization: `Bearer ${tokenData.access_token}` }
    //   });
    //   userEmail = userInfoResp.data.email;
    //   logger.info(`[CALLBACK] User identified: ${userEmail}`);
    // } catch (e) {
    //   logger.warn('[CALLBACK] Could not fetch user info:', e.message);
    // }

    const userId = uuidv4();

    // Guardamos userId y email en la sesión (tokens managed by client)
    req.session.userId = userId;
    req.session.email = userEmail;

    logger.info(`[CALLBACK] User authenticated: ${userId}, email: ${userEmail}`);

    // obtener redirect guardado (prioridad: stateStore -> session)
    const redirectTo = (stateInfo && stateInfo.redirect_uri) || req.session.redirect_uri || null;

    // limpiar estado usado
    if (stateInfo) delete stateStore[state];

    if (redirectTo) {
      // construir query seguro usando URL object
      try {
        const u = new URL(redirectTo);
        // agregar parámetros sin sobrescribir (usamos searchParams)
        u.searchParams.set('success', 'true');
        if (tokenData.access_token) u.searchParams.set('access_token', tokenData.access_token);
        if (tokenData.refresh_token) u.searchParams.set('refresh_token', tokenData.refresh_token);
        if (tokenData.expires_in) u.searchParams.set('expires_in', String(tokenData.expires_in));
        u.searchParams.set('state', state);

        const location = u.toString();
        logger.info('[CALLBACK] Redirecting to app loopback (no tokens logged).');
        return res.redirect(302, location);
      } catch (e) {
        logger.error('[CALLBACK] Error building redirect URL:', e.message);
        // fallback a json si algo falla con la redirect
      }
    }

    // Fallback: devolver JSON como antes (no se pudo redirigir a loopback)
    return res.json({
      success: true,
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_in: tokenData.expires_in,
      expires_at: new Date(expires_at).toISOString(),
      email: userEmail,
      userId: userId
    });
  } catch (err) {
    logger.error('[CALLBACK] Token exchange error:', err.response ? JSON.stringify(err.response.data) : err.message);
    return res.status(500).send(`Token exchange failed: ${err.message}`);
  }
});

// Status endpoint para debugging
app.get('/api/status', (req, res) => {
  const userId = req.session.userId;
  const authenticated = !!userId;

  res.json({
    authenticated,
    userId: userId || null,
    email: req.session.email || null
  });
});

// Logout simple
app.get('/logout', (req, res) => {
  const userId = req.session.userId;
  logger.info(`[LOGOUT] User logged out: ${userId}`);
  req.session = null;
  res.send('Logged out successfully');
});

// Página principal - simple mensaje
app.get('/', (req, res) => {
  res.json({
    message: 'Google Calendar OAuth Server',
    endpoints: {
      auth: '/auth - Start OAuth flow',
      status: '/api/status - Check auth status',
      logout: '/logout - Clear session'
    }
  });
});

// Página de éxito simple
app.get('/success', (req, res) => {
  res.send(`
    <html>
      <head><title>Authentication Successful</title></head>
      <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>✓ Authentication Successful!</h1>
        <p>You can now close this window and return to your widget.</p>
        <script>
          if (window.opener) {
            window.opener.postMessage({ type: 'oauth_success' }, '*');
            setTimeout(() => window.close(), 2000);
          }
        </script>
      </body>
    </html>
  `);
});

app.post('/api/refresh_with_token', async (req, res) => {
  const schema = Joi.object({
    refresh_token: Joi.string().required()
  });

  const { error, value } = schema.validate({
    refresh_token: req.body.refresh_token || req.query.refresh_token
  });

  if (error) {
    logger.warn('[REFRESH_WITH_TOKEN] Validation error:', error.details[0].message);
    return res.status(400).json({ error: 'validation_error', message: error.details[0].message });
  }

  const clientRefresh = value.refresh_token;

  try {
    logger.info('[REFRESH_WITH_TOKEN] Refresh requested (no token logged)');
    const r = await axios.post('https://oauth2.googleapis.com/token',
      querystring.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: clientRefresh,
        grant_type: 'refresh_token'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const data = r.data;
    // data: { access_token, expires_in, scope, token_type, refresh_token? }

    logger.info('[REFRESH_WITH_TOKEN] Token refresh successful');

    return res.json({
      success: true,
      access_token: data.access_token,
      refresh_token: data.refresh_token || null,
      expires_in: data.expires_in,
      expires_at: new Date(Date.now() + (data.expires_in * 1000)).toISOString()
    });
  } catch (err) {
    logger.error('[REFRESH_WITH_TOKEN] Refresh failed:', err.response ? JSON.stringify(err.response.data) : err.message);
    const status = err.response?.status || 500;
    const body = err.response?.data || { error: 'refresh_failed', message: err.message };
    return res.status(status).json({ error: 'refresh_failed', detail: body });
  }
});


// Start server (HTTP or HTTPS)
const server = credentials ? https.createServer(credentials, app) : http.createServer(app);
server.listen(PORT, () => {
  logger.info(`
╔════════════════════════════════════════════════════════════╗
║  Server running on ${PROTOCOL}://${DOMAIN}:${PORT}  ║
╚════════════════════════════════════════════════════════════╝

Auth URL: ${PROTOCOL}://${DOMAIN}:${PORT}/auth
Callback: ${REDIRECT_URI}
Status:   ${PROTOCOL}://${DOMAIN}:${PORT}/api/status

Ready to accept OAuth flows...
`);
});

