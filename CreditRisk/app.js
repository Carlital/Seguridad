const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const path = require('path');
const rateLimit = require('express-rate-limit');

//cargar rutas
const usuario_rutas = require('./routes/usuario');
const permiso_rutas = require('./routes/permiso');
const rol_rutas = require('./routes/rol');
const rol_permiso_rutas = require('./routes/rol_permiso');
const usuario_rol_rutas = require('./routes/usuario_rol');
const auditoria_rutas = require('./routes/auditoria');
const setting_rutas = require('./routes/setting');
const socios_rutas = require('./routes/socios');
const ml_rutas = require('./routes/ml');
const evaluacion_rutas = require('./routes/evaluacion');
const reportes_rutas = require('./routes/reportes');
// CORS SIEMPRE PRIMERO
// Allow HEAD in methods so browser fetch HEAD requests are permitted by CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
}));

app.set('trust proxy', true);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  
  max: 100,                  
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Demasiadas solicitudes. Por favor, intente nuevamente en 15 minutos.',
    retryAfter: 15 * 60
  }
});

// bloqueo automático (no modifica la configuración del limiter existente) ---
const BAN_THRESHOLD = 3; // número de respuestas 429 necesarias para banear
const BAN_DURATION_MS = 60 * 60 * 1000; // 1 hora
const ipBlacklist = new Map(); // ip -> expiry timestamp (ms)
const offenseCounts = new Map(); // ip -> count


function getClientIp(req) {
  return (req.ip || req.connection.remoteAddress || '')
    .replace('::ffff:', '');
}

// Middleware: si la IP está en la blacklist devuelve 403 inmediatamente
function Precheck(req, res, next) {
  const ip = getClientIp(req);
  const expiry = ipBlacklist.get(ip);

  if (expiry && expiry > Date.now()) {
    return res.status(403).json({
      status: 403,
      message: 'Forbidden: IP temporalmente bloqueada'
    });
  }

  if (expiry && expiry <= Date.now()) {
    ipBlacklist.delete(ip);
  }

  next();
}

// Middleware: vigila si el servidor responde 429 y contabiliza ofensas por IP.
// No modifica la configuración del rate limiter; simplemente observa la respuesta.
function Watcher(req, res, next) {
  const ip = getClientIp(req);

  const originalSend = res.send.bind(res);
  res.send = function (...args) {
    if (res.statusCode === 429) {
      const count = (offenseCounts.get(ip) || 0) + 1;
      offenseCounts.set(ip, count);

      if (count >= BAN_THRESHOLD) {
        ipBlacklist.set(ip, Date.now() + BAN_DURATION_MS);
        offenseCounts.delete(ip);
      }
    }
    return originalSend(...args);
  };

  next();
}


// Ruta de depuración que permite limpiar manualmente la blacklist y los contadores de ofensas.
// Se registra antes del Precheck para que pueda ejecutarse incluso si la IP está bloqueada.
// Es útil para pruebas y para desbloquear IPs sin reiniciar el servidor.
app.all('/api/debug/clear-blacklist', (req, res) => {
  try {
    // Guarda el estado previo de la blacklist y los contadores
    const before = { 
      blacklistSize: ipBlacklist.size, 
      offenseCountsSize: offenseCounts.size 
    };

    // Limpia completamente la blacklist y los contadores de ofensas
    ipBlacklist.clear();
    offenseCounts.clear();

    // Respuesta de confirmación
    return res.send({ 
      ok: true, 
      message: 'blacklist and offense counters cleared', 
      before 
    });
  } catch (e) {
    console.error('Error clearing blacklist', e);
    return res.status(500).send({ 
      ok: false, 
      message: 'error clearing blacklist' 
    });
  }
});

// Ruta de depuración que muestra las IPs bloqueadas y las ofensas registradas.
// Permite verificar qué IPs están sancionadas y cuánto tiempo resta para su desbloqueo.
app.get('/api/debug/list-blacklist', (req, res) => {
  try {
    const now = Date.now();

    // Lista de IPs bloqueadas con su tiempo restante de bloqueo
    const blacklist = Array.from(ipBlacklist.entries()).map(([ip, expiry]) => ({
      ip,
      expiry,
      expiresInMs: Math.max(0, expiry - now)
    }));

    // Lista de IPs con número de ofensas acumuladas
    const offenses = Array.from(offenseCounts.entries()).map(([ip, count]) => ({
      ip,
      count
    }));

    return res.send({ ok: true, blacklist, offenses });
  } catch (e) {
    console.error('Error listing blacklist', e);
    return res.status(500).send({ 
      ok: false, 
      message: 'error listing blacklist' 
    });
  }
});

// Endpoint de verificación de estado del servidor (health check).
// Siempre está disponible y permite comprobar que el backend está activo.
app.get('/api/status', (req, res) => {
  res.status(200).send({ 
    status: 'ok', 
    timestamp: new Date().toISOString() 
  });
});

// Se aplican los middlewares en este orden:
// 1. Precheck: bloquea inmediatamente las IPs en la blacklist.
// 2. Watcher: observa las respuestas 429 para contar ofensas.
// 3. Limiter: limita la cantidad de solicitudes por IP.
app.use('/api', Precheck, Watcher, limiter);

// Ruta de prueba afectada por el rate limiter.
// Se utiliza para generar respuestas 429 y verificar el bloqueo automático de IPs.
app.get('/api/debug/test-rate', (req, res) => {
  res.status(200).send({ 
    ok: true, 
    ts: new Date().toISOString() 
  });
});


const { logger } = require('./services/logger');

// Simple request logger for debugging (prints incoming method + path)
app.use((req, res, next) => {
  logger.info('[req] %s %s %s', req.ip, req.method, req.path);
  next();
});

// Attach audit helper to request so controllers can call req.audit(action, details)
app.use((req, res, next) => {
  const auditService = require('./services/audit');
  req.audit = (action, details) => {
    try {
      // Normalize possible token shapes: prefer .id, fallback to .id_usuario or .ID_USUARIO
      const userId = req.user ? (req.user.id || req.user.id_usuario || req.user.ID_USUARIO || null) : null;
      if (userId === null || userId === undefined) {
        // don't call the audit service if there's no authenticated user (DB has FK to usuarios)
        // keep a debug line so it's visible in logs
        console.debug('req.audit skipped — no authenticated user for action=', action);
      } else {
        auditService.logAction({ userId, action, details, req });
      }
    } catch (e) {
      console.error('req.audit error', e);
    }
  };
  req.logServerError = (error) => {
    try {
      const userId = req.user ? (req.user.id || req.user.id_usuario || req.user.ID_USUARIO || null) : null;
      // Always attempt to log server errors. The ErrorLog model allows null id_usuario so
      // errors from unauthenticated requests or system errors will also be recorded.
      auditService.logError({ userId, error, req });
    } catch (e) {
      console.error('req.logServerError error', e);
    }
  };
  next();
});

// Body parser: debe ir antes de registrar las rutas para que req.body esté disponible
app.use(bodyParser.urlencoded({ limit: '20mb', extended: true }));
app.use(bodyParser.json({ limit: '20mb' }));

// Servir archivos subidos (fotos) desde /uploads
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// ahora registramos las rutas

app.use('/api', usuario_rutas);
app.use('/api/permisos', permiso_rutas);
app.use('/api/roles', rol_rutas);
app.use('/api/rol_permiso', rol_permiso_rutas);
app.use('/api/usuario_rol', usuario_rol_rutas);
app.use('/api/auditoria', auditoria_rutas);
app.use('/api/settings', setting_rutas);
app.use('/api', socios_rutas);
app.use('/api/ml', ml_rutas);
app.use('/api/evaluacion', evaluacion_rutas);
app.use('/api/reportes', reportes_rutas);
// Debug routes removed (were causing issues in some environments)


// Dev helper: trigger a server error to test tb_errors logging
// (safe to remove in production)
app.get('/api/debug/error', (req, res) => {
  throw new Error('Test error - tb_errors logging');
});


// Generic error handler: logs errors to tb_errors and returns a generic response
app.use((err, req, res, next) => {
  try {
    logger.error('Unhandled error: %o', err);
    const auditService = require('./services/audit');
    const userId = req.user ? req.user.id : null;
    auditService.logError({ userId, error: err, req });
  } catch (e) {
    logger.error('Error while logging error: %o', e);
  }
  res.status(500).send({ message: 'Internal server error' });
});



module.exports = app;

