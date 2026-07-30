const pug = require('pug');
const express = require('express');
const morgan = require('morgan');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const assert = require('assert');
const { randomUUID } = require('node:crypto');
const tar = require('tar-stream');
const config = require('../config');
const eventBus = require('./eventBus');
const tusboy = require('./tusboy');
const Store = require('./store');
const tusMeta = require('./tusboy/tus-metadata');
const utils = require('./utils');
const debug = require('debug')('psitransfer:main');
const { hashPassword, verifyPassword } = require('./passwordHash');

const { safeCompare, contentDispositionUtf8Filename, md5Hex, sha256Hex } = utils;

/** Decoded path segment under the /files mount (must match req.params used by tusboy). */
function decodedUploadPathSegment(req) {
  const raw = req.path.startsWith('/') ? req.path.slice(1) : req.path;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

const pugVars = {
  baseUrl: config.baseUrl,
};

const errorPage = pug.compileFile(path.join(__dirname, '../public/pug/error.pug'), {
  pretty: true,
});
const adminPage = pug.compileFile(path.join(__dirname, '../public/pug/admin.pug'), {
  pretty: true,
});
const uploadPage = pug.compileFile(path.join(__dirname, '../public/pug/upload.pug'), {
  pretty: true,
});
const downloadPage = pug.compileFile(path.join(__dirname, '../public/pug/download.pug'), {
  pretty: true,
});

const cookieParser = require('cookie-parser');
const sso = require('./sso');
const SsoStore = require('./ssoStore');

const store = new Store(config.uploadDir);
const Db = require('./db');
const { createGzip } = require('zlib');
const httpErrors = require('http-errors');
const db = new Db(config.uploadDir, store);
db.init();

const ssoStore = new SsoStore(path.resolve(config.uploadDir, '../data'), config);
config.ssoStore = ssoStore;

const app = express();

app.disable('x-powered-by');
app.use(compression());
app.use(express.json());
app.use(cookieParser());

// Security headers
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-XSS-Protection', '0'); // Modern browsers should use CSP instead
  res.set(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
    ].join('; ')
  );
  if (config.sslPort || config.forceHttps) {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Rate limiting
const rateLimit = require('express-rate-limit');
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.',
});
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 auth attempts per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many authentication attempts, please try again later.',
});
app.use(globalLimiter);
app.use(`${config.baseUrl}config.json`, authLimiter);
app.use(`${config.baseUrl}admin`, authLimiter);

if (config.accessLog) {
  app.use(morgan(config.accessLog));
}

if (config.trustProxy) {
  app.set('trust proxy', config.trustProxy);
}

if (config.forceHttps) {
  app.enable('trust proxy');
  app.use(function (req, res, next) {
    if (req.secure) return next();
    const target = config.forceHttps === 'true' ? 'https://' + req.headers.host : config.forceHttps;
    res.redirect(target + req.url);
  });
}

// Static files
app.use(`${config.baseUrl}app`, express.static(path.join(__dirname, '../public/app')));
app.use(`${config.baseUrl}assets`, express.static(path.join(__dirname, '../public/assets')));

// Resolve language
app.use((req, res, next) => {
  const lang = req.acceptsLanguages(...Object.keys(config.languages)) || config.defaultLanguage;
  req.translations = config.languages[lang];
  next();
});

// Health check endpoint (for Docker HEALTHCHECK and monitoring)
app.get(`${config.baseUrl}health`, (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    buckets: Object.keys(db.db).length,
  });
});

// robots.txt
app.get(`${config.baseUrl}robots.txt`, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/robots.txt'));
});

// Init plugins
config.plugins.forEach((pluginName) => {
  require('../plugins/' + pluginName)(eventBus, app, config, db);
});

// Upload App
app.get(config.uploadAppPath, (req, res) => {
  res.send(
    uploadPage({
      ...pugVars,
      baseUrl: config.baseUrl,
      uploadAppPath: config.uploadAppPath,
      lang: req.translations,
    })
  );
});

// Return translations
app.get(`${config.baseUrl}lang.json`, (req, res) => {
  eventBus.emit('getLang', req.translations);
  res.json(req.translations);
});

// Config
app.get(`${config.baseUrl}config.json`, (req, res) => {
  // Upload password protection
  if (config.uploadPass) {
    const bfTimeout = 200;
    if (!req.get('x-passwd')) {
      setTimeout(() => res.status(401).send('Unauthorized'), bfTimeout);
      return;
    }
    if (!safeCompare(req.get('x-passwd'), config.uploadPass)) {
      setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
      return;
    }
  }

  const frontendConfig = {
    retentions: config.retentions,
    defaultRetention: config.defaultRetention,
    mailTemplate: config.mailTemplate,
    requireBucketPassword: config.requireBucketPassword,
    maxFileSize: config.maxFileSize,
    maxBucketSize: config.maxBucketSize,
    disableQrCode: config.disableQrCode,
    ssoEnabled: config.ssoEnabled,
    availableOrgs: ssoStore.getAvailableOrgs(),
  };

  eventBus.emit('getFrontendConfig', frontendConfig);

  res.json(frontendConfig);
});

// SSO Endpoints
app.get(`${config.baseUrl}auth/sso/me`, (req, res) => {
  const user = sso.getSsoUser(req, config);
  res.json({
    ssoEnabled: config.ssoEnabled,
    authenticated: !!user,
    user: user || null,
  });
});

app.get(`${config.baseUrl}auth/sso/login/:org`, (req, res) => {
  const org = req.params.org;
  const returnTo = sso.sanitizeReturnTo(req.query.returnTo, config.baseUrl);
  const email = req.query.email || `user@${org}`;
  const name = req.query.name || `User (${org})`;

  sso.setSsoCookie(res, { email, org, name }, config, req);
  res.redirect(returnTo);
});

app.get(`${config.baseUrl}auth/sso/logout`, (req, res) => {
  sso.clearSsoCookie(res);
  const returnTo = sso.sanitizeReturnTo(req.query.returnTo, config.baseUrl);
  res.redirect(returnTo);
});

const ssoAuthMiddleware = sso.authorizeBucketSso(db, config);

app.get(`${config.baseUrl}admin`, (req, res, next) => {
  if (!config.adminPass) return next();
  res.send(adminPage({ ...pugVars, lang: req.translations }));
});

app.get(`${config.baseUrl}admin/data.json`, (req, res, next) => {
  if (!config.adminPass) return next();

  const bfTimeout = 500;
  if (!req.get('x-passwd')) {
    // delay answer to make brute force attacks more difficult
    setTimeout(() => res.status(401).send('Unauthorized'), bfTimeout);
    return;
  }
  if (!safeCompare(req.get('x-passwd'), config.adminPass)) {
    setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
    return;
  }

  let result = JSON.parse(JSON.stringify(db.db));
  Object.values(result).forEach((bucket) => {
    bucket.forEach((file) => {
      if (file.metadata.password) {
        file.metadata._password = true;
        delete file.metadata.password;
        delete file.metadata.key;
        delete file.key;
        delete file.url;
      }
    });
  });

  setTimeout(() => res.json(result), bfTimeout);
});

// Admin SSO Org Management APIs
app.get(`${config.baseUrl}admin/sso-orgs.json`, (req, res, next) => {
  if (!config.adminPass) return next();
  const bfTimeout = 500;
  if (!req.get('x-passwd') || !safeCompare(req.get('x-passwd'), config.adminPass)) {
    setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
    return;
  }
  res.json(ssoStore.getAllOrgs());
});

app.post(`${config.baseUrl}admin/sso-orgs.json`, (req, res, next) => {
  if (!config.adminPass) return next();
  const bfTimeout = 500;
  if (!req.get('x-passwd') || !safeCompare(req.get('x-passwd'), config.adminPass)) {
    setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
    return;
  }
  const { domain, name, requireSso, issuerUrl, clientId, clientSecret } = req.body || {};
  if (!domain || typeof domain !== 'string') {
    return res.status(400).send('Domain is required');
  }
  const saved = ssoStore.setOrg(domain, { name, requireSso, issuerUrl, clientId, clientSecret });
  if (!saved) {
    return res.status(400).send('Invalid domain format');
  }
  res.json(saved);
});

app.delete(`${config.baseUrl}admin/sso-orgs/:domain`, (req, res, next) => {
  if (!config.adminPass) return next();
  const bfTimeout = 500;
  if (!req.get('x-passwd') || !safeCompare(req.get('x-passwd'), config.adminPass)) {
    setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
    return;
  }
  const domain = req.params.domain;
  const removed = ssoStore.removeOrg(domain);
  if (!removed) return res.status(404).send('Org not found');
  res.status(204).end();
});

// Prometheus Metrics Endpoint
app.get(`${config.baseUrl}metrics`, (req, res) => {
  const buckets = db.db || {};
  const activeBucketsCount = Object.keys(buckets).length;
  let totalFilesCount = 0;
  let totalSizeBytes = 0;

  Object.values(buckets).forEach((bucket) => {
    if (Array.isArray(bucket)) {
      totalFilesCount += bucket.length;
      bucket.forEach((file) => {
        totalSizeBytes += file.size || 0;
      });
    }
  });

  const uptimeSeconds = Math.floor(process.uptime());

  const metricsText = [
    '# HELP psitransfer_uptime_seconds Total application uptime in seconds',
    '# TYPE psitransfer_uptime_seconds counter',
    `psitransfer_uptime_seconds ${uptimeSeconds}`,
    '# HELP psitransfer_active_buckets_total Total number of active transfer buckets',
    '# TYPE psitransfer_active_buckets_total gauge',
    `psitransfer_active_buckets_total ${activeBucketsCount}`,
    '# HELP psitransfer_files_total Total number of stored files',
    '# TYPE psitransfer_files_total gauge',
    `psitransfer_files_total ${totalFilesCount}`,
    '# HELP psitransfer_storage_bytes_total Total size of stored files in bytes',
    '# TYPE psitransfer_storage_bytes_total gauge',
    `psitransfer_storage_bytes_total ${totalSizeBytes}`,
    '',
  ].join('\n');

  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  res.send(metricsText);
});

// List files / Download App
app.get(`${config.baseUrl}:sid`, ssoAuthMiddleware, async (req, res, next) => {
  if (req.url.endsWith('.json')) {
    const sid = req.params.sid.substr(0, req.params.sid.length - 5);
    if (!db.get(sid)) return res.status(404).end();

    const downloadPassword = req.get('x-download-pass');
    const items = db.get(sid).map((item) => ({
      ...item,
      url: `${config.baseUrl}files/${sid}++${item.key}`,
    }));

    res.header('Cache-control', 'private, max-age=0, no-cache, no-store, must-revalidate');

    // Currently, every item in a bucket must have the same password
    try {
      const pass = downloadPassword || '';
      for (const item of items) {
        if (!item.metadata.password) continue;
        const ok = await verifyPassword(item.metadata.password, pass);
        if (!ok) {
          setTimeout(() => res.status(401).send('Unauthorized'), 500);
          return;
        }
      }
    } catch (e) {
      console.error(e);
      setTimeout(() => res.status(401).send('Unauthorized'), 500);
      return;
    }

    const keyList = items.map((item) => item.key).join();
    const archiveToken = sha256Hex(keyList).slice(0, 32);

    res.json({
      items,
      archiveToken,
      config: {
        maxPreviewSize: config.maxPreviewSize,
      },
    });
  } else {
    if (!db.get(req.params.sid)) return next();
    res.send(downloadPage({ ...pugVars, lang: req.translations }));
  }
});

// Download files
app.get(`${config.baseUrl}files/:fid`, ssoAuthMiddleware, async (req, res, next) => {
  // let tusboy handle HEAD requests with Tus Header
  if (req.method === 'HEAD' && req.get('Tus-Resumable')) return next();

  // Disable HTTP transport compression for file downloads.
  // Archives already handle their own compression (zip/gzip), and for single
  // files this preserves Content-Length and Range request support needed for
  // resumable downloads of large files.
  res.set('Cache-Control', 'no-transform');

  const sid = req.params.fid.split('++')[0];

  // Download all files
  if (req.params.fid.match(/^[a-z0-9+]+\.(tar\.gz|zip)$/)) {
    const format = req.params.fid.endsWith('.zip') ? 'zip' : 'tar.gz';
    const bucket = db.get(sid);

    if (!bucket)
      return res.status(404).send(
        errorPage({
          ...pugVars,
          error: 'Download bucket not found.',
          lang: req.translations,
          uploadAppPath: config.uploadAppPath || config.baseUrl,
        })
      );

    const keyList = bucket.map((f) => f.key).join();
    const legacyMd5 = md5Hex(keyList);
    const newSha256 = sha256Hex(keyList).slice(0, 32);
    const expectedLegacy = `${sid}++${legacyMd5}.${format}`;
    const expectedNew = `${sid}++${newSha256}.${format}`;

    if (req.params.fid !== expectedLegacy && req.params.fid !== expectedNew) {
      res.status(404).send(
        errorPage({
          ...pugVars,
          error: 'Invalid link',
          uploadAppPath: config.uploadAppPath || config.baseUrl,
          lang: req.translations,
        })
      );
      return;
    }
    debug(`Download Bucket ${sid}`);

    const filename = `${sid}.${format}`;
    res.header('Content-Disposition', `attachment; filename="${filename}"`);

    try {
      res.on('finish', async () => {
        bucket.forEach(async (info) => {
          if (info.metadata.retention === 'one-time') {
            await db.remove(info.metadata.sid, info.metadata.key);
          } else {
            await db.updateLastDownload(info.metadata.sid, info.metadata.key);
          }
        });

        eventBus.emit('archiveDownloaded', {
          sid,
          file: filename,
          metadata: bucket[0].metadata,
          bucket,
          url: req.protocol + '://' + req.get('host') + req.originalUrl,
        });
      });
    } catch (e) {
      console.error(e);
    }

    if (format === 'zip') {
      res.header('ContentType', 'application/zip');
      const { ZipArchive } = await import('archiver');
      const archive = new ZipArchive();
      archive.on('error', function (err) {
        console.error(err);
      });
      archive.pipe(res);

      const usedNames = new Map();
      const uniqueName = (rawName, fallback) => {
        const base = utils.toSafeBasename(rawName, fallback);
        const prev = usedNames.get(base) || 0;
        usedNames.set(base, prev + 1);
        if (prev === 0) return base;
        const ext = path.extname(base);
        const stem = ext ? base.slice(0, -ext.length) : base;
        return `${stem} (${prev + 1})${ext}`;
      };

      for (const info of bucket) {
        await new Promise((resolve, reject) => {
          const stream = fs.createReadStream(
            store.getFilename(info.metadata.sid + '++' + info.key)
          );
          stream.on('end', resolve);
          stream.on('error', reject);
          archive.append(stream, { name: uniqueName(info.metadata.name, info.key) });
        });
      }

      await archive.finalize();
    } else {
      res.header('ContentType', 'application/x-gtar');
      const pack = tar.pack();
      pack.pipe(createGzip()).pipe(res);

      const usedNames = new Map();
      const uniqueName = (rawName, fallback) => {
        const base = utils.toSafeBasename(rawName, fallback);
        const prev = usedNames.get(base) || 0;
        usedNames.set(base, prev + 1);
        if (prev === 0) return base;
        const ext = path.extname(base);
        const stem = ext ? base.slice(0, -ext.length) : base;
        return `${stem} (${prev + 1})${ext}`;
      };

      for (const info of bucket) {
        await new Promise((resolve, reject) => {
          const readStream = fs.createReadStream(
            store.getFilename(info.metadata.sid + '++' + info.key)
          );
          const entry = pack.entry({
            name: uniqueName(info.metadata.name, info.key),
            size: info.size,
          });
          readStream.on('error', reject);
          entry.on('error', reject);
          entry.on('finish', resolve);
          readStream.pipe(entry);
        });
      }
      pack.finalize();
    }

    return;
  }

  // Download single file
  debug(`Download ${req.params.fid}`);
  try {
    if (req.params.fid.includes('++') && !utils.isSafeTusUploadId(req.params.fid)) {
      return res.status(404).send(
        errorPage({
          ...pugVars,
          error: 'Invalid link',
          lang: req.translations,
          uploadAppPath: config.uploadAppPath || config.baseUrl,
        })
      );
    }
    const info = await store.info(req.params.fid); // throws on 404
    const safeName = utils.toSafeBasename(info.metadata.name, info.key);
    res.set('Content-Disposition', contentDispositionUtf8Filename(safeName, info.key));
    res.sendFile(store.getFilename(req.params.fid));

    // remove one-time files after download
    res.on('finish', async () => {
      if (info.metadata.retention === 'one-time') {
        await db.remove(info.metadata.sid, info.metadata.key);
      } else {
        await db.updateLastDownload(info.metadata.sid, info.metadata.key);
      }

      eventBus.emit('fileDownloaded', {
        sid,
        file: info.metadata.name,
        metadata: info.metadata,
        url: req.protocol + '://' + req.get('host') + req.originalUrl,
      });
    });
  } catch (e) {
    res.status(404).send(
      errorPage({
        ...pugVars,
        error: e.message,
        lang: req.translations,
        uploadAppPath: config.uploadAppPath || config.baseUrl,
      })
    );
  }
});

// Upload file
app.use(
  `${config.uploadAppPath}files`,
  async function (req, res, next) {
    // Upload password protection
    if (config.uploadPass) {
      const bfTimeout = 500;
      if (!req.get('x-passwd')) {
        setTimeout(() => res.status(401).send('Unauthorized'), bfTimeout);
        return;
      }
      if (!safeCompare(req.get('x-passwd'), config.uploadPass)) {
        setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
        return;
      }
    }

    if (req.method === 'GET') return res.status(405).end();

    const fid = decodedUploadPathSegment(req);
    if (fid === null) {
      return res.status(400).end('Invalid path encoding');
    }

    // Lock bucket by PATCH /files/:sid?lock=yes
    if (fid && !fid.includes('++') && req.method === 'PATCH' && req.query.lock) {
      if (!utils.isSafeBucketFid(fid)) {
        return res.status(400).end('Invalid bucket id');
      }
      await db.lock(fid);
      return res.status(204).end('Bucket locked');
    }

    if (['POST', 'PATCH'].includes(req.method)) {
      if (fid && !fid.includes('++') && !utils.isSafeBucketFid(fid)) {
        return res.status(400).end('Invalid bucket id');
      }
      if (fid && !fid.includes('++') && db.isLocked(fid)) {
        return res.status(400).end('Bucket locked');
      }
      if (fid) {
        if (fid.includes('++') && !utils.isSafeTusUploadId(fid)) {
          return res.status(400).end('Invalid upload id');
        }
        try {
          const info = await store.info(fid);
          if (info.metadata.bucketLocked) {
            return res.status(400).end('Bucket locked');
          }
          if (!info.isPartial) {
            return res.status(400).end('Upload already completed');
          }
        } catch (e) {
          if (!(e instanceof httpErrors.NotFound)) {
            console.error(e);
            return next(e);
          }
        }
      }
    }

    if (req.method === 'POST') {
      // validate meta-data
      // !! tusMeta.encode supports only strings !!
      const meta = tusMeta.decode(req.get('Upload-Metadata'));

      try {
        assert(meta.name, 'tus meta prop missing: name');
        assert(meta.sid, 'tus meta prop missing: sid');
        if (!utils.isSafeBasename(meta.sid)) {
          return res.status(400).end('Invalid bucket id');
        }
        assert(meta.retention, 'tus meta prop missing: retention');
        assert(
          Object.keys(config.retentions).indexOf(meta.retention) >= 0,
          `invalid tus meta prop retention. Value ${meta.retention} not in [${Object.keys(config.retentions).join(',')}]`
        );

        // Prevent ZipSlip/tar path traversal by requiring a safe basename at upload time.
        // Policy (flat archive): no directories, no absolute paths, no traversal, no control chars.
        if (!utils.isSafeBasename(meta.name)) {
          return res.status(400).end('Invalid file name');
        }

        const uploadLength = req.get('Upload-Length');
        assert(uploadLength, 'missing Upload-Length header');

        // Restrict creating new files for locked buckets
        if (db.isLocked(meta.sid)) {
          return res.status(400).end('Bucket locked');
        }

        meta.uploadLength = uploadLength;
        meta.key = randomUUID();
        meta.createdAt = Date.now().toString();

        if (meta.org && sso.isSsoMandatoryOrg(meta.org, config)) {
          meta.ssoEnforced = 'true';
        } else {
          meta.ssoEnforced = 'false';
        }

        // limit file and bucket size
        if (config.maxFileSize && config.maxFileSize < +uploadLength) {
          return res
            .status(413)
            .json({ message: `File exceeds maximum upload size ${config.maxFileSize}.` });
        } else if (
          config.maxBucketSize &&
          db.bucketSize(meta.sid) + +uploadLength > config.maxBucketSize
        ) {
          return res
            .status(413)
            .json({ message: `Bucket exceeds maximum upload size ${config.maxBucketSize}.` });
        }

        // store changed metadata for tusboy
        if (typeof meta.password === 'string' && meta.password.length > 0) {
          meta.password = await hashPassword(meta.password);
        } else {
          delete meta.password;
        }
        req.headers['upload-metadata'] = tusMeta.encode(meta);
        // for tusboy getKey()
        req.FID = meta.sid + '++' + meta.key;

        db.add(meta.sid, meta.key, {
          isPartial: true,
          metadata: meta,
        });
      } catch (e) {
        console.error(e);
        return res.status(400).end(e.message);
      }
    }

    next();
  },

  // let tusboy handle the upload
  tusboy(store, {
    getKey: (req) => req.FID,
    maxUploadLength: config.maxFileSize || Infinity,
    afterComplete: (req, upload, fid) => {
      db.add(upload.metadata.sid, upload.metadata.key, upload);
      debug(`Completed upload ${fid}, size=${upload.size} name=${upload.metadata.name}`);
      eventBus.emit('fileUploaded', upload);
    },
  })
);

app.use((req, res, _next) => {
  if (req.url === config.baseUrl) {
    return res.redirect(config.uploadAppPath);
  }

  res.status(404).send(
    errorPage({
      ...pugVars,
      error: 'Download bucket not found.',
      uploadAppPath: config.uploadAppPath || config.baseUrl,
      lang: req.translations,
    })
  );
});

module.exports = app;
