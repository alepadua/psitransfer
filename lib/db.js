'use strict';
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('path');
const debug = require('debug')('psitransfer:db');
const config = require('../config');

module.exports = class DB {

  constructor(uploadDir, store) {
    this.initialized = false;
    this.db = {};

    this.uploadDir = uploadDir;
    this.store = store;

    // delete expired files
    const gc = () => {
      let sid,f,expires;
      for (sid of Object.keys(this.db)) {
        for (f of this.db[sid]) {
          // expire on maxAge
          expires = (+f.metadata.createdAt) + (config.maxAge * 1000) - Date.now();

          // respect one-time downloads
          if(expires > 0 && Number.isInteger(+f.metadata.retention)) {
            expires = (+f.metadata.createdAt) + (+f.metadata.retention * 1000) - Date.now();
          }

          if(expires <= 0) {
            debug(`Expired ${sid}++${f.key}`);
            this.remove(sid, f.key).catch(e => console.error(e));
          }
        }
      }
    };
    setInterval(gc, 60 * 1000).unref();

  }


  init() {
    if(this.initialized) return;
    this.initialized = true;

    try {
      this._sync();
    } catch(e) {
      this.initialized = false;
      e.message = `db initialization failed with error ${e.message}`;
      throw e;
    }
  }


  /**
   * @private
   */
  _sync() {
    fs.mkdirSync(this.uploadDir, { recursive: true });

    fs.readdirSync(this.uploadDir).forEach((sid) => {
      this._import(sid);
    });
  }


  /**
   * @private
   */
  _import(sid) {
    const p = path.resolve(this.uploadDir, sid);
    const stat = fs.statSync(p);
    if(!stat.isDirectory()) return;

    const entries = fs.readdirSync(p);
    for (const key of entries) {
      if(path.extname(key) !== '') {
        continue;
      }
      try {
        // Read info synchronously during startup to avoid race conditions.
        // The previous async forEach did not await promises, causing a silent bug.
        const jsonPath = path.resolve(p, key + '.json');
        const filePath = path.resolve(p, key);
        const raw = fs.readFileSync(jsonPath, 'utf8');
        const info = JSON.parse(raw);
        const fileStat = fs.statSync(filePath);
        info.size = fileStat.size;
        info.offset = fileStat.size;
        this.add(sid, key, info);
      } catch(e) {
        console.error(e);
      }
    }
  }


  add(sid, key, data) {
    if(!this.initialized) throw new Error('DB not initialized_');
    if(!this.db[sid]) this.db[sid] = [];
    data.key = key;
    const old = this.db[sid].findIndex(i => i.key === key);
    if(old !== -1) {
      this.db[sid].splice(old, 1, data);
      debug(`Updated ${sid}++${key}`);
    } else {
      this.db[sid].push(data);
      debug(`Added ${sid}++${key}`);
    }
  }


  async remove(sid, key) {
    if(!this.initialized) throw new Error('DB not initialized');
    debug(`Remove ${sid}++${key}`);
    await this.store.del(sid + '++' + key);
    const i = this.db[sid].findIndex(item => item.key === key);
    this.get(sid).splice(i, 1);
    if(this.get(sid).length === 0) {
      delete this.db[sid];
      await fsp.rmdir(path.resolve(this.uploadDir, sid));
    }
  }


  async updateLastDownload(sid, key) {
    debug(`Update last download ${sid}++${key}`);
    const data = this.get(sid).find(item => item.key === key);
    if(!data) return;
    data.metadata.lastDownload = Date.now();
    await this.store.update(`${sid}++${key}`, data);
  }


  async updateMetadata(sid, key, data) {
    debug(`Update metadata ${ sid }++${ key }`);
    const file = this.get(sid).find(item => item.key === key);
    if (!file) return;
    file.metadata = { ...file.metadata, ...data };
    await this.store.update(`${ sid }++${ key }`, file);
  }

  async lock(sid) {
    const files = this.get(sid);
    if(!files) return;
    await Promise.all(files.map(async file => {
      await this.updateMetadata(sid, file.key, { bucketLocked: true });
    }));
  }

  isLocked(sid) {
    const files = this.get(sid);
    if(!files) return false;
    return files.some(file => file.metadata.bucketLocked);
  }

  get(sid) {
    return this.db[sid];
  }

  bucketSize(sid) {
    const bucket = this.get(sid);
    if(!bucket) return 0;
    return bucket.reduce((v, file) => v + +file.metadata.uploadLength, 0);
  }

};