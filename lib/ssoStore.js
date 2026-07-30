const fs = require('node:fs');
const path = require('node:path');

class SsoStore {
  constructor(dataDir, config) {
    this.dataDir = dataDir || path.join(__dirname, '../data');
    this.filePath = path.join(this.dataDir, 'sso-orgs.json');
    this.config = config || {};
    this.orgs = {};
    this.init();
  }

  init() {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      if (fs.existsSync(this.filePath)) {
        const content = fs.readFileSync(this.filePath, 'utf8');
        this.orgs = JSON.parse(content);
      } else {
        this.orgs = {};
      }
    } catch (e) {
      console.error('Error loading sso-orgs.json:', e);
      this.orgs = {};
    }
  }

  saveToFile() {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      fs.writeFileSync(this.filePath, JSON.stringify(this.orgs, null, 2), 'utf8');
    } catch (e) {
      console.error('Error saving sso-orgs.json:', e);
    }
  }

  /**
   * Returns merged Map/Object of all registered Organizations from file store + static config.
   */
  getAllOrgs() {
    const staticOrgs = (this.config && this.config.ssoMandatoryOrgs) || {};
    return {
      ...staticOrgs,
      ...this.orgs,
    };
  }

  /**
   * Returns list of public available Orgs for dropdown selection.
   */
  getAvailableOrgs() {
    const merged = this.getAllOrgs();
    return Object.keys(merged).map((domain) => {
      const entry = merged[domain];
      return {
        domain,
        name: entry.name || domain,
        requireSso: entry.requireSso !== false,
      };
    });
  }

  /**
   * Returns Org config for a specific domain.
   */
  getOrg(domain) {
    if (!domain || typeof domain !== 'string') return null;
    const key = domain.toLowerCase().trim();
    const merged = this.getAllOrgs();
    return merged[key] || null;
  }

  /**
   * Adds or updates an Organization configuration.
   */
  setOrg(domain, data) {
    if (!domain || typeof domain !== 'string') return;
    const key = domain.toLowerCase().trim();
    this.orgs[key] = {
      domain: key,
      name: data.name || key,
      requireSso: data.requireSso !== false,
      issuerUrl: data.issuerUrl || '',
      clientId: data.clientId || '',
      clientSecret: data.clientSecret || '',
      allowedDomains: data.allowedDomains || [key],
      updatedAt: Date.now(),
    };
    this.saveToFile();
    return this.orgs[key];
  }

  /**
   * Removes an Organization configuration.
   */
  removeOrg(domain) {
    if (!domain || typeof domain !== 'string') return false;
    const key = domain.toLowerCase().trim();
    if (this.orgs[key]) {
      delete this.orgs[key];
      this.saveToFile();
      return true;
    }
    return false;
  }
}

module.exports = SsoStore;
