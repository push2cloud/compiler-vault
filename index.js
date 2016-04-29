const debug = require('debug')('push2cloud-compiler-vault');
const request = require('request');
const async = require('async');
const _ = require('lodash');
const fs = require('fs');

const debugCb = (debugFn, cb) => {
  return (err, result) => {
    if (err) {
      debugFn('error', `Errorcode: ${err}`, result);
    } else {
      debugFn('success', result);
    }
    return cb.apply(cb, _.toArray(arguments));
  };
};

const isVaultString = (string) => (string && _.isString(string) && string.indexOf('secret://') === 0);

const getVaultKey = (string) => string.substring(9);

const login = (options, cb) => {
  if (!options || !options.api) {
    return cb(new Error('No api endpoint defined!'));
  }

  options.certFile = options.certFile || process.env.VAULT_CERT_FILE;
  options.cert = options.cert || process.env.VAULT_CERT;
  options.keyFile = options.keyFile || process.env.VAULT_KEY_FILE;
  options.key = options.key || process.env.VAULT_KEY;
  options.caFile = options.caFile || process.env.VAULT_CA_FILE;
  options.ca = options.ca || process.env.VAULT_CA;
  options.pfxFile = options.pfxFile || process.env.VAULT_PFX_FILE;
  options.pfx = options.pfx || process.env.VAULT_PFX;
  options.passphrase = options.passphrase || process.env.VAULT_PASSPHRASE;

  if (options.certFile) {
    options.cert = fs.readFileSync(options.certFile);
  }
  if (options.keyFile) {
    options.key = fs.readFileSync(options.keyFile);
  }
  if (options.caFile) {
    options.ca = fs.readFileSync(options.caFile);
  }
  if (options.pfxFile) {
    options.pfx = fs.readFileSync(options.pfxFile);
  }

  request.post({
    baseUrl: options.api,
    uri: '/auth/cert/login',
    json: true,
    rejectUnauthorized: options.rejectUnauthorized === undefined || options.rejectUnauthorized === null ? true : options.rejectUnauthorized,
    cert: options.cert,
    key: options.key,
    ca: options.ca,
    pfx: options.pfx,
    passphrase: options.passphrase
  }, (err, response, result) => {
    if (err) {
      return cb(err);
    }

    if (!result || !result.auth || !result.auth.client_token) {
      debug(result);
      return cb(new Error('No client_token found!'));
    }

    cb(null, result.auth.client_token);
  });
};

const getSecretFromVault = (key, appName, options, cb) => {
  if (!options.token) {
    return cb(new Error('No token found! login() first!'));
  }

  if (!options.api) {
    return cb(new Error('No api endpoint defined!'));
  }

  var ns = '';
  if (options.namespace) {
    ns = '/' + options.namespace;
  }

  request.get({
    baseUrl: options.api,
    uri: `${ns}/${appName}`,
    json: true,
    rejectUnauthorized: options.rejectUnauthorized === undefined || options.rejectUnauthorized === null ? true : options.rejectUnauthorized,
    headers: {
      'X-Vault-Token': options.token
    }
  }, (err, response, result) => {
    if (err) {
      return cb(err);
    }

    if (result && result.data && result.data[key]) {
      // return specific
      return cb(null, result.data[key]);
    }

    if (!options.sharedSecretKey) {
      return cb(null, undefined);
    }

    request.get({
      baseUrl: options.api,
      uri: `${ns}/${options.sharedSecretKey}`,
      json: true,
      rejectUnauthorized: options.rejectUnauthorized === undefined || options.rejectUnauthorized === null ? true : options.rejectUnauthorized,
      headers: {
        'X-Vault-Token': options.token
      }
    }, (err, response, result) => {
      if (err) {
        return cb(err);
      }

      if (result && result.data && result.data[key]) {
        // return shared
        return cb(null, result.data[key]);
      }

      request.get({
        baseUrl: options.api,
        uri: `${ns}/${options.sharedSecretKey}/${key}`,
        json: true,
        rejectUnauthorized: options.rejectUnauthorized === undefined || options.rejectUnauthorized === null ? true : options.rejectUnauthorized,
        headers: {
          'X-Vault-Token': options.token
        }
      }, (err, response, result) => {
        if (err) {
          return cb(err);
        }

        if (!result || !result.data) {
          // return shared as value
          return cb(null, undefined);
        }

        return cb(null, result.data.value || result.data[key]);
      });
    });
  });
};

const vault = (config, mani, t, next) => {
  if (!mani.deployment.secretStore || mani.deployment.secretStore.type !== 'vault') return next(null, config, mani, t);

  var cb = debugCb(debug, next);

  login(mani.deployment.secretStore, (err, token) => {
    if (err) return cb(err);

    mani.deployment.secretStore.token = token;

    async.each(config.envVars, (appEnv, cb) => {
      var appName = appEnv.unversionedName || appEnv.name;

      async.each(_.keys(appEnv.env), (key, cb) => {
        if (!isVaultString(appEnv.env[key])) return cb(null);
        var vaultKey = getVaultKey(appEnv.env[key]);

        getSecretFromVault(vaultKey, appName, mani.deployment.secretStore, (err, value) => {
          if (err) return cb(err);

          appEnv.env[key] = value;
          cb(null);
        });
      }, cb);
    }, (err) => {
      cb(err, config, mani, t);
    });
  });
};

module.exports = vault;
