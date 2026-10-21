/*!
 * node-keychain
 * Copyright(c) 2023 Nicholas Penree <nick@penree.com>
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var childProcess = require('child_process');
var noop = function () {};

function spawn(command, args) {
  // Looked up at call time so tests can stub child_process.spawn.
  // Always an argument array and never a shell, so option values can't inject commands.
  return childProcess.spawn(command, args);
}

// Polyfill Buffer.from for Node < 4 that didn't have a #from method
if (!Buffer.from) {
  Buffer.from = function (data, encoding, len) {
    return new Buffer(data, encoding, len);
  };
}
// Between Node >=4 to < 4.5 Buffer.from was inherited from Uint8Array
// And behaved differently, it was backported in 4.5.
if (Buffer.from === Uint8Array.from) {
  throw new Error('Node >= 4.0.0 to < 4.5.0 are unsupported')
}

/**
 * Basic Keychain Access on Mac computers running Node.js
 *
 * @class KeychainAccess
 * @api public
 */

function KeychainAccess() {
  this.executablePath = '/usr/bin/security';
}

/**
 * Retreive a password from the keychain.
 *
 * @param {Object} opts Object containing `account` and `service`
 * @param {Function} fn Callback
 * @api public
 */

KeychainAccess.prototype.getPassword = function(opts, fn) {
  opts = opts || {};
  opts.type = (opts.type || 'generic').toLowerCase();
  fn = fn || noop;
  var err;

  if (process.platform !== 'darwin') {
    err = new KeychainAccess.errors.UnsupportedPlatformError(null, process.platform);
    fn(err, null);
    return;
  }

  if (!opts.account) {
    err = new KeychainAccess.errors.NoAccountProvidedError();
    fn(err, null);
    return;
  }

  if (!opts.service) {
    err = new KeychainAccess.errors.NoServiceProvidedError();
    fn(err, null);
    return;
  }

  var security = spawn(this.executablePath, [ 'find-'+opts.type+'-password', '-a', opts.account, '-s', opts.service, '-g' ]);
  var keychain = '';
  var password = '';

  security.on('error', function(err) {
    err = new KeychainAccess.errors.ServiceFailureError(null, err.message);
    fn(err, null);
    return;
  });

  security.stdout.on('data', function(d) {
    keychain += d.toString();
  });

  // For better or worse, the last line (containing the actual password) is actually written to stderr instead of stdout.
  // Reference: http://blog.macromates.com/2006/keychain-access-from-shell/
  security.stderr.on('data', function(d) {
    password += d.toString();
  });

  security.on('close', function(code, signal) {
    if (code !== 0) {
      err = new KeychainAccess.errors.PasswordNotFoundError();
      fn(err, null);
      return;
    }

    if (/password/.test(password)) {
      // When keychain escapes a char into octal it also includes a hex
      // encoded version.
      //
      // e.g. password 'passWith\' becomes:
      // password: 0x70617373576974685C  "passWith\134"
      //
      // And if the password does not contain ASCII it leaves out the quoted
      // version altogether:
      //
      // e.g. password '∆˚ˆ©ƒ®∂çµ˚¬˙ƒ®†¥' becomes:
      // password: 0xE28886CB9ACB86C2A9C692C2AEE28882C3A7C2B5CB9AC2ACCB99C692C2AEE280A0C2A5
      var hexMatch = password.match(/^password: 0x([0-9a-fA-F]+)/m);
      if (hexMatch) {
        fn(null, Buffer.from(hexMatch[1], 'hex').toString());
        return;
      }
      // Otherwise the password will be in quotes:
      // password: "passWithoutSlash"
      var quotedMatch = password.match(/"(.*)\"/);
      if (quotedMatch) {
        fn(null, quotedMatch[1]);
        return;
      }
      // Output we can't parse: report it rather than throwing inside the event handler.
      err = new KeychainAccess.errors.PasswordNotFoundError();
      fn(err, null);
    }
    else {
      err = new KeychainAccess.errors.PasswordNotFoundError();
      fn(err, null);
    }
  });
};

/**
 * Set/update a password in the keychain.
 *
 * @param {Object} opts Object containing `account`, `service`, and `password`
 * @param {Function} fn Callback
 * @api public
 */

KeychainAccess.prototype.setPassword = function(opts, fn) {
  opts = opts || {};
  opts.type = (opts.type || 'generic').toLowerCase();
  fn = fn || noop;
  var err;

  if (process.platform !== 'darwin') {
    err = new KeychainAccess.errors.UnsupportedPlatformError(null, process.platform);
    fn(err, null);
    return;
  }

  if (!opts.account) {
    err = new KeychainAccess.errors.NoAccountProvidedError();
    fn(err, null);
    return;
  }

  if (!opts.service) {
    err = new KeychainAccess.errors.NoServiceProvidedError();
    fn(err, null);
    return;
  }

  if (!opts.password) {
    err = new KeychainAccess.errors.NoPasswordProvidedError();
    fn(err, null);
    return;
  }

  var security = spawn(this.executablePath, [ 'add-'+opts.type+'-password', '-a', opts.account, '-s', opts.service, '-w', opts.password ]);
  var self = this;

  security.on('error', function(err) {
    err = new KeychainAccess.errors.ServiceFailureError(null, err.message);
    fn(err, null);
    return;
  });

  security.on('close', function(code, signal) {
    if (code !== 0) {
      if (code == 45) {
        self.deletePassword(opts, function(err) {
          if (err) {
            fn(err);
            return;
          }

          self.setPassword(opts, fn);
          return;
        });
      } else {
        var msg = 'Security returned a non-successful error code: ' + code;
        err = new KeychainAccess.errors.ServiceFailureError(msg);
        err.exitCode = code;
        fn(err);
        return;
      }
    } else {
      fn(null, opts.password);
    }
  });
};

/**
* Delete a password from the keychain.
*
* @param {Object} opts Object containing `account`, `service`, and `password`
* @param {Function} fn Callback
* @api public
*/

KeychainAccess.prototype.deletePassword = function(opts, fn) {
  opts = opts || {};
  opts.type = (opts.type || 'generic').toLowerCase();
  fn = fn || noop;
  var err;

  if (process.platform !== 'darwin') {
    err = new KeychainAccess.errors.UnsupportedPlatformError(null, process.platform);
    fn(err, null);
    return;
  }

  if (!opts.account) {
    err = new KeychainAccess.errors.NoAccountProvidedError();
    fn(err, null);
    return;
  }

  if (!opts.service) {
    err = new KeychainAccess.errors.NoServiceProvidedError();
    fn(err, null);
    return;
  }

  var security = spawn(this.executablePath, [ 'delete-'+opts.type+'-password', '-a', opts.account, '-s', opts.service ]);

  security.on('error', function(err) {
    err = new KeychainAccess.errors.ServiceFailureError(null, err.message);
    fn(err, null);
    return;
  });

  security.on('close', function(code, signal) {
    if (code !== 0) {
      err = new KeychainAccess.errors.PasswordNotFoundError();
      fn(err);
      return;
    }
    fn(null);
  });
};

/**
* Create a new keychain to be used in the system.
*
* @param {Object} opts Object containing 'keychainName' and `password`
* @param {Function} fn Callback
* @api public
*/
KeychainAccess.prototype.createKeychain = function(opts, fn) {
  opts = opts || {};
  fn = fn || noop;
  var err;

  if (!opts.keychainName) {
    err = new KeychainAccess.errors.NoKeychainNameProvidedError();
    fn(err, null);
    return;
  }

  if (!opts.password) {
    err = new KeychainAccess.errors.NoPasswordProvidedError();
    fn(err, null);
    return;
  }

  var security = spawn(this.executablePath, [ 'create-keychain', '-p', opts.password, opts.keychainName]);

  security.on('error', function(err) {
    err = new KeychainAccess.errors.ServiceFailureError(null, err.message);
    fn(err, null);
    return;
  });

  security.on('close', function(code, signal) {
    if (code !== 0) {
      var msg = 'Security returned a non-successful error code: ' + code;
      err = new KeychainAccess.errors.ServiceFailureError(msg);
      err.exitCode = code;
      fn(err);
      return;
    } else {
      fn(null, opts.keychainName);
    }
  });
};

/**
* Delete a keychain from the system.
*
* @param {Object} opts Object containing 'keychainName'
* @param {Function} fn Callback
* @api public
*/
KeychainAccess.prototype.deleteKeychain = function(opts, fn) {
  opts = opts || {};
  fn = fn || noop;
  var err;

  if (!opts.keychainName) {
    err = new KeychainAccess.errors.NoKeychainNameProvidedError();
    fn(err, null);
    return;
  }

  var security = spawn(this.executablePath, [ 'delete-keychain', opts.keychainName]);

  security.on('error', function(err) {
    err = new KeychainAccess.errors.ServiceFailureError(null, err.message);
    fn(err, null);
    return;
  });

  security.on('close', function(code, signal) {
    if (code !== 0) {
      var msg = 'Security returned a non-successful error code: ' + code;
      err = new KeychainAccess.errors.ServiceFailureError(msg);
      err.exitCode = code;
      fn(err);
      return;
    } else {
      fn(null, opts.keychainName);
    }
  });

};

/**
* Set the default keychain for the system.
*
* @param {Object} opts Object containing 'keychainName'
* @param {Function} fn Callback
* @api public
*/
KeychainAccess.prototype.setDefaultKeychain = function(opts, fn) {
  opts = opts || {};
  fn = fn || noop;
  var err;

  if (!opts.keychainName) {
    err = new KeychainAccess.errors.NoKeychainNameProvidedError();
    fn(err, null);
    return;
  }

  var security = spawn(this.executablePath, [ 'default-keychain', '-s', opts.keychainName]);

  security.on('error', function(err) {
    err = new KeychainAccess.errors.ServiceFailureError(null, err.message);
    fn(err, null);
    return;
  });

  security.on('close', function(code, signal) {
    if (code !== 0) {
      var msg = 'Security returned a non-successful error code: ' + code;
      err = new KeychainAccess.errors.ServiceFailureError(msg);
      err.exitCode = code;
      fn(err);
      return;
    } else {
      fn(null, opts.keychainName);
    }
  });
};

function errorClass(code, defaultMsg) {
  var errorType = code + 'Error';
  var ErrorClass = function (msg, append) {
    this.type = errorType;
    this.code = code;
    this.message = (msg || defaultMsg) + (append || '');
    this.stack = (new Error()).stack;
  };

  ErrorClass.prototype = Object.create(Error.prototype);
  ErrorClass.prototype.constructor = ErrorClass;
  KeychainAccess.errors[errorType] = ErrorClass
}

KeychainAccess.errors = {};
errorClass('UnsupportedPlatform', 'Expected darwin platform, got: ');
errorClass('NoAccountProvided', 'An account is required');
errorClass('NoServiceProvided', 'A service is required');
errorClass('NoPasswordProvided', 'A password is required');
errorClass('ServiceFailure', 'Keychain failed to start child process: ');
errorClass('PasswordNotFound', 'Could not find password');
errorClass('NoKeychainNameProvided', 'A keychain name is required');


/**
 * Promise support.
 *
 * Every public method keeps its callback signature exactly. When no callback
 * is passed, it returns a Promise that resolves with the value the callback
 * would have received, or rejects with the same error object.
 */

var PUBLIC_METHODS = [
  'getPassword',
  'setPassword',
  'deletePassword',
  'createKeychain',
  'deleteKeychain',
  'setDefaultKeychain'
];

// Node emits both 'error' and 'close' when spawn fails, so make sure a
// caller's callback runs at most once.
function once(fn) {
  var called = false;
  return function () {
    if (called) return;
    called = true;
    return fn.apply(this, arguments);
  };
}

function withPromise(method) {
  return function (opts, fn) {
    if (typeof fn === 'function') {
      method.call(this, opts, once(fn));
      return;
    }

    // No callback and no Promise (very old Node): behave as before.
    if (typeof Promise !== 'function') {
      method.call(this, opts, noop);
      return;
    }

    var self = this;
    var promise = new Promise(function (resolve, reject) {
      method.call(self, opts, function (err, value) {
        if (err) {
          reject(err);
        } else {
          resolve(value);
        }
      });
    });

    // Callers that used to fire and forget (no callback) never saw errors.
    // Mark the promise handled so they don't start crashing on unhandled
    // rejections; anyone who awaits or .catch()es still gets the error.
    promise.catch(noop);
    return promise;
  };
}

PUBLIC_METHODS.forEach(function (name) {
  KeychainAccess.prototype[name] = withPromise(KeychainAccess.prototype[name]);
});

/**
 * Expose new Keychain Access
 */

module.exports = new KeychainAccess();
