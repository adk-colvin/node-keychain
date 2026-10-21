/*!
 * Test helper: a fake `child_process.spawn` that stands in for the macOS
 * `security` CLI so the suite runs on any OS.
 *
 * keychain.js captures `spawn` at require time, so the stub must be installed
 * BEFORE the module is loaded. `load()` does that and returns a fresh copy of
 * the module. `process.platform` is forced to 'darwin' for the duration of a
 * test via `pretendDarwin()` / `restorePlatform()`.
 */

var EventEmitter = require('events').EventEmitter;
var childProcess = require('child_process');
var path = require('path');

var MODULE_PATH = path.resolve(__dirname, '..', '..', 'keychain.js');
var realSpawn = childProcess.spawn;
var realPlatform = Object.getOwnPropertyDescriptor(process, 'platform');

/**
 * Recorded spawn calls: [{ cmd, args }]
 */
var calls = [];

/**
 * Scripted responses, consumed in order. Each is:
 *   { stdout: String|[String], stderr: String|[String], code: Number, signal: String }
 *   or { error: Error }  -> emits 'error' instead of running
 * When the script is empty, the fake exits 0 with no output.
 */
var script = [];

function toChunks(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function fakeSpawn(cmd, args) {
  var child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.pid = 4242;
  child.kill = function () {};
  calls.push({ cmd: cmd, args: (args || []).slice() });

  var step = script.length ? script.shift() : { code: 0 };

  // Deliver asynchronously, like a real child process would.
  setImmediate(function () {
    if (step.error) {
      child.emit('error', step.error);
      return;
    }
    toChunks(step.stdout).forEach(function (c) { child.stdout.emit('data', Buffer.from(c)); });
    toChunks(step.stderr).forEach(function (c) { child.stderr.emit('data', Buffer.from(c)); });
    var code = step.code === undefined ? 0 : step.code;
    child.emit('exit', code, step.signal || null);
    child.emit('close', code, step.signal || null);
  });

  return child;
}

module.exports = {
  calls: calls,
  script: script,

  /** Install the fake spawn and return a freshly loaded keychain module. */
  load: function () {
    childProcess.spawn = fakeSpawn;
    delete require.cache[MODULE_PATH];
    var mod = require(MODULE_PATH);
    return mod;
  },

  /** Put the real spawn back and drop the cached module. */
  unload: function () {
    childProcess.spawn = realSpawn;
    delete require.cache[MODULE_PATH];
  },

  /** Queue one scripted `security` run. */
  respond: function (step) {
    script.push(step);
  },

  /** Forget recorded calls and queued responses. */
  reset: function () {
    calls.length = 0;
    script.length = 0;
  },

  pretendDarwin: function () {
    Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });
  },

  pretendPlatform: function (name) {
    Object.defineProperty(process, 'platform', { value: name, configurable: true });
  },

  restorePlatform: function () {
    Object.defineProperty(process, 'platform', realPlatform);
  },

  /** Helper: what `security find-*-password -g` prints for a password. */
  findOutput: function (password, opts) {
    opts = opts || {};
    var stdout = 'keychain: "/Users/test/Library/Keychains/login.keychain-db"\n' +
      'class: "genp"\nattributes:\n    "acct"<blob>="' + (opts.account || 'acct') + '"\n' +
      '    "svce"<blob>="' + (opts.service || 'svc') + '"\n';
    var stderr;
    if (opts.hex) {
      var hex = Buffer.from(password, 'utf8').toString('hex').toUpperCase();
      stderr = 'password: 0x' + hex + (opts.quoted === false ? '' : '  "' + opts.quoted + '"') + '\n';
    } else {
      stderr = 'password: "' + password + '"\n';
    }
    return { stdout: stdout, stderr: stderr, code: 0 };
  }
};
