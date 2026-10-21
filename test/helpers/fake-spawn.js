// Stand-in for child_process.spawn so tests run on any OS without touching a
// real keychain. Install it before requiring keychain.js.
var childProcess = require('child_process');
var EventEmitter = require('events').EventEmitter;

var realSpawn = childProcess.spawn;
var realPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
var behavior = null;

exports.calls = [];

// script: { stdout, stderr, code } or { error: 'message' } (spawn failure:
// emits 'error' then 'close' with code -2, the way Node does).
exports.respond = function (script) {
  behavior = script;
};

exports.install = function () {
  exports.calls = [];
  Object.defineProperty(process, 'platform', { value: 'darwin' });
  childProcess.spawn = function (command, args, options) {
    exports.calls.push({ command: command, args: args, options: options });
    var child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    var script = behavior || { code: 0 };
    setImmediate(function () {
      if (script.error) {
        var err = new Error(script.error);
        err.code = 'ENOENT';
        child.emit('error', err);
        child.emit('close', -2, null);
        return;
      }
      if (script.stdout) child.stdout.emit('data', Buffer.from(script.stdout));
      if (script.stderr) child.stderr.emit('data', Buffer.from(script.stderr));
      child.emit('close', script.code || 0, null);
    });
    return child;
  };
};

exports.restore = function () {
  childProcess.spawn = realSpawn;
  Object.defineProperty(process, 'platform', realPlatform);
  behavior = null;
};
