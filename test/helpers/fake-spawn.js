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
    var call = exports.calls[exports.calls.length - 1];
    call.stdin = '';
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = {
      write: function (data) { call.stdin += data; return true; },
      end: function (data) { if (data) call.stdin += data; call.stdinEnded = true; },
      on: function () { return child.stdin; }
    };
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

// What `security` would actually run for a call: its argv, or for `security -i`
// the commands it parses from stdin (a port of split_line in Apple's
// SecurityTool/macOS/security.c, with readline's 4095-byte line limit).
exports.commands = function (call) {
  if (call.args[0] !== '-i') return [call.args];
  var bytes = Buffer.from(call.stdin, 'utf8');
  var lines = [];
  var line = [];
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x0a || line.length === 4095) {
      lines.push(Buffer.from(line).toString('utf8'));
      line = [];
      if (bytes[i] === 0x0a) continue;
    }
    line.push(bytes[i]);
  }
  if (line.length) lines.push(Buffer.from(line).toString('utf8'));
  return lines.map(splitLine).filter(function (argv) { return argv.length; });
};

function splitLine(line) {
  var args = [];
  var cur = null;
  var state = 'ws';
  var quote = null;
  var cut = line.indexOf('\0');
  if (cut !== -1) line = line.slice(0, cut);
  for (var i = 0; i < line.length; i++) {
    var ch = line[i];
    if (state === 'ws') {
      if (/[ \t\n\v\f\r]/.test(ch)) continue;
      cur = '';
      if (ch === '"' || ch === "'") { quote = ch; state = 'quoted'; continue; }
      state = 'arg';
    }
    if (state === 'arg') {
      if (ch === '\\') { state = 'argEsc'; continue; }
      if (/[ \t\n\v\f\r]/.test(ch)) { args.push(cur); state = 'ws'; continue; }
      cur += ch; continue;
    }
    if (state === 'argEsc') { cur += ch; state = 'arg'; continue; }
    if (state === 'quoted') {
      if (ch === '\\') { state = 'quotedEsc'; continue; }
      if (ch === quote) { args.push(cur); state = 'ws'; continue; }
      cur += ch; continue;
    }
    if (state === 'quotedEsc') { cur += ch; state = 'quoted'; continue; }
  }
  if (state !== 'ws') args.push(cur);
  return args;
}
exports.splitLine = splitLine;
