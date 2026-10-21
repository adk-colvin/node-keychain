/*!
 * Backwards-compatibility suite.
 *
 * Pinned against keychain@1.5.0 (master 28ac548) BEFORE the promise API
 * landed. Every assertion here is observable behavior a caller of the
 * callback API could depend on. If a change breaks one of these on purpose,
 * it is a breaking change and needs a major version bump, not a test edit.
 */

var chai = require('chai');
var expect = chai.expect;
var mock = require('../helpers/mock-security');

describe('Backwards compatibility (pinned at 1.5.0)', function () {
  var keychain;
  var errors;

  beforeEach(function () {
    mock.reset();
    mock.pretendDarwin();
    keychain = mock.load();
    errors = keychain.constructor.errors;
  });

  afterEach(function () {
    mock.restorePlatform();
    mock.unload();
  });

  describe('error classes', function () {
    var table = [
      ['UnsupportedPlatformError', 'UnsupportedPlatform', 'Expected darwin platform, got: '],
      ['NoAccountProvidedError', 'NoAccountProvided', 'An account is required'],
      ['NoServiceProvidedError', 'NoServiceProvided', 'A service is required'],
      ['NoPasswordProvidedError', 'NoPasswordProvided', 'A password is required'],
      ['ServiceFailureError', 'ServiceFailure', 'Keychain failed to start child process: '],
      ['PasswordNotFoundError', 'PasswordNotFound', 'Could not find password'],
      ['NoKeychainNameProvidedError', 'NoKeychainNameProvided', 'A keychain name is required']
    ];

    table.forEach(function (row) {
      var name = row[0], code = row[1], defaultMsg = row[2];

      it(name + ': instanceof Error, type/code/message/stack as in 1.5.0', function () {
        var Cls = errors[name];
        expect(Cls).to.be.a('function');
        var e = new Cls();
        expect(e).to.be.instanceOf(Error);
        expect(e).to.be.instanceOf(Cls);
        expect(e.type).to.equal(name);
        expect(e.code).to.equal(code);
        expect(e.message).to.equal(defaultMsg);
        expect(e.stack).to.be.a('string');
        expect(e.constructor).to.equal(Cls);
        expect(Object.getPrototypeOf(Cls.prototype)).to.equal(Error.prototype);
      });

      it(name + ': (msg, append) constructor contract', function () {
        var Cls = errors[name];
        expect(new Cls('custom').message).to.equal('custom');
        expect(new Cls(null, 'tail').message).to.equal(defaultMsg + 'tail');
        expect(new Cls('custom', 'tail').message).to.equal('customtail');
      });
    });

    it('errors are reachable as require("keychain").constructor.errors and are the same objects', function () {
      expect(keychain.constructor.errors).to.equal(errors);
      expect(Object.keys(errors)).to.have.length(7);
    });

    it('errors are plain prototype-chain classes: callable with `new` only, not subclass-of-Error by ES6 `class`', function () {
      // 1.5.0 errors are constructed via `new`; this pins that `new` keeps working
      // and that instances get an own `message` (not inherited).
      var e = new errors.PasswordNotFoundError();
      expect(Object.prototype.hasOwnProperty.call(e, 'message')).to.equal(true);
    });
  });

  describe('callback timing and arity', function () {
    it('validation errors are delivered synchronously, before the method returns', function () {
      var called = false;
      keychain.getPassword({}, function () { called = true; });
      expect(called).to.equal(true);
    });

    it('platform errors are delivered synchronously, before the method returns', function () {
      mock.pretendPlatform('win32');
      var called = false;
      keychain.setPassword({ account: 'a', service: 's', password: 'p' }, function () { called = true; });
      expect(called).to.equal(true);
    });

    it('security-backed results are delivered asynchronously, after the method returns', function (done) {
      mock.respond(mock.findOutput('p'));
      var called = false;
      keychain.getPassword({ account: 'a', service: 's' }, function () {
        called = true;
        done();
      });
      expect(called).to.equal(false);
    });

    it('validation errors call back with exactly (err, null)', function () {
      var args;
      keychain.getPassword({}, function () { args = Array.prototype.slice.call(arguments); });
      expect(args).to.have.length(2);
      expect(args[0]).to.be.instanceOf(errors.NoAccountProvidedError);
      expect(args[1]).to.equal(null);
    });

    it('getPassword success calls back with exactly (null, password)', function (done) {
      mock.respond(mock.findOutput('p'));
      keychain.getPassword({ account: 'a', service: 's' }, function () {
        var args = Array.prototype.slice.call(arguments);
        expect(args).to.deep.equal([null, 'p']);
        done();
      });
    });

    it('getPassword not-found calls back with exactly (err, null)', function (done) {
      mock.respond({ code: 44 });
      keychain.getPassword({ account: 'a', service: 's' }, function () {
        var args = Array.prototype.slice.call(arguments);
        expect(args).to.have.length(2);
        expect(args[0]).to.be.instanceOf(errors.PasswordNotFoundError);
        expect(args[1]).to.equal(null);
        done();
      });
    });

    it('setPassword success calls back with exactly (null, password)', function (done) {
      mock.respond({ code: 0 });
      keychain.setPassword({ account: 'a', service: 's', password: 'p' }, function () {
        expect(Array.prototype.slice.call(arguments)).to.deep.equal([null, 'p']);
        done();
      });
    });

    it('setPassword service failure calls back with exactly (err) — one argument', function (done) {
      mock.respond({ code: 36 });
      keychain.setPassword({ account: 'a', service: 's', password: 'p' }, function () {
        var args = Array.prototype.slice.call(arguments);
        expect(args).to.have.length(1);
        expect(args[0]).to.be.instanceOf(errors.ServiceFailureError);
        expect(args[0].exitCode).to.equal(36);
        done();
      });
    });

    it('deletePassword success calls back with exactly (null) — one argument', function (done) {
      mock.respond({ code: 0 });
      keychain.deletePassword({ account: 'a', service: 's' }, function () {
        expect(Array.prototype.slice.call(arguments)).to.deep.equal([null]);
        done();
      });
    });

    it('deletePassword failure calls back with exactly (err) — one argument', function (done) {
      mock.respond({ code: 44 });
      keychain.deletePassword({ account: 'a', service: 's' }, function () {
        var args = Array.prototype.slice.call(arguments);
        expect(args).to.have.length(1);
        expect(args[0]).to.be.instanceOf(errors.PasswordNotFoundError);
        done();
      });
    });

    ['createKeychain', 'deleteKeychain', 'setDefaultKeychain'].forEach(function (method) {
      it(method + ' success calls back with exactly (null, keychainName)', function (done) {
        mock.respond({ code: 0 });
        keychain[method]({ keychainName: 'k', password: 'p' }, function () {
          expect(Array.prototype.slice.call(arguments)).to.deep.equal([null, 'k']);
          done();
        });
      });

      it(method + ' failure calls back with exactly (err) carrying exitCode', function (done) {
        mock.respond({ code: 7 });
        keychain[method]({ keychainName: 'k', password: 'p' }, function () {
          var args = Array.prototype.slice.call(arguments);
          expect(args).to.have.length(1);
          expect(args[0]).to.be.instanceOf(errors.ServiceFailureError);
          expect(args[0].message).to.equal('Security returned a non-successful error code: 7');
          expect(args[0].exitCode).to.equal(7);
          done();
        });
      });
    });

    it('spawn failure calls back with exactly (err, null) for every method', function (done) {
      var methods = ['getPassword', 'setPassword', 'deletePassword', 'createKeychain', 'deleteKeychain', 'setDefaultKeychain'];
      var remaining = methods.length;
      methods.forEach(function (method) {
        mock.respond({ error: new Error('boom') });
        keychain[method]({ account: 'a', service: 's', password: 'p', keychainName: 'k' }, function () {
          var args = Array.prototype.slice.call(arguments);
          expect(args, method).to.have.length(2);
          expect(args[0], method).to.be.instanceOf(errors.ServiceFailureError);
          expect(args[0].message, method).to.equal('Keychain failed to start child process: boom');
          expect(args[1], method).to.equal(null);
          if (--remaining === 0) done();
        });
      });
    });
  });

  describe('calling convention', function () {
    var methods = ['getPassword', 'setPassword', 'deletePassword', 'createKeychain', 'deleteKeychain', 'setDefaultKeychain'];

    methods.forEach(function (method) {
      it(method + ' returns undefined when a callback is given (no promise to leak or double-deliver)', function (done) {
        mock.respond({ code: 0, stderr: 'password: "p"\n' });
        var ret = keychain[method]({ account: 'a', service: 's', password: 'p', keychainName: 'k' }, function () { done(); });
        expect(ret).to.equal(undefined);
      });

      it(method + ' with a callback never throws synchronously on bad input', function () {
        expect(function () { keychain[method](undefined, function () {}); }).to.not.throw();
        expect(function () { keychain[method]({}, function () {}); }).to.not.throw();
        expect(function () { keychain[method](null, function () {}); }).to.not.throw();
      });
    });

    it('a missing callback is tolerated on valid input and security is still invoked', function (done) {
      mock.respond({ code: 0 });
      var ret = keychain.setPassword({ account: 'a', service: 's', password: 'p' });
      // 1.5.0 returns undefined; a promise-returning successor must still not throw here.
      if (ret && typeof ret.then === 'function') ret.then(function () {}, function () {});
      setImmediate(function () {
        expect(mock.calls).to.have.length(1);
        done();
      });
    });

    it('the `type` option is lower-cased, defaulted to generic, and written back onto the caller\'s opts object', function (done) {
      mock.respond({ code: 0 });
      var opts = { account: 'a', service: 's', type: 'Internet' };
      keychain.deletePassword(opts, function () {
        expect(opts.type).to.equal('internet');
        var opts2 = { account: 'a', service: 's' };
        mock.respond({ code: 0 });
        keychain.deletePassword(opts2, function () {
          expect(opts2.type).to.equal('generic');
          done();
        });
      });
    });

    it('executablePath is an own, writable instance property defaulting to /usr/bin/security', function () {
      expect(Object.prototype.hasOwnProperty.call(keychain, 'executablePath')).to.equal(true);
      expect(keychain.executablePath).to.equal('/usr/bin/security');
      keychain.executablePath = '/x';
      expect(keychain.executablePath).to.equal('/x');
    });

    it('module.exports is a singleton instance whose prototype methods are the six public methods', function () {
      var proto = Object.getPrototypeOf(keychain);
      expect(Object.keys(proto).sort()).to.deep.equal(
        ['createKeychain', 'deleteKeychain', 'deletePassword', 'getPassword', 'setDefaultKeychain', 'setPassword']
      );
      methods.forEach(function (m) { expect(keychain[m].length, m).to.equal(2); });
    });
  });

  // The commands `security` executes are pinned, not the raw argv: since 1.6
  // the two methods that carry a password (setPassword, createKeychain) send
  // the command line over stdin to `security -i` so it never shows up in ps,
  // and keychain names are protected with "--". What security *runs* is the
  // same command 1.5.0 ran. mock.commands() is a port of security's own
  // split_line, so this is what the tool would actually see.
  describe('commands executed by `security` (exact, as security parses them)', function () {
    var cases = [
      ['getPassword', { account: 'A', service: 'S' }, ['find-generic-password', '-a', 'A', '-s', 'S', '-g']],
      ['getPassword', { account: 'A', service: 'S', type: 'internet' }, ['find-internet-password', '-a', 'A', '-s', 'S', '-g']],
      ['setPassword', { account: 'A', service: 'S', password: 'P' }, ['add-generic-password', '-a', 'A', '-s', 'S', '-w', 'P']],
      ['setPassword', { account: 'A', service: 'S', password: 'P', type: 'internet' }, ['add-internet-password', '-a', 'A', '-s', 'S', '-w', 'P']],
      ['deletePassword', { account: 'A', service: 'S' }, ['delete-generic-password', '-a', 'A', '-s', 'S']],
      ['deletePassword', { account: 'A', service: 'S', type: 'internet' }, ['delete-internet-password', '-a', 'A', '-s', 'S']],
      ['createKeychain', { keychainName: 'K', password: 'P' }, ['create-keychain', '-p', 'P', '--', 'K']],
      ['deleteKeychain', { keychainName: 'K' }, ['delete-keychain', '--', 'K']],
      ['setDefaultKeychain', { keychainName: 'K' }, ['default-keychain', '-s', '--', 'K']]
    ];
    var secretMethods = ['setPassword', 'createKeychain'];

    cases.forEach(function (c) {
      var method = c[0], opts = c[1], argv = c[2];
      it(method + '(' + JSON.stringify(opts) + ') -> security ' + argv.join(' '), function (done) {
        mock.respond({ code: 0, stderr: 'password: "P"\n' });
        keychain[method](opts, function () {
          expect(mock.calls).to.have.length(1);
          expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
          expect(mock.commands(mock.calls[0])).to.deep.equal([argv]);
          if (secretMethods.indexOf(method) !== -1) {
            // password travels on stdin via `security -i`, never in argv
            expect(mock.calls[0].args).to.deep.equal(['-i']);
            expect(mock.calls[0].args.join(' ')).to.not.contain('P');
          } else {
            expect(mock.calls[0].args).to.deep.equal(argv);
          }
          done();
        });
      });
    });

    // `security -i` reads one line per command and its readline() stops at a
    // newline or after 4095 bytes, so values that cannot survive that transport
    // fall back to the 1.5.0 behaviour: the full command in argv, nothing on
    // stdin. Pinned so the fallback stays byte-identical to what 1.5.0 ran.
    describe('falls back to the 1.5.0 argv transport when the line cannot go through `security -i`', function () {
      var LIMIT = 4094;
      var fallbackValues = [
        ['newline', 'pass\nword'],
        ['NUL byte', 'pass\0word'],
        ['line over ' + LIMIT + ' bytes', 'x'.repeat(LIMIT + 1)]
      ];

      fallbackValues.forEach(function (c) {
        var label = c[0], value = c[1];

        it('setPassword with a ' + label + ' password: argv is the 1.5.0 argv, stdin untouched', function (done) {
          mock.respond({ code: 0 });
          var expected = ['add-generic-password', '-a', 'A', '-s', 'S', '-w', value];
          keychain.setPassword({ account: 'A', service: 'S', password: value }, function (err, pw) {
            expect(err).to.equal(null);
            expect(pw).to.equal(value);
            expect(mock.calls).to.have.length(1);
            expect(mock.calls[0].args).to.deep.equal(expected);
            expect(mock.calls[0].args).to.not.include('-i');
            expect(mock.calls[0].stdin).to.equal('');
            done();
          });
        });

        it('createKeychain with a ' + label + ' password: argv is the 1.5.0 argv plus "--", stdin untouched', function (done) {
          mock.respond({ code: 0 });
          var expected = ['create-keychain', '-p', value, '--', 'K'];
          keychain.createKeychain({ keychainName: 'K', password: value }, function (err, name) {
            expect(err).to.equal(null);
            expect(name).to.equal('K');
            expect(mock.calls).to.have.length(1);
            expect(mock.calls[0].args).to.deep.equal(expected);
            expect(mock.calls[0].stdin).to.equal('');
            done();
          });
        });
      });

      it('a command line of exactly ' + LIMIT + ' bytes still travels on stdin (boundary)', function (done) {
        // Every token is double-quoted on the -i line; the password fills what is left of the limit.
        var framing = Buffer.byteLength('"add-generic-password" "-a" "A" "-s" "S" "-w" ""', 'utf8');
        var value = 'x'.repeat(LIMIT - framing);
        mock.respond({ code: 0 });
        keychain.setPassword({ account: 'A', service: 'S', password: value }, function (err) {
          expect(err).to.equal(null);
          expect(mock.calls[0].args).to.deep.equal(['-i']);
          expect(Buffer.byteLength(mock.calls[0].stdin, 'utf8')).to.equal(LIMIT + 1); // + trailing newline
          expect(mock.commands(mock.calls[0])).to.deep.equal([['add-generic-password', '-a', 'A', '-s', 'S', '-w', value]]);
          done();
        });
      });

      it('one byte over the limit falls back to argv (boundary)', function (done) {
        var framing = Buffer.byteLength('"add-generic-password" "-a" "A" "-s" "S" "-w" ""', 'utf8');
        var value = 'x'.repeat(LIMIT - framing + 1);
        mock.respond({ code: 0 });
        keychain.setPassword({ account: 'A', service: 'S', password: value }, function (err) {
          expect(err).to.equal(null);
          expect(mock.calls[0].args).to.deep.equal(['add-generic-password', '-a', 'A', '-s', 'S', '-w', value]);
          expect(mock.calls[0].stdin).to.equal('');
          done();
        });
      });
    });

    it('security is always invoked by absolute path with an argv array (no shell string)', function (done) {
      mock.respond({ code: 0 });
      keychain.setPassword({ account: 'a b', service: 's;rm -rf /', password: '$(id)' }, function () {
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.be.an('array');
        var cmd = mock.commands(mock.calls[0]);
        expect(cmd).to.have.length(1);
        expect(cmd[0]).to.include('s;rm -rf /');
        expect(cmd[0]).to.include('$(id)');
        done();
      });
    });

    it('setPassword exit 45 retry sequence is add -> delete -> add with identical -a/-s', function (done) {
      mock.respond({ code: 45 });
      mock.respond({ code: 0 });
      mock.respond({ code: 0 });
      keychain.setPassword({ account: 'A', service: 'S', password: 'P' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('P');
        expect(mock.calls.map(function (c) { return mock.commands(c)[0]; })).to.deep.equal([
          ['add-generic-password', '-a', 'A', '-s', 'S', '-w', 'P'],
          ['delete-generic-password', '-a', 'A', '-s', 'S'],
          ['add-generic-password', '-a', 'A', '-s', 'S', '-w', 'P']
        ]);
        done();
      });
    });
  });

  describe('password parsing', function () {
    it('hex form wins over the quoted form when both are present', function (done) {
      // security prints: password: 0x70617373576974685C  "passWith\134"
      mock.respond({ code: 0, stderr: 'password: 0x70617373576974685C  "passWith\\134"\n' });
      keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
        expect(pass).to.equal('passWith\\');
        done();
      });
    });

    it('hex form is decoded as UTF-8', function (done) {
      mock.respond({ code: 0, stderr: 'password: 0xE28886656C7461\n' });
      keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
        expect(pass).to.equal('∆elta');
        done();
      });
    });

    it('quoted form is returned verbatim, including inner quotes and spaces', function (done) {
      mock.respond({ code: 0, stderr: 'password: "a "b" c"\n' });
      keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
        expect(pass).to.equal('a "b" c');
        done();
      });
    });

    it('the password line is read from stderr, not stdout', function (done) {
      mock.respond({ code: 0, stdout: 'password: "from-stdout"\n', stderr: 'password: "from-stderr"\n' });
      keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
        expect(pass).to.equal('from-stderr');
        done();
      });
    });
  });
});
