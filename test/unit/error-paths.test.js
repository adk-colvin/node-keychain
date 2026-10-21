// Pins 1.5.0's error behavior on every path, through both the callback and the
// promise API. Mocked, so it runs on any OS.
var fake = require('../helpers/fake-spawn');
fake.install();
var keychain = require('../../');
fake.restore();
var errors = keychain.constructor.errors;
var chai = require('chai');
var expect = chai.expect;

// Calls method both ways and hands each (err, value) to check.
// NK_CALLBACK_ONLY=1 runs just the callback half, to check these against 1.5.0.
var CALLBACK_ONLY = !!process.env.NK_CALLBACK_ONLY;

function bothWays(method, opts, check) {
  function copy() { return opts === undefined ? undefined : Object.assign({}, opts); }
  return new Promise(function (resolve, reject) {
    var calls = 0;
    keychain[method](copy(), function (err, value) {
      calls++;
      if (calls > 1) return; // counted below; 1.5.0 sometimes called back twice
      try { check(err, value, 'callback'); } catch (e) { return reject(e); }
      // Give a stray second callback (spawn 'error' + 'close') a chance to show up.
      setTimeout(function () {
        try { if (!CALLBACK_ONLY) expect(calls, 'callback calls').to.equal(1); resolve(); } catch (e) { reject(e); }
      }, 5);
    });
  }).then(function () {
    if (CALLBACK_ONLY) return;
    var p = keychain[method](copy());
    expect(p).to.be.an.instanceof(Promise);
    return p.then(function (value) { check(null, value, 'promise'); },
                  function (err) { check(err, undefined, 'promise'); });
  });
}

function expectError(Type, code) {
  return function (err, value, how) {
    expect(err, how).to.be.an.instanceof(Type);
    expect(err, how).to.be.an.instanceof(Error);
    expect(err.code, how).to.equal(code);
    expect(err.type, how).to.equal(code + 'Error');
    if (how === 'callback' && arguments.length > 1 && value !== undefined) expect(value).to.equal(null);
  };
}

var pw = { account: 'a', service: 's', password: 'p' };
var kc = { keychainName: 'k.keychain', password: 'p' };

describe('error paths (mocked security, callback and promise)', function () {
  beforeEach(function () { fake.install(); fake.respond({ code: 0 }); });
  afterEach(function () { fake.restore(); });

  describe('input validation fails before spawning security', function () {
    [
      ['getPassword', { service: 's' }, 'NoAccountProvided'],
      ['getPassword', { account: 'a' }, 'NoServiceProvided'],
      ['setPassword', { service: 's', password: 'p' }, 'NoAccountProvided'],
      ['setPassword', { account: 'a', password: 'p' }, 'NoServiceProvided'],
      ['setPassword', { account: 'a', service: 's' }, 'NoPasswordProvided'],
      ['deletePassword', { service: 's' }, 'NoAccountProvided'],
      ['deletePassword', { account: 'a' }, 'NoServiceProvided'],
      ['createKeychain', { password: 'p' }, 'NoKeychainNameProvided'],
      ['createKeychain', { keychainName: 'k' }, 'NoPasswordProvided'],
      ['deleteKeychain', {}, 'NoKeychainNameProvided'],
      ['setDefaultKeychain', {}, 'NoKeychainNameProvided']
    ].forEach(function (c) {
      it(c[0] + ' ' + JSON.stringify(c[1]) + ' -> ' + c[2] + 'Error', function () {
        return bothWays(c[0], c[1], expectError(errors[c[2] + 'Error'], c[2])).then(function () {
          expect(fake.calls).to.have.length(0);
        });
      });
    });

    [
      ['getPassword', 'NoAccountProvided'], ['setPassword', 'NoAccountProvided'],
      ['deletePassword', 'NoAccountProvided'], ['createKeychain', 'NoKeychainNameProvided'],
      ['deleteKeychain', 'NoKeychainNameProvided'], ['setDefaultKeychain', 'NoKeychainNameProvided']
    ].forEach(function (c) {
      it(c[0] + ' with no opts at all -> ' + c[1] + 'Error (no throw)', function () {
        return bothWays(c[0], undefined, expectError(errors[c[1] + 'Error'], c[1]));
      });
    });
  });

  describe('password methods refuse non-darwin platforms', function () {
    ['getPassword', 'setPassword', 'deletePassword'].forEach(function (m) {
      it(m, function () {
        Object.defineProperty(process, 'platform', { value: 'linux' });
        return bothWays(m, pw, function (err, value, how) {
          expectError(errors.UnsupportedPlatformError, 'UnsupportedPlatform')(err, value, how);
          expect(err.message, how).to.equal('Expected darwin platform, got: linux');
        }).then(function () { expect(fake.calls).to.have.length(0); });
      });
    });
  });

  describe('security failing to start -> ServiceFailureError, callback called once', function () {
    [
      ['getPassword', pw], ['setPassword', pw], ['deletePassword', pw],
      ['createKeychain', kc], ['deleteKeychain', kc], ['setDefaultKeychain', kc]
    ].forEach(function (c) {
      it(c[0], function () {
        fake.respond({ error: 'spawn /usr/bin/security ENOENT' });
        return bothWays(c[0], c[1], function (err, value, how) {
          expectError(errors.ServiceFailureError, 'ServiceFailure')(err, value, how);
          expect(err.message, how).to.equal('Keychain failed to start child process: spawn /usr/bin/security ENOENT');
        });
      });
    });
  });

  describe('non-zero exit codes', function () {
    it('getPassword -> PasswordNotFoundError', function () {
      fake.respond({ code: 44, stderr: 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n' });
      return bothWays('getPassword', pw, expectError(errors.PasswordNotFoundError, 'PasswordNotFound'));
    });

    it('deletePassword -> PasswordNotFoundError', function () {
      fake.respond({ code: 44 });
      return bothWays('deletePassword', pw, expectError(errors.PasswordNotFoundError, 'PasswordNotFound'));
    });

    [['createKeychain', 48], ['deleteKeychain', 50], ['setDefaultKeychain', 1], ['setPassword', 51]].forEach(function (c) {
      it(c[0] + ' -> ServiceFailureError with exitCode', function () {
        fake.respond({ code: c[1] });
        return bothWays(c[0], c[0] === 'setPassword' ? pw : kc, function (err, value, how) {
          expectError(errors.ServiceFailureError, 'ServiceFailure')(err, value, how);
          expect(err.message, how).to.equal('Security returned a non-successful error code: ' + c[1]);
          expect(err.exitCode, how).to.equal(c[1]);
        });
      });
    });

    it('setPassword exit 45 whose delete fails passes the delete error through', function () {
      fake.respond(function (call) {
        var argv = fake.commands(call)[0];
        return { code: argv[0] === 'delete-generic-password' ? 44 : 45 };
      });
      return bothWays('setPassword', pw, expectError(errors.PasswordNotFoundError, 'PasswordNotFound'));
    });
  });

  describe('getPassword output parsing', function () {
    function got(stderr, expected) {
      // Real security prints the item's attributes on stdout, the password on stderr.
      fake.respond({ code: 0, stdout: 'keychain: "/Users/me/Library/Keychains/login.keychain-db"\nclass: "genp"\n', stderr: stderr });
      return bothWays('getPassword', pw, function (err, value, how) {
        expect(err, how).to.equal(null);
        expect(value, how).to.equal(expected);
      });
    }

    it('quoted value', function () { return got('password: "plain"\n', 'plain'); });
    it('hex value wins over the quoted one', function () { return got('password: 0x70617373576974685C  "passWith\\134"\n', 'passWith\\'); });
    it('hex-only (non-ASCII) value', function () { return got('password: 0xE28886CB9A\n', '∆˚'); });
    it('empty quoted value', function () { return got('password: ""\n', ''); });

    [['no password line', 'nothing useful\n'], ['unparseable password line', 'password: <redacted>\n'], ['no stderr at all', '']].forEach(function (c) {
      it(c[0] + ' -> PasswordNotFoundError', function () {
        fake.respond({ code: 0, stderr: c[1] });
        return bothWays('getPassword', pw, expectError(errors.PasswordNotFoundError, 'PasswordNotFound'));
      });
    });
  });

  describe('callback-less calls on a runtime without Promise', function () {
    var saved;
    beforeEach(function () { saved = global.Promise; });
    afterEach(function () { global.Promise = saved; });

    it('return undefined and still run security, as 1.5.0 did', function (done) {
      var P = global.Promise;
      global.Promise = undefined;
      var ret = keychain.deletePassword({ account: 'a', service: 's' });
      global.Promise = P;
      expect(ret).to.equal(undefined);
      setImmediate(function () {
        expect(fake.calls).to.have.length(1);
        done();
      });
    });
  });

  describe('error classes keep the 1.5.0 shape', function () {
    var expected = {
      UnsupportedPlatformError: 'Expected darwin platform, got: ',
      NoAccountProvidedError: 'An account is required',
      NoServiceProvidedError: 'A service is required',
      NoPasswordProvidedError: 'A password is required',
      ServiceFailureError: 'Keychain failed to start child process: ',
      PasswordNotFoundError: 'Could not find password',
      NoKeychainNameProvidedError: 'A keychain name is required'
    };

    it('exposes exactly the 1.5.0 classes', function () {
      expect(Object.keys(errors).sort()).to.deep.equal(Object.keys(expected).sort());
    });

    Object.keys(expected).forEach(function (name) {
      it(name + ' default message, append, type/code, stack', function () {
        var e = new errors[name]();
        expect(e).to.be.an.instanceof(Error);
        expect(e.constructor).to.equal(errors[name]);
        expect(e.message).to.equal(expected[name]);
        expect(e.type).to.equal(name);
        expect(e.code).to.equal(name.replace(/Error$/, ''));
        expect(e.stack).to.be.a('string');
        expect(new errors[name]('custom', '!').message).to.equal('custom!');
      });
    });
  });
});
