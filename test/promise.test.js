// Promise API: every method returns a Promise when no callback is passed, and
// behaves exactly as before when one is. Mocked, so it runs on any OS.
var fake = require('./helpers/fake-spawn');
fake.install();
var keychain = require('../');
fake.restore();
var chai = require('chai');
chai.should();

var errors = keychain.constructor.errors;

var cases = [
  { method: 'getPassword', opts: { account: 'a', service: 's' }, ok: { stderr: 'password: "secret"\n' }, value: 'secret' },
  { method: 'setPassword', opts: { account: 'a', service: 's', password: 'secret' }, ok: {}, value: 'secret' },
  { method: 'deletePassword', opts: { account: 'a', service: 's' }, ok: {}, value: undefined },
  { method: 'createKeychain', opts: { keychainName: 'k.keychain', password: 'pw' }, ok: {}, value: 'k.keychain' },
  { method: 'deleteKeychain', opts: { keychainName: 'k.keychain' }, ok: {}, value: 'k.keychain' },
  { method: 'setDefaultKeychain', opts: { keychainName: 'k.keychain' }, ok: {}, value: 'k.keychain' }
];

describe('promise API (mocked security)', function () {
  beforeEach(function () { fake.install(); });
  afterEach(function () { fake.restore(); });

  cases.forEach(function (c) {
    describe('.' + c.method + '(opts)', function () {
      it('returns a Promise when no callback is passed', function () {
        fake.respond(c.ok);
        var p = keychain[c.method](Object.assign({}, c.opts));
        p.should.be.instanceOf(Promise);
        return p;
      });

      it('resolves with the value the callback gets', function (done) {
        fake.respond(c.ok);
        keychain[c.method](Object.assign({}, c.opts), function (err, cbValue) {
          (err === null || err === undefined).should.equal(true);
          fake.respond(c.ok);
          keychain[c.method](Object.assign({}, c.opts)).then(function (value) {
            (value === cbValue).should.equal(true);
            (value === c.value).should.equal(true);
            done();
          }, done);
        });
      });

      it('rejects with the same error class the callback gets', function (done) {
        fake.respond({ code: 1 });
        keychain[c.method](Object.assign({}, c.opts), function (cbErr) {
          fake.respond({ code: 1 });
          keychain[c.method](Object.assign({}, c.opts)).then(function () {
            done(new Error('expected a rejection'));
          }, function (err) {
            err.constructor.should.equal(cbErr.constructor);
            err.code.should.equal(cbErr.code);
            err.message.should.equal(cbErr.message);
            done();
          });
        });
      });

      it('returns undefined when a callback is passed', function (done) {
        fake.respond(c.ok);
        (keychain[c.method](Object.assign({}, c.opts), function () { done(); }) === undefined).should.equal(true);
      });

      it('rejects validation errors (missing options)', function () {
        return keychain[c.method]({}).then(function () {
          throw new Error('expected a rejection');
        }, function (err) {
          err.should.be.instanceOf(Error);
          (typeof err.code).should.equal('string');
        });
      });
    });
  });

  it('still calls back synchronously for validation errors', function () {
    var called = false;
    keychain.getPassword({ service: 's' }, function (err) {
      err.should.be.instanceOf(errors.NoAccountProvidedError);
      called = true;
    });
    called.should.equal(true);
  });

  it('rejects with UnsupportedPlatformError off macOS', function () {
    Object.defineProperty(process, 'platform', { value: 'linux' });
    return keychain.getPassword({ account: 'a', service: 's' }).then(function () {
      throw new Error('expected a rejection');
    }, function (err) {
      err.should.be.instanceOf(errors.UnsupportedPlatformError);
      err.message.should.equal('Expected darwin platform, got: linux');
    });
  });

  it('setPassword resolves after replacing an existing item (exit 45)', function () {
    var codes = [45, 0, 0];
    fake.respond({ code: 45 });
    var childProcess = require('child_process');
    var stub = childProcess.spawn;
    childProcess.spawn = function (cmd, args) {
      fake.respond({ code: codes.shift() });
      return stub(cmd, args);
    };
    return keychain.setPassword({ account: 'a', service: 's', password: 'new' }).then(function (pw) {
      pw.should.equal('new');
      fake.calls.map(function (c) { return c.args[0]; })
        .should.deep.equal(['add-generic-password', 'delete-generic-password', 'add-generic-password']);
    });
  });

  it('works with async/await', async function () {
    fake.respond({ stderr: 'password: 0xE28886656C7461\n' });
    var pass = await keychain.getPassword({ account: 'a', service: 's' });
    pass.should.equal('∆elta');
  });

  it('does not crash fire-and-forget callers on errors (no unhandled rejection)', function (done) {
    var unhandled = [];
    var onUnhandled = function (reason) { unhandled.push(reason); };
    process.on('unhandledRejection', onUnhandled);
    fake.respond({ code: 1 });
    keychain.deletePassword({ account: 'a', service: 's' });
    keychain.setPassword({});
    setTimeout(function () {
      process.removeListener('unhandledRejection', onUnhandled);
      unhandled.length.should.equal(0);
      done();
    }, 50);
  });
});
