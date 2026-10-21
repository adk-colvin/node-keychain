/*!
 * Unit suite: every code path in keychain.js, with the `security` CLI faked.
 * Runs on any OS.
 */

var chai = require('chai');
var expect = chai.expect;
var mock = require('../helpers/mock-security');

describe('KeychainAccess (unit, mocked security)', function () {
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

  describe('module shape', function () {
    it('exports a KeychainAccess instance with executablePath /usr/bin/security', function () {
      expect(keychain.executablePath).to.equal('/usr/bin/security');
      expect(keychain.constructor.name).to.equal('KeychainAccess');
    });

    it('exposes the seven error classes on the constructor', function () {
      expect(Object.keys(errors).sort()).to.deep.equal([
        'NoAccountProvidedError',
        'NoKeychainNameProvidedError',
        'NoPasswordProvidedError',
        'NoServiceProvidedError',
        'PasswordNotFoundError',
        'ServiceFailureError',
        'UnsupportedPlatformError'
      ]);
    });
  });

  describe('platform guard', function () {
    ['getPassword', 'setPassword', 'deletePassword'].forEach(function (method) {
      it(method + ' fails with UnsupportedPlatformError off darwin', function (done) {
        mock.pretendPlatform('linux');
        keychain[method]({ account: 'a', service: 's', password: 'p' }, function (err, result) {
          expect(err).to.be.instanceOf(errors.UnsupportedPlatformError);
          expect(err.message).to.equal('Expected darwin platform, got: linux');
          expect(result).to.equal(null);
          expect(mock.calls).to.have.length(0);
          done();
        });
      });
    });
  });

  describe('.getPassword(opts, fn)', function () {
    it('spawns security find-generic-password with -a/-s/-g', function (done) {
      mock.respond(mock.findOutput('hunter2'));
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('hunter2');
        expect(mock.calls).to.have.length(1);
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.deep.equal(['find-generic-password', '-a', 'me', '-s', 'svc', '-g']);
        done();
      });
    });

    it('uses find-internet-password when type is internet (case-insensitive)', function (done) {
      mock.respond(mock.findOutput('x'));
      keychain.getPassword({ account: 'me', service: 'svc', type: 'INTERNET' }, function (err) {
        expect(err).to.equal(null);
        expect(mock.calls[0].args[0]).to.equal('find-internet-password');
        done();
      });
    });

    it('decodes the hex form when security escapes characters', function (done) {
      mock.respond(mock.findOutput('passWith\\', { hex: true, quoted: 'passWith\\134' }));
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('passWith\\');
        done();
      });
    });

    it('decodes the hex-only form for non-ASCII passwords', function (done) {
      var pw = '∆˚ˆ©ƒ®∂çµ˚¬˙ƒ®†¥';
      mock.respond(mock.findOutput(pw, { hex: true, quoted: false }));
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal(pw);
        done();
      });
    });

    it('returns a quoted password that itself looks like a hex line', function (done) {
      var pw = 'password: 0x4e6573746564';
      mock.respond(mock.findOutput(pw));
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal(pw);
        done();
      });
    });

    it('returns an empty string for an empty quoted password', function (done) {
      mock.respond({ stdout: 'class: "genp"\n', stderr: 'password: ""\n', code: 0 });
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('');
        done();
      });
    });

    it('reassembles a password delivered in several stderr chunks', function (done) {
      mock.respond({ stdout: '', stderr: ['password: "ab', 'cd"\n'], code: 0 });
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('abcd');
        done();
      });
    });

    it('fails with PasswordNotFoundError on a non-zero exit', function (done) {
      mock.respond({ stderr: 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n', code: 44 });
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.be.instanceOf(errors.PasswordNotFoundError);
        expect(err.message).to.equal('Could not find password');
        expect(pass).to.equal(null);
        done();
      });
    });

    it('fails with PasswordNotFoundError when exit is 0 but no password line appears', function (done) {
      mock.respond({ stdout: 'class: "genp"\n', stderr: '', code: 0 });
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.be.instanceOf(errors.PasswordNotFoundError);
        expect(pass).to.equal(null);
        done();
      });
    });

    it('fails with ServiceFailureError when security cannot be spawned', function (done) {
      mock.respond({ error: new Error('spawn /usr/bin/security ENOENT') });
      keychain.getPassword({ account: 'me', service: 'svc' }, function (err, pass) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        expect(err.message).to.equal('Keychain failed to start child process: spawn /usr/bin/security ENOENT');
        expect(pass).to.equal(null);
        done();
      });
    });

    it('fails with NoAccountProvidedError / NoServiceProvidedError before spawning', function () {
      var seen = [];
      keychain.getPassword({ service: 's' }, function (err) { seen.push(err); });
      keychain.getPassword({ account: 'a' }, function (err) { seen.push(err); });
      keychain.getPassword(undefined, function (err) { seen.push(err); });
      expect(seen[0]).to.be.instanceOf(errors.NoAccountProvidedError);
      expect(seen[1]).to.be.instanceOf(errors.NoServiceProvidedError);
      expect(seen[2]).to.be.instanceOf(errors.NoAccountProvidedError);
      expect(mock.calls).to.have.length(0);
    });

    it('honours a custom executablePath', function (done) {
      keychain.executablePath = '/opt/bin/security';
      mock.respond(mock.findOutput('p'));
      keychain.getPassword({ account: 'me', service: 'svc' }, function () {
        expect(mock.calls[0].cmd).to.equal('/opt/bin/security');
        done();
      });
    });
  });

  describe('.setPassword(opts, fn)', function () {
    it('runs add-generic-password -a/-s/-w through `security -i` (password on stdin, not argv) and returns the password', function (done) {
      mock.respond({ code: 0 });
      keychain.setPassword({ account: 'me', service: 'svc', password: 'pw' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('pw');
        expect(mock.calls).to.have.length(1);
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.deep.equal(['-i']);
        expect(mock.calls[0].stdinEnded).to.equal(true);
        expect(mock.commands(mock.calls[0])).to.deep.equal([
          ['add-generic-password', '-a', 'me', '-s', 'svc', '-w', 'pw']
        ]);
        done();
      });
    });

    it('uses add-internet-password when type is internet', function (done) {
      mock.respond({ code: 0 });
      keychain.setPassword({ account: 'me', service: 'svc', password: 'pw', type: 'internet' }, function (err) {
        expect(err).to.equal(null);
        expect(mock.commands(mock.calls[0])[0][0]).to.equal('add-internet-password');
        done();
      });
    });

    it('on exit 45 (already exists) deletes then re-adds the password', function (done) {
      mock.respond({ code: 45 });           // add -> exists
      mock.respond({ code: 0 });            // delete
      mock.respond({ code: 0 });            // add again
      keychain.setPassword({ account: 'me', service: 'svc', password: 'pw' }, function (err, pass) {
        expect(err).to.equal(null);
        expect(pass).to.equal('pw');
        expect(mock.calls.map(function (c) { return mock.commands(c)[0][0]; })).to.deep.equal([
          'add-generic-password', 'delete-generic-password', 'add-generic-password'
        ]);
        done();
      });
    });

    it('on exit 45 surfaces the delete error if the delete fails', function (done) {
      mock.respond({ code: 45 });
      mock.respond({ code: 1 });
      keychain.setPassword({ account: 'me', service: 'svc', password: 'pw' }, function (err) {
        expect(err).to.be.instanceOf(errors.PasswordNotFoundError);
        expect(mock.calls).to.have.length(2);
        done();
      });
    });

    it('fails with ServiceFailureError carrying exitCode on any other non-zero exit', function (done) {
      mock.respond({ code: 36 });
      keychain.setPassword({ account: 'me', service: 'svc', password: 'pw' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        expect(err.message).to.equal('Security returned a non-successful error code: 36');
        expect(err.exitCode).to.equal(36);
        done();
      });
    });

    it('fails with ServiceFailureError when security cannot be spawned', function (done) {
      mock.respond({ error: new Error('spawn EACCES') });
      keychain.setPassword({ account: 'me', service: 'svc', password: 'pw' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        expect(err.message).to.equal('Keychain failed to start child process: spawn EACCES');
        done();
      });
    });

    it('validates account, service and password before spawning', function () {
      var seen = [];
      keychain.setPassword({ service: 's', password: 'p' }, function (err) { seen.push(err); });
      keychain.setPassword({ account: 'a', password: 'p' }, function (err) { seen.push(err); });
      keychain.setPassword({ account: 'a', service: 's' }, function (err) { seen.push(err); });
      expect(seen[0]).to.be.instanceOf(errors.NoAccountProvidedError);
      expect(seen[1]).to.be.instanceOf(errors.NoServiceProvidedError);
      expect(seen[2]).to.be.instanceOf(errors.NoPasswordProvidedError);
      expect(mock.calls).to.have.length(0);
    });
  });

  describe('.deletePassword(opts, fn)', function () {
    it('spawns security delete-generic-password with -a/-s and calls back with no error', function (done) {
      mock.respond({ code: 0 });
      keychain.deletePassword({ account: 'me', service: 'svc' }, function (err) {
        expect(err).to.equal(null);
        expect(mock.calls).to.have.length(1);
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.deep.equal(['delete-generic-password', '-a', 'me', '-s', 'svc']);
        done();
      });
    });

    it('uses delete-internet-password when type is internet', function (done) {
      mock.respond({ code: 0 });
      keychain.deletePassword({ account: 'me', service: 'svc', type: 'Internet' }, function () {
        expect(mock.calls[0].args[0]).to.equal('delete-internet-password');
        done();
      });
    });

    it('fails with PasswordNotFoundError on a non-zero exit', function (done) {
      mock.respond({ code: 44 });
      keychain.deletePassword({ account: 'me', service: 'svc' }, function (err) {
        expect(err).to.be.instanceOf(errors.PasswordNotFoundError);
        done();
      });
    });

    it('fails with ServiceFailureError when security cannot be spawned', function (done) {
      mock.respond({ error: new Error('spawn ENOENT') });
      keychain.deletePassword({ account: 'me', service: 'svc' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        done();
      });
    });

    it('validates account and service before spawning', function () {
      var seen = [];
      keychain.deletePassword({ service: 's' }, function (err) { seen.push(err); });
      keychain.deletePassword({ account: 'a' }, function (err) { seen.push(err); });
      expect(seen[0]).to.be.instanceOf(errors.NoAccountProvidedError);
      expect(seen[1]).to.be.instanceOf(errors.NoServiceProvidedError);
      expect(mock.calls).to.have.length(0);
    });
  });

  describe('.createKeychain(opts, fn)', function () {
    it('runs create-keychain -p <password> -- <name> through `security -i` and returns the name', function (done) {
      mock.respond({ code: 0 });
      keychain.createKeychain({ keychainName: 'test.keychain', password: 'pw' }, function (err, name) {
        expect(err).to.equal(null);
        expect(name).to.equal('test.keychain');
        expect(mock.calls).to.have.length(1);
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.deep.equal(['-i']);
        expect(mock.commands(mock.calls[0])).to.deep.equal([
          ['create-keychain', '-p', 'pw', '--', 'test.keychain']
        ]);
        done();
      });
    });

    it('fails with ServiceFailureError carrying exitCode on non-zero exit', function (done) {
      mock.respond({ code: 48 });
      keychain.createKeychain({ keychainName: 'test.keychain', password: 'pw' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        expect(err.exitCode).to.equal(48);
        done();
      });
    });

    it('fails with ServiceFailureError when security cannot be spawned', function (done) {
      mock.respond({ error: new Error('spawn ENOENT') });
      keychain.createKeychain({ keychainName: 'k', password: 'pw' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        done();
      });
    });

    it('validates keychainName and password before spawning (no platform guard)', function () {
      var seen = [];
      keychain.createKeychain({ password: 'p' }, function (err) { seen.push(err); });
      keychain.createKeychain({ keychainName: 'k' }, function (err) { seen.push(err); });
      keychain.createKeychain(undefined, function (err) { seen.push(err); });
      expect(seen[0]).to.be.instanceOf(errors.NoKeychainNameProvidedError);
      expect(seen[1]).to.be.instanceOf(errors.NoPasswordProvidedError);
      expect(seen[2]).to.be.instanceOf(errors.NoKeychainNameProvidedError);
      expect(mock.calls).to.have.length(0);
    });
  });

  describe('.deleteKeychain(opts, fn)', function () {
    it('spawns security delete-keychain -- <name> and returns the name', function (done) {
      mock.respond({ code: 0 });
      keychain.deleteKeychain({ keychainName: 'test.keychain' }, function (err, name) {
        expect(err).to.equal(null);
        expect(name).to.equal('test.keychain');
        expect(mock.calls).to.have.length(1);
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.deep.equal(['delete-keychain', '--', 'test.keychain']);
        done();
      });
    });

    it('fails with ServiceFailureError carrying exitCode on non-zero exit', function (done) {
      mock.respond({ code: 50 });
      keychain.deleteKeychain({ keychainName: 'test.keychain' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        expect(err.exitCode).to.equal(50);
        done();
      });
    });

    it('fails with ServiceFailureError when security cannot be spawned', function (done) {
      mock.respond({ error: new Error('spawn ENOENT') });
      keychain.deleteKeychain({ keychainName: 'k' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        done();
      });
    });

    it('validates keychainName before spawning', function () {
      var seen = [];
      keychain.deleteKeychain({}, function (err) { seen.push(err); });
      keychain.deleteKeychain(undefined, function (err) { seen.push(err); });
      expect(seen[0]).to.be.instanceOf(errors.NoKeychainNameProvidedError);
      expect(seen[1]).to.be.instanceOf(errors.NoKeychainNameProvidedError);
      expect(mock.calls).to.have.length(0);
    });
  });

  describe('.setDefaultKeychain(opts, fn)', function () {
    it('spawns security default-keychain -s -- <name> and returns the name', function (done) {
      mock.respond({ code: 0 });
      keychain.setDefaultKeychain({ keychainName: 'login.keychain' }, function (err, name) {
        expect(err).to.equal(null);
        expect(name).to.equal('login.keychain');
        expect(mock.calls).to.have.length(1);
        expect(mock.calls[0].cmd).to.equal('/usr/bin/security');
        expect(mock.calls[0].args).to.deep.equal(['default-keychain', '-s', '--', 'login.keychain']);
        done();
      });
    });

    it('fails with ServiceFailureError carrying exitCode on non-zero exit', function (done) {
      mock.respond({ code: 50 });
      keychain.setDefaultKeychain({ keychainName: 'missing' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        expect(err.exitCode).to.equal(50);
        done();
      });
    });

    it('fails with ServiceFailureError when security cannot be spawned', function (done) {
      mock.respond({ error: new Error('spawn ENOENT') });
      keychain.setDefaultKeychain({ keychainName: 'k' }, function (err) {
        expect(err).to.be.instanceOf(errors.ServiceFailureError);
        done();
      });
    });

    it('validates keychainName before spawning', function () {
      var seen = [];
      keychain.setDefaultKeychain({}, function (err) { seen.push(err); });
      keychain.setDefaultKeychain(undefined, function (err) { seen.push(err); });
      expect(seen[0]).to.be.instanceOf(errors.NoKeychainNameProvidedError);
      expect(seen[1]).to.be.instanceOf(errors.NoKeychainNameProvidedError);
      expect(mock.calls).to.have.length(0);
    });
  });

  describe('argument safety', function () {
    it('passes hostile account/service/password values as discrete tokens security parses, never through a shell', function (done) {
      var evil = '$(touch /tmp/pwned); `id`; foo | bar && baz';
      mock.respond({ code: 0 });
      keychain.setPassword({ account: evil, service: evil, password: evil }, function () {
        expect(mock.calls[0].args).to.deep.equal(['-i']);
        expect(mock.commands(mock.calls[0])).to.deep.equal([
          ['add-generic-password', '-a', evil, '-s', evil, '-w', evil]
        ]);
        done();
      });
    });
  });
});
