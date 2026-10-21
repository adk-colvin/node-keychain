// Regression tests for bugs in 1.5.0. Mocked, so they run on any OS.
var fake = require('./helpers/fake-spawn');
fake.install();
var keychain = require('../');
fake.restore();
var chai = require('chai');
chai.should();

var errors = keychain.constructor.errors;

describe('robustness (mocked security)', function () {
  beforeEach(function () { fake.install(); });
  afterEach(function () { fake.restore(); });

  describe('when security cannot be started', function () {
    ['getPassword', 'setPassword', 'deletePassword'].forEach(function (method) {
      it(method + ' calls back exactly once with ServiceFailureError', function (done) {
        fake.respond({ error: 'spawn /usr/bin/security ENOENT' });
        var calls = [];
        keychain[method]({ account: 'a', service: 's', password: 'p' }, function (err) {
          calls.push(err);
        });
        setTimeout(function () {
          calls.length.should.equal(1);
          calls[0].should.be.instanceOf(errors.ServiceFailureError);
          done();
        }, 50);
      });
    });
  });

  describe('getPassword with output it cannot parse', function () {
    it('calls back with PasswordNotFoundError instead of throwing', function (done) {
      fake.respond({ stderr: 'password: \n', code: 0 });
      keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
        err.should.be.instanceOf(errors.PasswordNotFoundError);
        (pass === null).should.equal(true);
        done();
      });
    });
  });

  describe('getPassword hex parsing', function () {
    it('reads the hex form even when another line comes first', function (done) {
      fake.respond({ stderr: 'warning: 0xDEAD something\npassword: 0x70617373576974685C  "passWith\\134"\n', code: 0 });
      keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
        (err === null).should.equal(true);
        pass.should.equal('passWith\\');
        done();
      });
    });
  });
});
