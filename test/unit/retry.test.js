// setPassword retries once (delete, then add again) when the item already
// exists (exit 45). Mocked, so it runs on any OS.
var fake = require('../helpers/fake-spawn');
fake.install();
var keychain = require('../../');
fake.restore();
var chai = require('chai');
chai.should();

var errors = keychain.constructor.errors;

function isAdd(call) {
  return fake.commands(call).some(function (argv) { return /^add-/.test(argv[0]); });
}

describe('setPassword exit-45 retry (mocked security)', function () {
  beforeEach(function () { fake.install(); });
  afterEach(function () { fake.restore(); });

  it('deletes and adds again once when the item already exists', function (done) {
    var adds = 0;
    fake.respond(function (call) {
      if (!isAdd(call)) return { code: 0 };
      adds++;
      return { code: adds === 1 ? 45 : 0 };
    });
    keychain.setPassword({ account: 'a', service: 's', password: 'p' }, function (err, pass) {
      (err === null).should.equal(true);
      pass.should.equal('p');
      fake.calls.map(function (c) { return fake.commands(c)[0][0]; })
        .should.deep.equal(['add-generic-password', 'delete-generic-password', 'add-generic-password']);
      done();
    });
  });

  it('gives up with exit code 45 instead of looping when the add keeps failing', function (done) {
    var adds = 0;
    // Stop answering 45 after 10 adds so a looping implementation ends and
    // fails this test instead of hanging it.
    fake.respond(function (call) {
      if (!isAdd(call)) return { code: 0 };
      adds++;
      return { code: adds <= 10 ? 45 : 0 };
    });
    keychain.setPassword({ account: 'a', service: 's', password: 'p' }, function (err) {
      adds.should.be.at.most(2, 'add attempts');
      err.should.be.instanceOf(errors.ServiceFailureError);
      err.exitCode.should.equal(45);
      done();
    });
  });
});
