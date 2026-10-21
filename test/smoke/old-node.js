// Plain-Node smoke test (no mocha) so CI can show the library itself still
// runs on old Node versions the test runner no longer supports. Mocked
// `security`, so it runs on any OS. Exits non-zero on the first failure.
var assert = require('assert');
var fake = require('../helpers/fake-spawn');
fake.install();
var keychain = require('../../');
var errors = keychain.constructor.errors;

var unhandled = [];
process.on('unhandledRejection', function (reason) { unhandled.push(reason); });

var steps = [
  function callbackStillWorks(next) {
    fake.respond({ stderr: 'password: "secret"\n' });
    var ret = keychain.getPassword({ account: 'a', service: 's' }, function (err, pass) {
      assert.strictEqual(err, null);
      assert.strictEqual(pass, 'secret');
      next();
    });
    assert.strictEqual(ret, undefined);
  },
  function promiseResolves(next) {
    fake.respond({ stderr: 'password: 0xE28886656C7461\n' });
    keychain.getPassword({ account: 'a', service: 's' }).then(function (pass) {
      assert.strictEqual(pass, '∆elta');
      next();
    }, next);
  },
  function promiseRejectsWithSameClass(next) {
    fake.respond({ code: 44 });
    keychain.getPassword({ account: 'a', service: 's' }).then(function () {
      next(new Error('expected a rejection'));
    }, function (err) {
      assert.ok(err instanceof errors.PasswordNotFoundError);
      next();
    });
  },
  function passwordGoesOverStdin(next) {
    fake.respond({ code: 0 });
    keychain.setPassword({ account: 'a', service: 's', password: 'p"w' }).then(function (pw) {
      assert.strictEqual(pw, 'p"w');
      var call = fake.calls[fake.calls.length - 1];
      assert.deepStrictEqual(call.args, ['-i']);
      assert.deepStrictEqual(fake.commands(call)[0], ['add-generic-password', '-a', 'a', '-s', 's', '-w', 'p"w']);
      next();
    }, next);
  },
  function callbackRunsOnceOnSpawnFailure(next) {
    fake.respond({ error: 'spawn ENOENT' });
    var count = 0;
    keychain.deletePassword({ account: 'a', service: 's' }, function () { count++; });
    setTimeout(function () {
      assert.strictEqual(count, 1);
      next();
    }, 50);
  },
  function fireAndForgetDoesNotCrash(next) {
    fake.respond({ code: 1 });
    keychain.deletePassword({ account: 'a', service: 's' });
    setTimeout(function () {
      assert.strictEqual(unhandled.length, 0);
      next();
    }, 50);
  }
];

(function run(i) {
  if (i === steps.length) {
    fake.restore();
    console.log('ok ' + steps.length + ' smoke checks on node ' + process.version);
    return;
  }
  steps[i](function (err) {
    if (err) {
      console.error('not ok ' + steps[i].name + ': ' + (err.stack || err));
      process.exit(1);
    }
    run(i + 1);
  });
})(0);
