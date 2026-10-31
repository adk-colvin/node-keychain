// Security properties of how keychain.js drives `security`. Mocked, so it runs
// on any OS; fake.commands() shows what `security` would actually execute.
var fake = require('../helpers/fake-spawn');
fake.install();
var keychain = require('../../');
fake.restore();
var chai = require('chai');
chai.should();

describe('security (mocked security)', function () {
  beforeEach(function () { fake.install(); fake.respond({ code: 0 }); });
  afterEach(function () { fake.restore(); });

  var secret = 'hunter2-S3cret!';

  function lastCall() { return fake.calls[fake.calls.length - 1]; }

  describe('passwords stay out of the process argument list (visible in ps)', function () {
    it('setPassword', function () {
      return keychain.setPassword({ account: 'a', service: 's', password: secret }).then(function () {
        lastCall().args.join(' ').should.not.contain(secret);
      });
    });

    it('createKeychain', function () {
      return keychain.createKeychain({ keychainName: 'k.keychain', password: secret }).then(function () {
        lastCall().args.join(' ').should.not.contain(secret);
      });
    });
  });

  describe('keychain names that start with "-" are not parsed as options', function () {
    [
      ['createKeychain', { keychainName: '-P', password: 'pw' }],
      ['deleteKeychain', { keychainName: '-P' }],
      ['setDefaultKeychain', { keychainName: '-P' }]
    ].forEach(function (c) {
      it(c[0], function () {
        return keychain[c[0]](c[1]).then(function () {
          var argv = fake.commands(lastCall())[0];
          var end = argv.indexOf('--');
          end.should.be.above(0, 'expected "--" before the keychain name');
          argv.indexOf('-P').should.be.above(end);
        });
      });
    });
  });

  describe('values cannot inject extra security commands', function () {
    var nasty = [
      'plain',
      'with space',
      'quote"inside',
      "single'quote",
      'back\\slash\\',
      '\\"; delete-keychain login.keychain; "',
      '-w',
      'tab\there',
      'cr\rhere',
      'line\nbreak delete-keychain login.keychain',
      '∆˚ˆ©ƒ®∂çµ˚¬˙ƒ®†¥',
      'x'.repeat(5000) + ' delete-keychain login.keychain'
    ];

    nasty.forEach(function (value) {
      var label = JSON.stringify(value.length > 40 ? value.slice(0, 20) + '…(' + value.length + ')' : value);

      it('setPassword runs exactly one add command with ' + label + ' intact', function () {
        return keychain.setPassword({ account: value, service: value, password: value }).then(function () {
          var cmds = fake.commands(lastCall());
          cmds.length.should.equal(1);
          cmds[0].should.deep.equal(['add-generic-password', '-a', value, '-s', value, '-w', value]);
        });
      });

      it('createKeychain runs exactly one create command with ' + label + ' intact', function () {
        return keychain.createKeychain({ keychainName: value, password: value }).then(function () {
          var cmds = fake.commands(lastCall());
          cmds.length.should.equal(1);
          cmds[0].should.deep.equal(['create-keychain', '-p', value, '--', value]);
        });
      });
    });
  });
});
