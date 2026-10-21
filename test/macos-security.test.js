// Real-keychain checks for the security hardening (macOS only): passwords sent
// through `security -i` must round-trip exactly, and nothing in them may run
// as a second command. Skipped on other platforms.
var keychain = require('../');
var chai = require('chai');
chai.should();

var onMac = process.platform === 'darwin';

(onMac ? describe : describe.skip)('security hardening on a real keychain', function () {
  this.timeout(20000);

  var service = 'KeychainAccess#hardening#' + Date.now();
  var values = [
    'with space',
    'quote"inside',
    "single'quote",
    'back\\slash\\',
    '\\"; delete-generic-password -s ' + service + ' -a "plain',
    '-w',
    'tab\there',
    '∆˚ˆ©ƒ®∂çµ˚¬˙ƒ®†¥'
  ];

  values.forEach(function (value, i) {
    it('round-trips password ' + JSON.stringify(value), async function () {
      var account = 'acct' + i;
      (await keychain.setPassword({ account: account, service: service, password: value })).should.equal(value);
      (await keychain.getPassword({ account: account, service: service })).should.equal(value);
      // Setting it again goes through the exit-45 replace path.
      (await keychain.setPassword({ account: account, service: service, password: value + '2' })).should.equal(value + '2');
      (await keychain.getPassword({ account: account, service: service })).should.equal(value + '2');
      await keychain.deletePassword({ account: account, service: service });
    });
  });

  it('round-trips an account and service that need quoting', async function () {
    var account = 'a "quoted" \\ account';
    var svc = service + ' "svc" \\';
    await keychain.setPassword({ account: account, service: svc, password: 'pw' });
    (await keychain.getPassword({ account: account, service: svc })).should.equal('pw');
    await keychain.deletePassword({ account: account, service: svc });
  });

  it('creates and deletes a keychain whose name starts with "-"', async function () {
    var name = '-nk-test-' + Date.now() + '.keychain';
    (await keychain.createKeychain({ keychainName: name, password: 'p "w\\' })).should.equal(name);
    (await keychain.deleteKeychain({ keychainName: name })).should.equal(name);
  });
});
