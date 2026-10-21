#  Basic Keychain Access on Mac computers running Node.js
[![Build Status](https://img.shields.io/github/actions/workflow/status/drudge/node-keychain/test.yaml?branch=master)](https://github.com/drudge/node-keychain/actions/workflows/test.yaml)

  This module adds methods for basic Keychain access in Node.js by way of the `security` command-line tool.

## Requirements

 * Mac OS X 10.6+

## Installation

    npm install keychain

## Examples

### Generic Password Example

```javascript
var keychain = require('keychain');

keychain.setPassword({ account: 'foo', service: 'FooBar', password: 'baz' }, function(err) {
  keychain.getPassword({ account: 'foo', service: 'FooBar' }, function(err, pass) {
    console.log('Password is', pass);
    // Prints: Password is baz
  });
});
```

### Internet Password Example
```javascript
var keychain = require('keychain');

keychain.setPassword({ account: 'foo', service: 'FooBar.com', type: 'internet', password: 'baz' }, function(err) {
  keychain.getPassword({ account: 'foo', service: 'FooBar.com', type: 'internet' }, function(err, pass) {
    console.log('Password is', pass);
    // Prints: Password is baz
  });
});
```

### Promises

Every method returns a Promise when you leave out the callback:

```javascript
const keychain = require('keychain');

await keychain.setPassword({ account: 'foo', service: 'FooBar', password: 'baz' });
const pass = await keychain.getPassword({ account: 'foo', service: 'FooBar' });
console.log('Password is', pass);
// Prints: Password is baz
```

The Promise resolves with the value the callback would get and rejects with the same error objects (see [Errors](#errors)). Pass a callback and nothing changes from earlier versions: the method calls it and returns `undefined`.

## Usage

The available methods:

```js
keychain.setPassword(options[, callback]);    // resolves with the password
keychain.getPassword(options[, callback]);    // resolves with the password
keychain.deletePassword(options[, callback]); // resolves with undefined
keychain.createKeychain(options[, callback]); // resolves with the keychain name
keychain.deleteKeychain(options[, callback]); // resolves with the keychain name
keychain.setDefaultKeychain(options[, callback]); // resolves with the keychain name
```

Without a callback, each returns a Promise. Earlier versions ignored errors when no callback was passed, so these Promises are marked handled: code that never awaits them won't start crashing on unhandled rejections, and code that does `await` or `.catch()` still gets the error.

### Options

Available params you can pass to the options object:

| Param | Description |
| ----- | ----------- |
| `account` | Specify account name (required) |
| `service` | Specify service name (required) |
| `password` | Specify password to be added (required for `setPassword`) |
| `type` | The type of password to get or save. Supported values are `generic` and `internet`. See [docs](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html). Default: `generic` |
| `keychainName` | Specify the name of the keychain (required for `createKeychain`, `deleteKeychain` and `setDefaultKeychain`) |

### Errors

Errors are instances of the classes on `keychain.constructor.errors`, each with a `code`:

| Class | `code` | When |
| ----- | ------ | ---- |
| `UnsupportedPlatformError` | `UnsupportedPlatform` | Not running on macOS (password methods) |
| `NoAccountProvidedError` | `NoAccountProvided` | `account` missing |
| `NoServiceProvidedError` | `NoServiceProvided` | `service` missing |
| `NoPasswordProvidedError` | `NoPasswordProvided` | `password` missing |
| `NoKeychainNameProvidedError` | `NoKeychainNameProvided` | `keychainName` missing |
| `PasswordNotFoundError` | `PasswordNotFound` | No matching item, or `security` output that couldn't be read |
| `ServiceFailureError` | `ServiceFailure` | `security` couldn't start or exited with an error (`exitCode` is set for the latter) |

```javascript
try {
  await keychain.getPassword({ account: 'foo', service: 'Missing' });
} catch (err) {
  if (err instanceof keychain.constructor.errors.PasswordNotFoundError) {
    // not stored yet
  }
}
```

## Security

`keychain` runs `/usr/bin/security` with an argument list, never through a shell. `setPassword` and `createKeychain` send their command to `security -i` on standard input, so the password doesn't show up in the process list (`ps`). The exception is a command `security -i` can't read back intact (a value containing a newline or NUL byte, or a command over about 4 KB): it goes on the command line as in earlier versions. Keychain names are passed after `--`, so a name that starts with `-` isn't read as an option.

## Contributors

The following are the major contributors of `node-keychain` (in no specific order).

  * Nicholas Penree ([drudge](https://github.com/drudge))
  * Tejesh Mehta ([tjmehta](https://github.com/tjmehta))
  * Benjamin Hutchins ([benhutchins](https://github.com/benhutchins))
  * Manuel de la Pena ([mandel-macaque](https://github.com/mandel-macaque))

## License

(The MIT License)

Copyright (c) 2013-2023 Nicholas Penree &lt;nick@penree.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
