# go-apple-security

Go bindings for the Apple [Security framework](https://developer.apple.com/documentation/security).

This library covers a subset of the Security framework as required by [Granted](https://granted.dev). This library is not yet used in Granted.

## Usage

To use this library you must codesign your binary and include entitlements allowing it to access the keychain.

## Testing

To run tests you'll need an Apple Developer account, along with a provisioning profile set up locally. A [script](./cmd/test/main.go) is included in this repo which builds the Go unit tests as binaries, codesigns them, and then runs them.

To run the test process, run

```bash
make test
```

The first time you run it, you'll be prompted to add details about the code signing identity and Apple developer team to use.

## Acknowledgements

A thankyou to the maintainers of the following repositories for providing a reference implementation on interfacing with the Security framework -- if you're looking to use the MacOS keychain these libraries are worth a look:

- https://github.com/keybase/go-keychain
- https://github.com/99designs/keyring
- https://github.com/facebookincubator/sks
