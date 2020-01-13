# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project should eventually adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
however it has not stabilized, yet.

## [Unreleased]

## [0.2.2] - 2020-01-13
### Fixed
- Fix library export for TypeScript (#125)

### Changed
- Update of many dev dependencies (#120, #123, #134, #137, #139, #140)

## [0.2.1] - 2019-08-08
### Fixed
- Fix WebCryptographer export (#116).

### Changed
- Update of many dev dependencies (#103, #104, #105, #107, #108, #111, #112)

### Deprecated
- Node.js 9 is unsupported. CI is configured to run latest Node.js version and latest
  LTS release (#113).

## [0.2.0] - 2019-07-23
### Added
- Support for signing and verifying using EC keys (#95).

### Fixed
- Fix babel-loader config (#91).
- `window.crypto` check now works for Service Workers (#92).
- Add missing method signature to type definitions (#98).
- Fix default ES6-style export (#97).

### Changed
- Use ESLint instead of JSHint and adopt [JavaScript Standard Style](https://standardjs.com/)
  for the project -- with the exception of [semi rule](https://eslint.org/docs/rules/semi)
  (we still require semicolons everywhere) (#99).

## [0.1.7] - 2019-02-21
### Changed
- Library is now written in ES6 and Babel is used for backwards compatibility (in browsers
  and Node.js environments) and it works with Webpack (#82).

### Fixed
- Use passed algorithm when importing private RSA key (#67).

## [0.1.6] - 2017-10-16
### Added
- Better type definitions that now also include allowed algorithm types (#61).

## [0.1.5] - 2017-05-20
### Fixed
- Perform UTF-8 conversion on JSON stringified objects, not just strings (#55).


## [0.1.4] - 2016-10-25
### Added
- Add payload to successful verification results (#48).

### Fixed
- Ability to use `setCrypto` API in browsers (#49).
- Allow CryptoKey to be recognized even when provided by minified applications (#50).

## [0.1.2] - 2016-09-16
### Added
- Handle UTF-8 plaintexts (as allowed by the JOSE spec) (#42 & #46).


## [0.1.1] - 2016-09-06
### Fixed
- Restore serialization methods for `SignedJws` interface (#39).
- Replace Promise.accept() with Promise.resolve() as Promise API changed (#45).

## [0.1.0] - 2016-04-11
### Added
- JWS support (#15).
- Direct encryption using pre-shared symmetric keys (#22).
- Add optional argument in Verifier that returns `Promise<CryptoKey>` given
  a key id (#24).
- CommonJS packaging that allows for importing js-jose via Webpack (#27).
- Support for Node.js, however it still requires a use of [polyfill](https://github.com/PeculiarVentures/node-webcrypto-ossl) (#30).
- The API is enriched with TypeScript type definitions (#28 & #35).

### Changed
- NPM package renamed to `jose-jwe-jws`

## [0.0.3] - 2015-03-03
### Added
- Travis CI integration (#8).
- Browser support check that ensures necessary APIs are available before
  JOSE operations (#11).

## [0.0.2] - 2015-02-11
### Added
- Partial support for user defined headers (#2).
- First NPM release.

### Fixed
- Bug in public key import (#1).

## [0.0.1] - 2014-11-25
### Added
- Initial release with support for JWE encryption.
- Support for key encryption algorithms: RSA-OAEP (default), RSA-OAEP-256,
  A128KW (not recommended for use) and A256KW (not recommended for use).
- Support for content encryption: A128CBC-HS256, A256CBC-HS512, A128GCM,
  A256GCM (default).

[Unreleased]: https://github.com/square/js-jose/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/square/js-jose/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/square/js-jose/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/square/js-jose/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/square/js-jose/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/square/js-jose/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/square/js-jose/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/square/js-jose/compare/v0.1.2...v0.1.4
[0.1.2]: https://github.com/square/js-jose/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/square/js-jose/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/square/js-jose/compare/v0.0.3...v0.1.0
[0.0.3]: https://github.com/square/js-jose/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/square/js-jose/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/square/js-jose/releases/tag/v0.0.1
