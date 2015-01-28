TODO List
=========

* Improve README. There is some stigma attached to doing crypto in the browser.
  This library uses the browser's Crypto API, so it's not as bad as it sounds :)
* The code currently only works on browsers which implement the Web Crypto API.
  We should expose a way to check if the current browser is supported or not.
* Think about pros vs cons of implementing polyfills for older browsers. We will
  need to think about entropy, timing leaks, etc.
* Build a unittest coverage map
* Make it easier to build a subset of the library. Some people might only want
  to do encryption or encryption with a specific algorithm.
* Rethink error handling. Do we really need JoseJWE.assert?
* Add support for importing public keys as PEM files and validating signatures.
* Improve handling of malformed JSON input (see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-10.12)
