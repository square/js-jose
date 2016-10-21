/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var Jose = {};

/**
 * Javascript Object Signing and Encryption library.
 *
 * @author Alok Menghrajani <alok@squareup.com>
 */

/**
 * Initializes a JoseJWE object.
 */
var JoseJWE = {};

/**
 * Initializes a JoseJWS object.
 */
var JoseJWS = {};

/**
 * Set crypto provider to use (window.crypto, node-webcrypto-ossl, node-webcrypto-pkcs11 etc.).
 */
exports.setCrypto = function (cp) {
  Jose.crypto = cp;
};

/**
 * Default to the global "crypto" variable
 */
exports.setCrypto(crypto);

/**
 * Use Node versions of atob, btoa functions outside the browser
 */
if (typeof atob !== "function") {
  atob = function (str) {
    return new Buffer(str, 'base64').toString('binary');
  };
}

if (typeof btoa !== "function") {
  btoa = function (str) {
    var buffer;
    if (str instanceof Buffer) {
      buffer = str;
    } else {
      buffer = new Buffer(str.toString(), 'binary');
    }
    return buffer.toString('base64');
  };
}

/**
 * Checks if we have all the required APIs.
 *
 * It might make sense to take a Cryptographer and delegate some of the checks
 * to the cryptographer. I however wanted to keep things simple, so I put all
 * the checks here for now.
 *
 * This list is generated manually and needs to be kept up-to-date.
 *
 * Casual testing shows that:
 * - things work in Chrome 40.0.2214.115
 * - things work in Firefox 35.0.1
 * - Safari 7.1.3 doesn't support JWK keys.
 * - Internet Explorer doesn't support Promises.
 *
 * Note: We don't check if the browser supports specific crypto operations.
 *       I.e. it's possible for this function to return true, but encryption or
 *       decryption to subsequently fail because the browser does not support a
 *       given encryption, decryption, key wrapping, key unwrapping or hmac
 *       operation.
 *
 * @return bool
 */
Jose.caniuse = function() {
  var r = true;

  // Promises/A+ (https://promisesaplus.com/)
  r = r && (typeof Promise == "function");
  r = r && (typeof Promise.reject == "function");
  r = r && (typeof Promise.prototype.then == "function");
  r = r && (typeof Promise.all == "function");

  // Crypto (http://www.w3.org/TR/WebCryptoAPI/)
  r = r && (typeof Jose.crypto == "object");
  r = r && (typeof Jose.crypto.subtle == "object");
  r = r && (typeof Jose.crypto.getRandomValues == "function");
  r = r && (typeof Jose.crypto.subtle.importKey == "function");
  r = r && (typeof Jose.crypto.subtle.generateKey == "function");
  r = r && (typeof Jose.crypto.subtle.exportKey == "function");
  r = r && (typeof Jose.crypto.subtle.wrapKey == "function");
  r = r && (typeof Jose.crypto.subtle.unwrapKey == "function");
  r = r && (typeof Jose.crypto.subtle.encrypt == "function");
  r = r && (typeof Jose.crypto.subtle.decrypt == "function");
  r = r && (typeof Jose.crypto.subtle.sign == "function");

  // ArrayBuffer (http://people.mozilla.org/~jorendorff/es6-draft.html#sec-arraybuffer-constructor)
  r = r && (typeof ArrayBuffer == "function");
  r = r && (typeof Uint8Array == "function" || typeof Uint8Array == "object"); // Safari uses "object"
  r = r && (typeof Uint32Array == "function" || typeof Uint32Array == "object"); // Safari uses "object"
  // skipping Uint32Array.prototype.buffer because https://people.mozilla.org/~jorendorff/es6-draft.html#sec-properties-of-the-%typedarrayprototype%-object

  // JSON (http://www.ecma-international.org/ecma-262/5.1/#sec-15.12.3)
  r = r && (typeof JSON == "object");
  r = r && (typeof JSON.parse == "function");
  r = r && (typeof JSON.stringify == "function");

  // Base64 (http://www.w3.org/TR/html5/webappapis.html#dom-windowbase64-atob)
  r = r && (typeof atob == "function");
  r = r && (typeof btoa == "function");

  // skipping Array functions (map, join, push, length, etc.)
  // skipping String functions (split, charCodeAt, fromCharCode, replace, etc.)
  // skipping regexp.test and parseInt

  return r;
};

/**
 * Feel free to override this function.
 */
Jose.assert = function(expr, msg) {
  if (!expr) {
    throw new Error(msg);
  }
};

exports.Jose = Jose;
exports.JoseJWE = JoseJWE;
exports.JoseJWS = JoseJWS;