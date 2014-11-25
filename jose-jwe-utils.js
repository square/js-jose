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

JoseJWE.Utils = {};

JoseJWE.Utils.isString = function(str) {
  return ((typeof(str) == "string") || (str instanceof String));
};

/**
 * Converts the modulus/exponent from `openssl x509 -text` or
 * `openssl rsa -text` into a CryptoKey which can then be used with RSA-OAEP.
 *
 * The key is either a public key or a public/private pair.
 *
 * @param rsa_key  json, e.g. {"n": "00:c2:4b:af:0f:2d....", "e": 65537}
 * @param purpose  array<string>, e.g. ["encrypt", "decrypt"]
 * @return Promise<CryptoKey>
 *
 * TODO: handle private pair version...
 */
JoseJWE.Utils.importRsaKeyFromHex = function(rsa_key, purpose) {
  if (!JoseJWE.Utils.isString(rsa_key.n)) {
    return Promise.reject("importRsaKeyFromHex: expecting rsa_key['n'] to be a string");
  }
  if (typeof(rsa_key.e) != "number") {
    return Promise.reject("importRsaKeyFromHex: expecting rsa_key['e'] to be a number");
  }
  if (!(purpose instanceof Array)) {
    return Promise.reject("importRsaKeyFromHex: expecting purpose to be an array");
  }
  purpose.push("wrapKey");
  var n = rsa_key.n
    .split(':')
    .map(function(e){return String.fromCharCode(parseInt(e, 16))})
    .join('');
  var jwk = {
    "kty": "RSA",
    "n": JoseJWE.Utils.Base64Url.encode(n),
    "e": JoseJWE.Utils.Base64Url.encodeArrayBuffer(JoseJWE.Utils.arrayFromInt32(rsa_key.e))
  }
  var config = JoseJWE.getCryptoConfig("RSA-OAEP");
  return crypto.subtle.importKey("jwk", jwk, config.id, false, purpose);
};

/**
 * Very simple wrapper to import a JWK into the Web Crypto API.
 *
 * @param jwk      json
 * @param purpose  array<string>
 * @return Promise<CryptoKey>
 */
JoseJWE.Utils.importRSAfromJWK = function(jwk, purpose) {
  if (!JoseJWE.Utils.isString(jwk.kty)) {
    return Promise.reject("importRSAfromJWK: expecting jwk['kty'] to be a string");
  }
  if (jwk.kty != "RSA") {
    return Promise.reject("importRSAfromJWK: expecting jwk['kty'] to be RSA");
  }
  if (!JoseJWE.Utils.isString(jwk.n)) {
    return Promise.reject("importRSAfromJWK: expecting jwk['n'] to be a string");
  }
  if (!JoseJWE.Utils.isString(jwk.e)) {
    return Promise.reject("importRSAfromJWK: expecting jwk['e'] to be a string");
  }
  if (!(purpose instanceof Array)) {
    return Promise.reject("importRSAfromJWK: expecting purpose to be an array");
  }
  purpose.push("wrapKey");
  var config = JoseJWE.getCryptoConfig("RSA-OAEP");

    return crypto.subtle.importKey(
      "jwk",
      jwk,
      config.id,
      false,
      purpose
    );
};

/**
 * Converts a string into an array of ascii codes.
 *
 * @param str  string
 * @return Uint8Array
 */
JoseJWE.Utils.arrayFromString = function(str) {
  var arr = str.split('').map(function(c){return c.charCodeAt(0)});
  return new Uint8Array(arr);
};

/**
 * Converts a number into an array of 4 bytes.
 * @param i  number
 * @return ArrayBuffer
 */
JoseJWE.Utils.arrayFromInt32 = function(i) {
  JoseJWE.assert(typeof(i) == "number");
  JoseJWE.assert(i == i|0, "arrayFromInt32: out of range");

  return new Uint32Array([i]).buffer;
};

/**
 * Concatenates ArrayBuffers.
 *
 * @param two or more ArrayBuffer
 * @return Uint8Array
 */
JoseJWE.Utils.arrayBufferConcat = function(/* ... */) {
  // Compute total size
  var total = 0;
  for (var i=0; i<arguments.length; i++) {
    JoseJWE.assert(arguments[i] instanceof ArrayBuffer, "arrayBufferConcat: unexpecting input");
    total += arguments[i].byteLength;
  }
  var r = new Uint8Array(total);
  var offset = 0;
  for (i=0; i<arguments.length; i++) {
    r.set(new Uint8Array(arguments[i]), offset);
    offset += arguments[i].byteLength;
  }
  JoseJWE.assert(offset == total, "arrayBufferConcat: unexpected offset");
  return r;
};

JoseJWE.Utils.Base64Url = {};

/**
 * Base64Url encodes a string
 *
 * @param str  string
 * @return string
 */
JoseJWE.Utils.Base64Url.encode = function(str) {
  JoseJWE.assert(JoseJWE.Utils.isString(str));
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

/**
 * Base64Url encodes an ArrayBuffer
 *
 * @param buf  ArrayBuffer
 * @return string
 */
JoseJWE.Utils.Base64Url.encodeArrayBuffer = function(buf) {
  JoseJWE.assert(buf instanceof ArrayBuffer, "encodeArrayBuffer: invalid input");
  arr = new Uint8Array(buf);
  var r = "";
  for (i=0; i<arr.length; i++) {
    r+=String.fromCharCode(arr[i]);
  }
  return JoseJWE.Utils.Base64Url.encode(r);
};
