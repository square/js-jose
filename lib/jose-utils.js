/* -
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

// TODO(eslint): figure out how to properly include Jose or expose crypto object

import { WebCryptographer } from './jose-jwe-webcryptographer';
import { Jose } from './jose-core';
const webCryptographer = new WebCryptographer();

/**
 * Import a public key in JWK format, either RSA or ECDSA.
 *
 * @param key   JWK public key
 * @param alg   Name of the JWA signing algorithm (e.g. RS256)
 * @return Promise<CryptoKey>
 */
export const importPublicKey = (key, alg) => {
  switch (alg) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return importRsaPublicKey(key, alg);
    case 'ES256':
    case 'ES384':
    case 'ES512':
      return importEcPublicKey(key, alg);
    default:
      throw Error('unsupported algorithm: ' + alg);
  }
};

/**
 * Import a private key in JWK format, either RSA or EC.
 *
 * @param key   JWK private key
 * @param alg   Name of the JWA signing algorithm (e.g. RS256)
 * @return Promise<CryptoKey>
 */
export const importPrivateKey = (key, alg) => {
  switch (alg) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return importRsaPrivateKey(key, alg);
    case 'ES256':
    case 'ES384':
    case 'ES512':
      return importEcPrivateKey(key, alg);
    default:
      throw Error('unsupported algorithm: ' + alg);
  }
};

/**
 * Import a public EC key in JWK format.
 *
 * @param ecKey   JWK public key
 * @param alg   Name of the JWA signing algorithm (e.g. ES256)
 * @return Promise<CryptoKey>
 */
export const importEcPublicKey = (ecKey, alg) => {
  var config = webCryptographer.getSignConfig(alg);
  var usage = webCryptographer.getKeyUsageByAlg(alg);

  return Jose.crypto.subtle.importKey('jwk', ecKey, config.id, false, [usage.publicKey]);
};

/**
 * Import a private EC key in JWK format.
 *
 * @param ecKey   JWK private key
 * @param alg   Name of the JWA signing algorithm (e.g. ES256)
 * @return Promise<CryptoKey>
 */
export const importEcPrivateKey = (ecKey, alg) => {
  var config = webCryptographer.getSignConfig(alg);
  var usage = webCryptographer.getKeyUsageByAlg(alg);

  return Jose.crypto.subtle.importKey('jwk', ecKey, config.id, false, [usage.privateKey]);
};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsaKey  public RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @return Promise<CryptoKey>
 */
export const importRsaPublicKey = (rsaKey, alg) => {
  var jwk;
  var config;
  var usage = webCryptographer.getKeyUsageByAlg(alg);

  if (usage.publicKey === 'wrapKey') {
    if (!rsaKey.alg) {
      rsaKey.alg = alg;
    }
    jwk = convertRsaKey(rsaKey, ['n', 'e']);
    config = webCryptographer.getCryptoConfig(alg);
  } else {
    var rk = {};
    for (var name in rsaKey) {
      if (Object.prototype.hasOwnProperty.call(rsaKey, name)) {
        rk[name] = rsaKey[name];
      }
    }

    if (!rk.alg && alg) {
      rk.alg = alg;
    }
    config = webCryptographer.getSignConfig(rk.alg);
    jwk = convertRsaKey(rk, ['n', 'e']);
    jwk.ext = true;
  }
  return Jose.crypto.subtle.importKey('jwk', jwk, config.id, false, [usage.publicKey]);
};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP and RSA. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsaKey  private RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @return Promise<CryptoKey>
 */
export const importRsaPrivateKey = (rsaKey, alg) => {
  var jwk;
  var config;
  var usage = webCryptographer.getKeyUsageByAlg(alg);

  if (usage.privateKey === 'unwrapKey') {
    if (!rsaKey.alg) {
      rsaKey.alg = alg;
    }
    jwk = convertRsaKey(rsaKey, ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']);
    config = webCryptographer.getCryptoConfig(alg);
  } else {
    var rk = {};
    for (var name in rsaKey) {
      if (Object.prototype.hasOwnProperty.call(rsaKey, name)) {
        rk[name] = rsaKey[name];
      }
    }
    config = webCryptographer.getSignConfig(alg);
    if (!rk.alg && alg) {
      rk.alg = alg;
    }
    jwk = convertRsaKey(rk, ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']);
    jwk.ext = true;
  }
  return Jose.crypto.subtle.importKey('jwk', jwk, config.id, false, [usage.privateKey]);
};

// Private functions

export const isString = (str) => {
  return ((typeof (str) === 'string') || (str instanceof String));
};

/**
 * Takes an arrayish (an array, ArrayBuffer or Uint8Array)
 * and returns an array or a Uint8Array.
 *
 * @param arr  arrayish
 * @return array or Uint8Array
 */
export const arrayish = (arr) => {
  if (arr instanceof Array) {
    return arr;
  }
  if (arr instanceof Uint8Array) {
    return arr;
  }
  if (arr instanceof ArrayBuffer) {
    return new Uint8Array(arr);
  }
  webCryptographer.assert(false, 'arrayish: invalid input');
};

/**
 * Checks if an RSA key contains all the expected parameters. Also checks their
 * types. Converts hex encoded strings (or numbers) to base64.
 *
 * @param rsaKey     RSA key in json format. Parameters can be base64 encoded,
 *                    strings or number (for 'e').
 * @param parameters  array<string>
 * @return json
 */
export const convertRsaKey = (rsaKey, parameters) => {
  var r = {};
  var alg;

  // Check that we have all the parameters
  var missing = [];
  parameters.map(function (p) { if (typeof (rsaKey[p]) === 'undefined') { missing.push(p); } });

  if (missing.length > 0) {
    webCryptographer.assert(false, 'convertRsaKey: Was expecting ' + missing.join());
  }

  // kty is either missing or is set to "RSA"
  if (typeof (rsaKey.kty) !== 'undefined') {
    webCryptographer.assert(rsaKey.kty === 'RSA', "convertRsaKey: expecting rsaKey['kty'] to be 'RSA'");
  }
  r.kty = 'RSA';

  try {
    webCryptographer.getSignConfig(rsaKey.alg);
    alg = rsaKey.alg;
  } catch (err) {
    try {
      webCryptographer.getCryptoConfig(rsaKey.alg);
      alg = rsaKey.alg;
    } catch (er) {
      webCryptographer.assert(alg, "convertRsaKey: expecting rsaKey['alg'] to have a valid value");
    }
  }
  r.alg = alg;

  // note: we punt on checking key_ops

  var intFromHex = (e) => {
    return parseInt(e, 16);
  };
  for (var i = 0; i < parameters.length; i++) {
    var p = parameters[i];
    var v = rsaKey[p];
    var base64UrlEncoder = new Base64Url();
    if (p === 'e') {
      if (typeof (v) === 'number') {
        v = base64UrlEncoder.encodeArray(stripLeadingZeros(arrayFromInt32(v)));
      }
    } else if (/^([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$/.test(v)) {
      var arr = v.split(':').map(intFromHex);
      v = base64UrlEncoder.encodeArray(stripLeadingZeros(arr));
    } else if (typeof (v) !== 'string') {
      webCryptographer.assert(false, "convertRsaKey: expecting rsaKey['" + p + "'] to be a string");
    }
    r[p] = v;
  }

  return r;
};

/**
 * Converts a string into an array of ascii codes.
 *
 * @param str  ascii string
 * @return Uint8Array
 */
export const arrayFromString = (str) => {
  webCryptographer.assert(isString(str), 'arrayFromString: invalid input');
  var arr = str.split('').map(function (c) {
    return c.charCodeAt(0);
  });
  return new Uint8Array(arr);
};

/**
 * Converts a string into an array of utf-8 codes.
 *
* @param str  utf-8 string
 * @return Uint8Array
 */
export const arrayFromUtf8String = (str) => {
  webCryptographer.assert(isString(str), 'arrayFromUtf8String: invalid input');
  // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.
  str = unescape(encodeURIComponent(str));
  return arrayFromString(str);
};

/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  arrayish
 * @return ascii string
 */
export const stringFromArray = (arr) => {
  arr = arrayish(arr);
  var r = '';
  for (var i = 0; i < arr.length; i++) {
    r += String.fromCharCode(arr[i]);
  }

  return r;
};

/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  ArrayBuffer
 * @return ascii string
 */
export const utf8StringFromArray = (arr) => {
  webCryptographer.assert(arr instanceof ArrayBuffer, 'utf8StringFromArray: invalid input');

  // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.
  var r = stringFromArray(arr);
  return decodeURIComponent(escape(r));
};

/**
 * Strips leading zero in an array.
 *
 * @param arr  arrayish
 * @return array
 */
export const stripLeadingZeros = (arr) => {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }
  var isLeadingZero = true;
  var r = [];
  for (var i = 0; i < arr.length; i++) {
    if (isLeadingZero && arr[i] === 0) {
      continue;
    }
    isLeadingZero = false;
    r.push(arr[i]);
  }
  return r;
};

/**
 * Converts a number into an array of 4 bytes (big endian).
 *
 * @param i  number
 * @return ArrayBuffer
 */
export const arrayFromInt32 = (i) => {
  webCryptographer.assert(typeof (i) === 'number', 'arrayFromInt32: invalid input');
  // TODO(eslint): figure out if there's a better way to validate i
  // eslint-disable-next-line eqeqeq, no-self-compare
  webCryptographer.assert(i == i | 0, 'arrayFromInt32: out of range');

  var buf = new Uint8Array(new Uint32Array([i]).buffer);
  var r = new Uint8Array(4);
  for (var j = 0; j < 4; j++) {
    r[j] = buf[3 - j];
  }
  return r.buffer;
};

/**
 * Concatenates arrayishes.
 *
 * note: cannot be a Arrow function, because Arrow functions do not expose 'arguments' object
 * and Rest parameters are not supported in Babel yet.
 *
 * @param arguments two or more arrayishes
 * @return Uint8Array
 */
export function arrayBufferConcat (/* ... */) {
  // Compute total size
  var args = [];
  var total = 0;
  for (var i = 0; i < arguments.length; i++) {
    args.push(arrayish(arguments[i]));
    total += args[i].length;
  }
  var r = new Uint8Array(total);
  var offset = 0;
  for (i = 0; i < arguments.length; i++) {
    for (var j = 0; j < args[i].length; j++) {
      r[offset++] = args[i][j];
    }
  }
  webCryptographer.assert(offset === total, 'arrayBufferConcat: unexpected offset');
  return r;
}

export const sha256 = (str) => {
  // Browser docs indicate the first parameter to crypto.subtle.digest to be a
  // DOMString. This was initially implemented as an object and continues to be
  // supported, so we favor the older form for backwards compatibility.
  return Jose.crypto.subtle.digest({ name: 'SHA-256' }, arrayFromString(str)).then(function (hash) {
    return new Base64Url().encodeArray(hash);
  });
};

export const isCryptoKey = (rsaKey) => {
  // Some browsers don't expose the CryptoKey as an object, so we need to check
  // the constructor's name.
  if (rsaKey.constructor.name === 'CryptoKey') {
    return true;
  }

  // In the presence of minifiers, relying on class names can be problematic,
  // so let's also allow objects that have an 'algorithm' property.
  if (Object.prototype.hasOwnProperty.call(rsaKey, 'algorithm')) {
    return true;
  }

  return false;
};
export class Base64Url {
  /**
   * Base64Url encodes a string (no trailing '=')
   *
   * @param str  string
   * @return string
   */
  encode (str) {
    webCryptographer.assert(isString(str), 'Base64Url.encode: invalid input');
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /**
   * Base64Url encodes an array
   *
   * @param arr array or ArrayBuffer
   * @return string
   */
  encodeArray (arr) {
    return this.encode(stringFromArray(arr));
  }

  /**
   * Base64Url decodes a string
   *
   * @param str  string
   * @return string
   */
  decode (str) {
    webCryptographer.assert(isString(str), 'Base64Url.decode: invalid input');
    // atob is nice and ignores missing '='
    return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  }

  decodeArray (str) {
    webCryptographer.assert(isString(str), 'Base64Url.decodeArray: invalid input');
    return arrayFromString(this.decode(str));
  }
}
