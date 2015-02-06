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
var Utils = {};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP. Also accepts (and validates)
 * JWK keys.
 *
 * @param rsa_key  public RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @return Promise<CryptoKey>
 */
JoseJWE.Utils.importRsaPublicKey = function(rsa_key) {
  var jwk = Utils.convertRsaKey(rsa_key, ["n", "e"]);
  var config = getCryptoConfig("RSA-OAEP");
  return crypto.subtle.importKey("jwk", jwk, config.id, false, ["wrapKey"]);
};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP. Also accepts (and validates)
 * JWK keys.
 *
 * @param rsa_key  private RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @return Promise<CryptoKey>
 */
JoseJWE.Utils.importRsaPrivateKey = function(rsa_key) {
  var jwk = Utils.convertRsaKey(rsa_key, ["n", "e", "d", "p", "q", "dp", "dq", "qi"]);
  var config = getCryptoConfig("RSA-OAEP");
  return crypto.subtle.importKey("jwk", jwk, config.id, false, ["unwrapKey"]);
};

// Private functions

Utils.isString = function(str) {
  return ((typeof(str) == "string") || (str instanceof String));
};

/**
 * Takes an arrayish (an array, ArrayBuffer or Uint8Array)
 * and returns an array or a Uint8Array.
 *
 * @param arr  arrayish
 * @return array or Uint8Array
 */
Utils.arrayish = function(arr) {
  if (arr instanceof Array) {
    return arr;
  }
  if (arr instanceof Uint8Array) {
    return arr;
  }
  if (arr instanceof ArrayBuffer) {
    return new Uint8Array(arr);
  }
  JoseJWE.assert(false, "arrayish: invalid input");
};

/**
 * Checks if an RSA key contains all the expected parameters. Also checks their
 * types. Converts hex encoded strings (or numbers) to base64.
 *
 * @param rsa_key     RSA key in json format. Parameters can be base64 encoded,
 *                    strings or number (for 'e').
 * @param parameters  array<string>
 * @return json
 */
Utils.convertRsaKey = function(rsa_key, parameters) {
  var r = {};

  // Check that we have all the parameters
  var missing = [];
  parameters.map(function(p){if (rsa_key[p] === undefined) { missing.push(p); }});

  if (missing.length > 0) {
    JoseJWE.assert(false, "convertRsaKey: Was expecting " + missing.join());
  }

  // kty is either missing or is set to "RSA"
  if (rsa_key.kty !== undefined) {
    JoseJWE.assert(rsa_key.kty == "RSA", "convertRsaKey: expecting rsa_key['kty'] to be 'RSA'");
  }
  r.kty = "RSA";

  // alg is either missing or is set to "RSA-OAEP"
  if (rsa_key.alg !== undefined) {
    JoseJWE.assert(rsa_key.alg == "RSA-OAEP", "convertRsaKey: expecting rsa_key['alg'] to be 'RSA-OAEP'");
  }
  r.alg = "RSA-OAEP";

  // note: we punt on checking key_ops

  var intFromHex = function(e){return parseInt(e, 16);};
  for (var i=0; i<parameters.length; i++) {
    var p = parameters[i];
    var v = rsa_key[p];
    if (p == "e") {
      if (typeof(v) == "number") {
        v = Utils.Base64Url.encodeArray(Utils.stripLeadingZeros(Utils.arrayFromInt32(v)));
      }
    } else if (/^([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$/.test(v)) {
      var arr = v.split(":").map(intFromHex);
      v = Utils.Base64Url.encodeArray(Utils.stripLeadingZeros(arr));
    } else if (typeof(v) != "string") {
      JoseJWE.assert(false, "convertRsaKey: expecting rsa_key['" + p + "'] to be a string");
    }
    r[p] = v;
  }

  return r;
};

/**
 * Converts a string into an array of ascii codes.
 *
 * @param str  string
 * @return Uint8Array
 */
Utils.arrayFromString = function(str) {
  JoseJWE.assert(Utils.isString(str), "arrayFromString: invalid input");
  var arr = str.split('').map(function(c){return c.charCodeAt(0);});
  return new Uint8Array(arr);
};

/**
 * Converts an array of ascii codes into a string.
 *
 * @param arr  ArrayBuffer
 * @return string
 */
Utils.stringFromArray = function(arr) {
  JoseJWE.assert(arr instanceof ArrayBuffer, "stringFromArray: invalid input");
  arr = new Uint8Array(arr);
  r = '';
  for (var i = 0; i<arr.length; i++) {
    r += String.fromCharCode(arr[i]);
  }
  return r;
};

/**
 * Strips leading zero in an array.
 *
 * @param arr  arrayish
 * @return array
 */
Utils.stripLeadingZeros = function(arr) {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }
  var is_leading_zero = true;
  var r = [];
  for (var i=0; i<arr.length; i++) {
    if (is_leading_zero && arr[i] === 0) {
      continue;
    }
    is_leading_zero = false;
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
Utils.arrayFromInt32 = function(i) {
  JoseJWE.assert(typeof(i) == "number", "arrayFromInt32: invalid input");
  JoseJWE.assert(i == i|0, "arrayFromInt32: out of range");

  var buf = new Uint8Array(new Uint32Array([i]).buffer);
  var r = new Uint8Array(4);
  for (var j=0; j<4; j++) {
    r[j] = buf[3-j];
  }
  return r.buffer;
};

/**
 * Concatenates arrayishes.
 *
 * @param two or more arrayishes
 * @return Uint8Array
 */
Utils.arrayBufferConcat = function(/* ... */) {
  // Compute total size
  var args = [];
  var total = 0;
  for (var i=0; i<arguments.length; i++) {
    args.push(Utils.arrayish(arguments[i]));
    total += args[i].length;
  }
  var r = new Uint8Array(total);
  var offset = 0;
  for (i=0; i<arguments.length; i++) {
    for (var j=0; j<args[i].length; j++) {
      r[offset++] = args[i][j];
    }
  }
  JoseJWE.assert(offset == total, "arrayBufferConcat: unexpected offset");
  return r;
};

/**
 * Compares two Uint8Arrays in constant time.
 *
 * @return Promise<void>
 */
Utils.compare = function(config, mac_key_promise, arr1, arr2) {
  JoseJWE.assert(arr1 instanceof Uint8Array, "compare: invalid input");
  JoseJWE.assert(arr2 instanceof Uint8Array, "compare: invalid input");

  return mac_key_promise.then(function(mac_key) {
    var hash1 = crypto.subtle.sign(config.auth.id, mac_key, arr1);
    var hash2 = crypto.subtle.sign(config.auth.id, mac_key, arr2);
    return Promise.all([hash1, hash2]).then(function(all) {
      var hash1 = new Uint8Array(all[0]);
      var hash2 = new Uint8Array(all[1]);
      if (hash1.length != hash2.length) {
        throw new Error("compare failed");
      }
      for (var i=0; i<hash1.length; i++) {
        if (hash1[i] != hash2[i]) {
          throw new Error("compare failed");
        }
      }
      return Promise.accept(null);
    });
  });
};

/**
 * Returns algorithm and operation needed to create a CEK.
 *
 * In some cases, e.g. A128CBC-HS256, the CEK gets split into two keys. The Web
 * Crypto API does not allow us to generate an arbitrary number of bytes and
 * then create a CryptoKey without any associated algorithm. We therefore piggy
 * back on AES-CBS and HMAC which allows the creation of CEKs of size 16, 32, 64
 * and 128 bytes.
 */
Utils.getCekWorkaround = function(alg) {
  var len = alg.specific_cek_bytes;
  if (len) {
    if (len == 16) {
      return {id: {name: "AES-CBC", length: 128}, enc_op: ["encrypt"], dec_op: ["decrypt"]};
    } else if (len == 32) {
      return {id: {name: "AES-CBC", length: 256}, enc_op: ["encrypt"], dec_op: ["decrypt"]};
    } else if (len == 64) {
      return {id: {name: "HMAC", hash: {name: "SHA-256"}}, enc_op: ["sign"], dec_op: ["verify"]};
    } else if (len == 128) {
      return {id: {name: "HMAC", hash: {name: "SHA-384"}}, enc_op: ["sign"], dec_op: ["verify"]};
    } else {
      JoseJWE.assert(false, "getCekWorkaround: invalid len");
    }
  }
  return {id: alg.id, enc_op: ["encrypt"], dec_op: ["decrypt"]};
};

Utils.Base64Url = {};

/**
 * Base64Url encodes a string (no trailing '=')
 *
 * @param str  string
 * @return string
 */
Utils.Base64Url.encode = function(str) {
  JoseJWE.assert(Utils.isString(str), "Base64Url.encode: invalid input");
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

/**
 * Base64Url encodes an array
 *
 * @param buf  array or ArrayBuffer
 * @return string
 */
Utils.Base64Url.encodeArray = function(arr) {
  arr = Utils.arrayish(arr);
  var r = "";
  for (i=0; i<arr.length; i++) {
    r+=String.fromCharCode(arr[i]);
  }
  return Utils.Base64Url.encode(r);
};

/**
 * Base64Url decodes a string
 *
 * @param str  string
 * @return string
 */
Utils.Base64Url.decode = function(str) {
  JoseJWE.assert(Utils.isString(str), "Base64Url.decode: invalid input");
  // atob is nice and ignores missing '='
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
};

Utils.Base64Url.decodeArray = function(str) {
  JoseJWE.assert(Utils.isString(str), "Base64Url.decodeArray: invalid input");
  return Utils.arrayFromString(Utils.Base64Url.decode(str));
};
