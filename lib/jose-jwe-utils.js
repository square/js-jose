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
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsa_key  public RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @param usage    String having either "wrapKey" or "sign" as a value. Default: wrapKey
 * @return Promise<CryptoKey>
 */
JoseJWE.Utils.importRsaPublicKey = function(rsa_key, alg, usage) {
  var jwk,
    config = null,
    rk;

  usage = usage || "wrapKey";
  alg = alg || (usage == "wrapKey" ? "RSA-OAEP" : "RS256");

  if (usage == "wrapKey") {
    jwk = Utils.convertRsaKey(rsa_key, ["n", "e"]);
    config = getCryptoConfig(alg);
  } else {
    rk = Object.create(rsa_key);
    config = getSignConfig(alg);
    if (!rk.alg && alg) {
      rk.alg = alg;
    }
    jwk = Utils.convertRsaKey(rk, ["n", "e"]);
    jwk.ext = true;
  }
  return crypto.subtle.importKey("jwk", jwk, config.id, false, [usage]);
};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP and RSA. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsa_key  private RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @param usage    string having either "unwrapKey" or "sign" as a value. Default: unwrapKey
 * @return Promise<CryptoKey>
 */
JoseJWE.Utils.importRsaPrivateKey = function(rsa_key, alg, usage) {
  var jwk,
    config,
    rk;

  usage = usage || "unwrapKey";
  alg = alg || (usage == "unwrapKey" ? "RSA-OAEP" : "RS256");

  if (usage == "unwrapKey") {
    jwk = Utils.convertRsaKey(rsa_key, ["n", "e", "d", "p", "q", "dp", "dq", "qi"]);
    config = getCryptoConfig("RSA-OAEP");
  } else {
    rk = Object.create(rsa_key);
    config = getSignConfig(alg);
    if (!rk.alg && alg) {
      rk.alg = alg;
    }
    jwk = Utils.convertRsaKey(rk, ["n", "e", "d", "p", "q", "dp", "dq", "qi"]);
    jwk.ext = true;
  }
  return crypto.subtle.importKey("jwk", jwk, config.id, false, [usage]);
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
  Jose.assert(false, "arrayish: invalid input");
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
    Jose.assert(false, "convertRsaKey: Was expecting " + missing.join());
  }

  // kty is either missing or is set to "RSA"
  if (rsa_key.kty !== undefined) {
    Jose.assert(rsa_key.kty == "RSA", "convertRsaKey: expecting rsa_key['kty'] to be 'RSA'");
  }
  r.kty = "RSA";

  // alg is either missing or is set to "RSA-OAEP"
  if (rsa_key.alg !== undefined) {
    // Jose.assert(rsa_key.alg == "RSA-OAEP" || rsa_key.alg == "RS256", "convertRsaKey: expecting rsa_key['alg'] to be 'RSA-OAEP'");
    r.alg = rsa_key.alg;
  } else {
    r.alg = "RSA-OAEP";
  }

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
      Jose.assert(false, "convertRsaKey: expecting rsa_key['" + p + "'] to be a string");
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
  Jose.assert(Utils.isString(str), "arrayFromString: invalid input");
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
  Jose.assert(arr instanceof ArrayBuffer, "stringFromArray: invalid input");
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
  Jose.assert(typeof(i) == "number", "arrayFromInt32: invalid input");
  Jose.assert(i == i|0, "arrayFromInt32: out of range");

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
 * @param arguments two or more arrayishes
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
  Jose.assert(offset == total, "arrayBufferConcat: unexpected offset");
  return r;
};

Utils.Base64Url = {};

/**
 * Base64Url encodes a string (no trailing '=')
 *
 * @param str  string
 * @return string
 */
Utils.Base64Url.encode = function(str) {
  Jose.assert(Utils.isString(str), "Base64Url.encode: invalid input");
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

/**
 * Base64Url encodes an array
 *
 * @param arr array or ArrayBuffer
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
  Jose.assert(Utils.isString(str), "Base64Url.decode: invalid input");
  // atob is nice and ignores missing '='
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
};

Utils.Base64Url.decodeArray = function(str) {
  Jose.assert(Utils.isString(str), "Base64Url.decodeArray: invalid input");
  return Utils.arrayFromString(Utils.Base64Url.decode(str));
};
