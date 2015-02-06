(function(){
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

/**
 * JSON Web Encryption (JWE) library for JavaScript.
 *
 * @author Alok Menghrajani <alok@squareup.com>
 */

/**
 * Initializes a JoseJWE object.
 */
JoseJWE = function() {
  this.setKeyEncryptionAlgorithm("RSA-OAEP");
  this.setContentEncryptionAlgorithm("A256GCM");
};

/**
 * Feel free to override this function.
 */
JoseJWE.assert = function(expr, msg) {
  if (!expr) {
    throw new Error(msg);
  }
};

/**
 * Overrides the default key encryption algorithm
 * @param alg  string
 */
JoseJWE.prototype.setKeyEncryptionAlgorithm = function(alg) {
  this.key_encryption = getCryptoConfig(alg);
};

/**
 * Overrides the default content encryption algorithm
 * @param alg  string
 */
JoseJWE.prototype.setContentEncryptionAlgorithm = function(alg) {
  this.content_encryption = getCryptoConfig(alg);
};

// Private functions

/**
 * Converts the Jose web algorithms into data which is
 * useful for the Web Crypto API.
 *
 * length = in bits
 * bytes = in bytes
 */
var getCryptoConfig = function(alg) {
  switch (alg) {
    // Key encryption
    case "RSA-OAEP":
      return {
        jwe_name: "RSA-OAEP",
        id: {name: "RSA-OAEP", hash: {name: "SHA-1"}}
      };
    case "RSA-OAEP-256":
     return {
        jwe_name: "RSA-OAEP-256",
        id: {name: "RSA-OAEP", hash: {name: "SHA-256"}}
      };
    case "A128KW":
      return {
        jwe_name: "A128KW",
        id: {name: "AES-KW", length: 128}
      };
    case "A256KW":
      return {
        jwe_name: "A256KW",
        id: {name: "AES-KW", length: 256}
    };

    // Content encryption
    case "A128CBC-HS256":
      return {
        jwe_name: "A128CBC-HS256",
        id: {name: "AES-CBC", length: 128},
        iv_bytes: 16,
        specific_cek_bytes: 32,
        auth: {
          key_bytes: 16,
          id: {name: "HMAC", hash: {name: "SHA-256"}},
          truncated_bytes: 16
        }
      };
    case "A256CBC-HS512":
      return {
        id: {name: "AES-CBC", length: 256},
        iv_bytes: 16,
        specific_cek_bytes: 64,
        auth: {
          key_bytes: 32,
          id: {name: "HMAC", hash: {name: "SHA-512"}},
          truncated_bytes: 32
        }
      };
    case "A128GCM":
      return {
        id: {name: "AES-GCM", length: 128},
        iv_bytes: 12,
        auth: {
          aead: true,
          tag_bytes: 16
        }
      };
    case "A256GCM":
      return {
        jwe_name: "A256GCM",
        id: {name: "AES-GCM", length: 256},
        iv_bytes: 12,
        auth: {
          aead: true,
          tag_bytes: 16
        }
      };
    default:
      JoseJWE.assert(false, "unsupported algorithm: " + alg);
  }
};


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

/**
 * Generates an IV.
 * This function mainly exists so that it can be mocked for testing purpose.
 *
 * @return Uint8Array with random bytes
 */
JoseJWE.prototype.createIV = function() {
  var iv = new Uint8Array(new Array(this.content_encryption.iv_bytes));
  return crypto.getRandomValues(iv);
};

/**
 * Creates a random content encryption key.
 * This function mainly exists so that it can be mocked for testing purpose.
 *
 * @return Promise<CryptoKey>
 */
JoseJWE.prototype.createCEK = function() {
  var hack = Utils.getCekWorkaround(this.content_encryption);
  return crypto.subtle.generateKey(hack.id, true, hack.enc_op);
};

/**
 * Performs encryption
 *
 * @param key_promise  Promise<CryptoKey>, either RSA or shared key
 * @param plain_text   string to encrypt
 * @return Promise<string>
 */
JoseJWE.prototype.encrypt = function(key_promise, plain_text) {
  // Create a CEK key
  var cek_promise = this.createCEK();

  // Key & Cek allows us to create the encrypted_cek
  var encrypted_cek = this.encryptCek(key_promise, cek_promise);

  // Cek allows us to encrypy the plain text
  var enc_promise = this.encryptPlainText(cek_promise, plain_text);

  // Once we have all the promises, we can base64 encode all the pieces.
  return Promise.all([encrypted_cek, enc_promise]).then(function(all) {
    var encrypted_cek = all[0];
    var data = all[1];
    return data.header + "." +
      Utils.Base64Url.encodeArray(encrypted_cek) + "." +
      Utils.Base64Url.encodeArray(data.iv) + "." +
      Utils.Base64Url.encodeArray(data.cipher) + "." +
      Utils.Base64Url.encodeArray(data.tag);
  });
};

/**
 * Encrypts the CEK
 *
 * @param key_promise  Promise<CryptoKey>
 * @param cek_promise  Promise<CryptoKey>
 * @return Promise<ArrayBuffer>
 */
JoseJWE.prototype.encryptCek = function(key_promise, cek_promise) {
  var config = this.key_encryption;
  return Promise.all([key_promise, cek_promise]).then(function(all) {
    var key = all[0];
    var cek = all[1];
    return crypto.subtle.wrapKey("raw", cek, key, config.id);
  });
};

/**
 * Encrypts plain_text with CEK.
 *
 * @param cek_promise  Promise<CryptoKey>
 * @param plain_text   string
 * @return Promise<json>
 */
JoseJWE.prototype.encryptPlainText = function(cek_promise, plain_text) {
  // Create header
  var jwe_protected_header = Utils.Base64Url.encode(JSON.stringify({
    "alg": this.key_encryption.jwe_name,
    "enc": this.content_encryption.jwe_name
  }));

  // Create the IV
  var iv = this.createIV();
  if (iv.length != this.content_encryption.iv_bytes) {
    return Promise.reject("encryptPlainText: invalid IV length");
  }

  // Create the AAD
  var aad = Utils.arrayFromString(jwe_protected_header);
  plain_text = Utils.arrayFromString(plain_text);

  var config = this.content_encryption;
  if (config.auth.aead) {
    var tag_bytes = config.auth.tag_bytes;

    var enc = {
      name: config.id.name,
      iv: iv,
      additionalData: aad,
      tagLength: tag_bytes * 8
    };

    return cek_promise.then(function(cek) {
      return crypto.subtle.encrypt(enc, cek, plain_text).then(function(cipher_text) {
        var offset = cipher_text.byteLength - tag_bytes;
        return {
          header: jwe_protected_header,
          iv: iv,
          cipher: cipher_text.slice(0, offset),
          tag: cipher_text.slice(offset)
        };
      });
    });
  } else {
    var keys = EncryptThenMac.splitKey(config, cek_promise, ["encrypt"]);
    var mac_key_promise = keys[0];
    var enc_key_promise = keys[1];

    // Encrypt the plain text
    var cipher_text_promise = enc_key_promise.then(function(enc_key) {
      var enc = {
        name: config.id.name,
        iv: iv,
      };
      return crypto.subtle.encrypt(enc, enc_key, plain_text);
    });

    // compute MAC
    var mac_promise = cipher_text_promise.then(function(cipher_text) {
      return EncryptThenMac.truncatedMac(
        config,
        mac_key_promise,
        aad,
        iv,
        cipher_text);
    });

    return Promise.all([cipher_text_promise, mac_promise]).then(function(all) {
      var cipher_text = all[0];
      var mac = all[1];
      return {
        header: jwe_protected_header,
        iv: iv,
        cipher: cipher_text,
        tag: mac
      };
    });
  }
};

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

/**
 * Performs decryption
 *
 * @param key_promise  Promise<CryptoKey>, either RSA private key or shared key
 * @param plain_text   string to decrypt
 * @return Promise<string>
 */
JoseJWE.prototype.decrypt = function(key_promise, cipher_text) {
  // Split cipher_text in 5 parts
  var parts = cipher_text.split(".");
  if (parts.length != 5) {
    return Promise.reject("decrypt: invalid input");
  }

  // part 1: header
  header = JSON.parse(Utils.Base64Url.decode(parts[0]));
  if (!header.alg) {
    return Promise.reject("decrypt: missing alg");
  }
  this.setKeyEncryptionAlgorithm(header.alg);

  if (!header.enc) {
    return Promise.reject("decrypt: missing enc");
  }
  this.setContentEncryptionAlgorithm(header.enc);

  if (header.crit) {
    // We don't support the crit header
    return Promise.reject("decrypt: crit is not supported");
  }

  // part 2: decrypt the CEK
  var cek_promise = this.decryptCek(key_promise, Utils.Base64Url.decodeArray(parts[1]));

  // part 3: decrypt the cipher text
  var plain_text_promise = this.decryptCiphertext(
    cek_promise,
    Utils.arrayFromString(parts[0]),
    Utils.Base64Url.decodeArray(parts[2]),
    Utils.Base64Url.decodeArray(parts[3]),
    Utils.Base64Url.decodeArray(parts[4]));

  return plain_text_promise.then(Utils.stringFromArray);
};

/**
 * @param key_promise    Promise<CryptoKey>
 * @param encrypted_cek  string
 * @return Promise<string>
 */
JoseJWE.prototype.decryptCiphertext = function(cek_promise, aad, iv, cipher_text, tag) {
  if (iv.length != this.content_encryption.iv_bytes) {
    return Promise.reject("decryptCiphertext: invalid IV");
  }

  var config = this.content_encryption;
  if (config.auth.aead) {
    var dec = {
      name: config.id.name,
      iv: iv,
      additionalData: aad,
      tagLength: config.auth.tag_bytes * 8
    };

    return cek_promise.then(function(cek) {
      var buf = Utils.arrayBufferConcat(cipher_text, tag);
      return crypto.subtle.decrypt(dec, cek, buf);
    });
  } else {
    var keys = EncryptThenMac.splitKey(config, cek_promise, ["decrypt"]);
    var mac_key_promise = keys[0];
    var enc_key_promise = keys[1];

    // Validate the MAC
    var mac_promise = EncryptThenMac.truncatedMac(
      config,
      mac_key_promise,
      aad,
      iv,
      cipher_text);

    return Promise.all([enc_key_promise, mac_promise]).then(function(all) {
      var enc_key = all[0];
      var mac = all[1];

      return Utils.compare(config, mac_key_promise, new Uint8Array(mac), tag).then(function() {
        var dec = {
          name: config.id.name,
          iv: iv,
        };
        return crypto.subtle.decrypt(dec, enc_key, cipher_text);
      }).catch(function (err) {
        return Promise.reject("decryptCiphertext: MAC failed.");
      });
    });
  }
};

/**
 * Decrypts the encrypted CEK. If decryption fails, we create a random CEK.
 *
 * In some modes (e.g. RSA-PKCS1v1.5), you myst take precautions to prevent
 * chosen-ciphertext attacks as described in RFC 3218, "Preventing
 * the Million Message Attack on Cryptographic Message Syntax". We currently
 * only support RSA-OAEP, so we don't generate a key if unwrapping fails.
 *
 * return Promise<CryptoKey>
 */
JoseJWE.prototype.decryptCek = function(key_promise, encrypted_cek) {
  var hack = Utils.getCekWorkaround(this.content_encryption);
  var extractable = (this.content_encryption.specific_cek_bytes > 0);
  var key_encryption = this.key_encryption.id;

  return key_promise.then(function(key) {
    return crypto.subtle.unwrapKey("raw", encrypted_cek, key, key_encryption, hack.id, extractable, hack.dec_op);
  });
};

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

var EncryptThenMac = {};

/**
 * Splits a CEK into two pieces: a MAC key and an ENC key.
 *
 * This code is structured around the fact that the crypto API does not provide
 * a way to validate truncated MACs. The MAC key is therefore always imported to
 * sign data.
 *
 * @param hash                config (used for key lengths & algorithms)
 * @param Promise<CryptoKey>  CEK key to split
 * @return [Promise<mac key>, Promise<enc key>]
 */
EncryptThenMac.splitKey = function(config, cek_promise, purpose) {
  // We need to split the CEK key into a MAC and ENC keys
  var cek_bytes_promise = cek_promise.then(function(cek) {
    return crypto.subtle.exportKey("raw", cek);
  });
  var mac_key_promise = cek_bytes_promise.then(function(cek_bytes) {
    if (cek_bytes.byteLength * 8 != config.id.length + config.auth.key_bytes * 8) {
      return Promise.reject("encryptPlainText: incorrect cek length");
    }
    var bytes = cek_bytes.slice(0, config.auth.key_bytes);
    return crypto.subtle.importKey("raw", bytes, config.auth.id, false, ["sign"]);
  });
  var enc_key_promise = cek_bytes_promise.then(function(cek_bytes) {
    if (cek_bytes.byteLength * 8 != config.id.length + config.auth.key_bytes * 8) {
      return Promise.reject("encryptPlainText: incorrect cek length");
    }
    var bytes = cek_bytes.slice(config.auth.key_bytes);
    return crypto.subtle.importKey("raw", bytes, config.id, false, purpose);
  });
  return [mac_key_promise, enc_key_promise];
};

/**
 * Computes a truncated MAC.
 *
 * @param hash                config
 * @param Promise<CryptoKey>  mac key
 * @param Uint8Array          aad
 * @param Uint8Array          iv
 * @param Uint8Array          cipher_text
 * @return Promise<buffer>    truncated MAC
 */
EncryptThenMac.truncatedMac = function(config, mac_key_promise, aad, iv, cipher_text) {
  return mac_key_promise.then(function(mac_key) {
    var al = new Uint8Array(Utils.arrayFromInt32(aad.length * 8));
    var al_full = new Uint8Array(8);
    al_full.set(al, 4);
    var buf = Utils.arrayBufferConcat(aad, iv, cipher_text, al_full);
    return crypto.subtle.sign(config.auth.id, mac_key, buf).then(function(bytes) {
      return bytes.slice(0, config.auth.truncated_bytes);
    });
  });
};
}());
