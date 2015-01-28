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
