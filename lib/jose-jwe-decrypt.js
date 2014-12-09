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
  header = JSON.parse(JoseJWE.Utils.Base64Url.decode(parts[0]));
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
  var cek_promise = this.decryptCek(key_promise, JoseJWE.Utils.Base64Url.decodeArray(parts[1]));

  // part 3: decrypt the cipher text
  var plain_text_promise = this.decryptCiphertext(
    cek_promise,
    JoseJWE.Utils.arrayFromString(parts[0]),
    JoseJWE.Utils.Base64Url.decodeArray(parts[2]),
    JoseJWE.Utils.Base64Url.decodeArray(parts[3]),
    JoseJWE.Utils.Base64Url.decodeArray(parts[4]));

  return plain_text_promise.then(JoseJWE.Utils.stringFromArray);
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
      var buf = JoseJWE.Utils.arrayBufferConcat(cipher_text, tag);
      return crypto.subtle.decrypt(dec, cek, buf);
    });
  } else {
    var keys = JoseJWE.MacThenEncrypt.splitKey(config, cek_promise, ["decrypt"]);
    var mac_key_promise = keys[0];
    var enc_key_promise = keys[1];

    // Validate the MAC
    var mac_promise = JoseJWE.MacThenEncrypt.truncatedMac(
      config,
      mac_key_promise,
      aad,
      iv,
      cipher_text);

    return Promise.all([enc_key_promise, mac_promise]).then(function(all) {
      var enc_key = all[0];
      var mac = all[1];

      if (!JoseJWE.Utils.compare(new Uint8Array(mac), tag)) {
        return Promise.reject("decryptCiphertext: MAC failed.");
      }

      var dec = {
        name: config.id.name,
        iv: iv,
      };
      return crypto.subtle.decrypt(dec, enc_key, cipher_text);
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
  var hack = JoseJWE.Utils.getCekWorkaround(this.content_encryption);
  var extractable = (this.content_encryption.specific_cek_bytes > 0);
  var key_encryption = this.key_encryption.id;

  return key_promise.then(function(key) {
    return crypto.subtle.unwrapKey("raw", encrypted_cek, key, key_encryption, hack.id, extractable, hack.dec_op);
  });
};
