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
 * Performs encryption
 *
 * @param key_promise  Promise<CryptoKey>, either RSA or shared key
 * @param plain_text   string to encrypt
 * @return Promise<string>
 */
JoseJWE.encrypt = function(cryptographer, key_promise, plain_text) {
  /**
   * Encrypts the CEK
   *
   * @param key_promise  Promise<CryptoKey>
   * @param cek_promise  Promise<CryptoKey>
   * @return Promise<ArrayBuffer>
   */
  var encryptCek = function(key_promise, cek_promise) {
    return Promise.all([key_promise, cek_promise]).then(function(all) {
      var key = all[0];
      var cek = all[1];
      return cryptographer.wrapCek(cek, key);
    });
  };

  /**
   * Encrypts plain_text with CEK.
   *
   * @param cek_promise  Promise<CryptoKey>
   * @param plain_text   string
   * @return Promise<json>
   */
  var encryptPlainText = function(cek_promise, plain_text) {
    // Create header
    var jwe_protected_header = Utils.Base64Url.encode(JSON.stringify({
      "alg": cryptographer.getKeyEncryptionAlgorithm(),
      "enc": cryptographer.getContentEncryptionAlgorithm()
    }));

    // Create the IV
    var iv = cryptographer.createIV();

    // Create the AAD
    var aad = Utils.arrayFromString(jwe_protected_header);
    plain_text = Utils.arrayFromString(plain_text);

    return cryptographer.encrypt(iv, aad, cek_promise, plain_text).then(function(r) {
      r.header = jwe_protected_header;
      r.iv = iv;
      return r;
    });
  };

  // Create a CEK key
  var cek_promise = cryptographer.createCek();

  // Key & Cek allows us to create the encrypted_cek
  var encrypted_cek = encryptCek(key_promise, cek_promise);

  // Cek allows us to encrypy the plain text
  var enc_promise = encryptPlainText(cek_promise, plain_text);

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
