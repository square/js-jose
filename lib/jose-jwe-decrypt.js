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
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param key_promise    Promise<CryptoKey>, either RSA or shared key
 */
JoseJWE.Decrypter = function (cryptographer, key_promise) {
  this.cryptographer = cryptographer;
  this.key_promise = key_promise;
  this.headers = {};
};

JoseJWE.Decrypter.prototype.getHeaders = function () {
  return this.headers;
};

/**
 * Performs decryption.
 *
 * @param cipher_text  String
 * @return Promise<String>
 */
JoseJWE.Decrypter.prototype.decrypt = function (cipher_text) {
  var that = this;
  // Split cipher_text in 5 parts
  var parts = cipher_text.split(".");
  if (parts.length != 5) {
    return Promise.reject(Error("decrypt: invalid input"));
  }

  // part 1: header
  that.headers = JSON.parse(Utils.Base64Url.decode(parts[0]));
  if (!that.headers.alg) {
    return Promise.reject(Error("decrypt: missing alg"));
  }
  if (!that.headers.enc) {
    return Promise.reject(Error("decrypt: missing enc"));
  }
  that.cryptographer.setKeyEncryptionAlgorithm(this.headers.alg);
  that.cryptographer.setContentEncryptionAlgorithm(this.headers.enc);

  if (that.headers.crit) {
    // We don't support the crit header
    return Promise.reject(Error("decrypt: crit is not supported"));
  }

  // part 2: decrypt the CEK
  // In some modes (e.g. RSA-PKCS1v1.5), you must take precautions to prevent
  // chosen-ciphertext attacks as described in RFC 3218, "Preventing
  // the Million Message Attack on Cryptographic Message Syntax". We currently
  // only support RSA-OAEP, so we don't generate a key if unwrapping fails.
  var encrypted_cek = Utils.Base64Url.decodeArray(parts[1]);
  var cek_promise = that.key_promise.then(function (key) {
    return this.cryptographer.unwrapCek(encrypted_cek, key);
  }.bind(that));

  // part 3: decrypt the cipher text
  var plain_text_promise = that.cryptographer.decrypt(
    cek_promise,
    Utils.arrayFromString(parts[0]),
    Utils.Base64Url.decodeArray(parts[2]),
    Utils.Base64Url.decodeArray(parts[3]),
    Utils.Base64Url.decodeArray(parts[4]));

  return plain_text_promise.then(Utils.stringFromArray);
};
