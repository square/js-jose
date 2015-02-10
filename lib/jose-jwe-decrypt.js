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
JoseJWE.decrypt = function(cryptographer, key_promise, cipher_text) {
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
  var decryptCek = function(key_promise, encrypted_cek) {
    return key_promise.then(function(key) {
      return cryptographer.unwrapCek(encrypted_cek, key);
    });
  };

  // Split cipher_text in 5 parts
  var parts = cipher_text.split(".");
  if (parts.length != 5) {
    return Promise.reject(Error("decrypt: invalid input"));
  }

  // part 1: header
  header = JSON.parse(Utils.Base64Url.decode(parts[0]));
  if (!header.alg) {
    return Promise.reject(Error("decrypt: missing alg"));
  }
  cryptographer.setKeyEncryptionAlgorithm(header.alg);

  if (!header.enc) {
    return Promise.reject(Error("decrypt: missing enc"));
  }
  cryptographer.setContentEncryptionAlgorithm(header.enc);

  if (header.crit) {
    // We don't support the crit header
    return Promise.reject(Error("decrypt: crit is not supported"));
  }

  // part 2: decrypt the CEK
  var cek_promise = decryptCek(key_promise, Utils.Base64Url.decodeArray(parts[1]));

  // part 3: decrypt the cipher text
  var plain_text_promise = cryptographer.decrypt(
    cek_promise,
    Utils.arrayFromString(parts[0]),
    Utils.Base64Url.decodeArray(parts[2]),
    Utils.Base64Url.decodeArray(parts[3]),
    Utils.Base64Url.decodeArray(parts[4]));

  return plain_text_promise.then(Utils.stringFromArray);
};
