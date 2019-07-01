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

import * as Utils from './jose-utils';

/**
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param keyPromise    Promise<CryptoKey>, either RSA or shared key
 */
export class Decrypter {
  constructor (cryptographer, keyPromise) {
    this.cryptographer = cryptographer;
    this.keyPromise = keyPromise;
    this.headers = {};
    this.base64UrlEncoder = new Utils.Base64Url();
  }

  getHeaders () {
    return this.headers;
  }

  /**
   * Performs decryption.
   *
   * @param cipherText  String
   * @return Promise<String>
   */
  decrypt (cipherText) {
    // Split cipherText in 5 parts
    var parts = cipherText.split('.');
    if (parts.length !== 5) {
      return Promise.reject(Error('decrypt: invalid input'));
    }

    // part 1: header
    this.headers = JSON.parse(this.base64UrlEncoder.decode(parts[0]));
    if (!this.headers.alg) {
      return Promise.reject(Error('decrypt: missing alg'));
    }
    if (!this.headers.enc) {
      return Promise.reject(Error('decrypt: missing enc'));
    }
    this.cryptographer.setKeyEncryptionAlgorithm(this.headers.alg);
    this.cryptographer.setContentEncryptionAlgorithm(this.headers.enc);

    if (this.headers.crit) {
      // We don't support the crit header
      return Promise.reject(Error('decrypt: crit is not supported'));
    }

    var cekPromise;

    if (this.headers.alg === 'dir') {
      // with direct mode, we already have the cek
      cekPromise = Promise.resolve(this.keyPromise);
    } else {
      // part 2: decrypt the CEK
      // In some modes (e.g. RSA-PKCS1v1.5), you must take precautions to prevent
      // chosen-ciphertext attacks as described in RFC 3218, "Preventing
      // the Million Message Attack on Cryptographic Message Syntax". We currently
      // only support RSA-OAEP, so we don't generate a key if unwrapping fails.
      var encryptedCek = this.base64UrlEncoder.decodeArray(parts[1]);
      cekPromise = this.keyPromise.then(function (key) {
        return this.cryptographer.unwrapCek(encryptedCek, key);
      }.bind(this));
    }

    // part 3: decrypt the cipher text
    var plainTextPromise = this.cryptographer.decrypt(
      cekPromise,
      Utils.arrayFromString(parts[0]),
      this.base64UrlEncoder.decodeArray(parts[2]),
      this.base64UrlEncoder.decodeArray(parts[3]),
      this.base64UrlEncoder.decodeArray(parts[4]));

    return plainTextPromise.then(Utils.utf8StringFromArray);
  }
}
