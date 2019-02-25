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

import * as Utils from './jose-utils';
import * as Operations from './jose-operations';

/**
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param key_promise    Promise<CryptoKey>, either RSA or shared key
 */
export class Decrypter { 
  constructor(cryptographer, key_promise) {
    this.cryptographer = cryptographer;
    this.key_promise = key_promise;
    this.headers = {};
    this.base64UrlEncoder = new Operations.Base64Url();
  }

  getHeaders() {
    return this.headers;
  }

  /**
   * Performs decryption.
   *
   * @param cipher_text  String
   * @return Promise<String>
   */
  decrypt(cipher_text) {
    // Split cipher_text in 5 parts
    var parts = cipher_text.split(".");
    if (parts.length != 5) {
      return Promise.reject(Error("decrypt: invalid input"));
    }

    // part 1: header
    this.headers = JSON.parse(this.base64UrlEncoder.decode(parts[0]));
    if (!this.headers.alg) {
      return Promise.reject(Error("decrypt: missing alg"));
    }
    if (!this.headers.enc) {
      return Promise.reject(Error("decrypt: missing enc"));
    }
    this.cryptographer.setKeyEncryptionAlgorithm(this.headers.alg);
    this.cryptographer.setContentEncryptionAlgorithm(this.headers.enc);

    if (this.headers.crit) {
      // We don't support the crit header
      return Promise.reject(Error("decrypt: crit is not supported"));
    }

    var cek_promise;

    if (this.headers.alg == "dir") {
      // with direct mode, we already have the cek
      cek_promise = Promise.resolve(this.key_promise);
    } else {
      // part 2: decrypt the CEK
      // In some modes (e.g. RSA-PKCS1v1.5), you must take precautions to prevent
      // chosen-ciphertext attacks as described in RFC 3218, "Preventing
      // the Million Message Attack on Cryptographic Message Syntax". We currently
      // only support RSA-OAEP, so we don't generate a key if unwrapping fails.
      var encrypted_cek = this.base64UrlEncoder.decodeArray(parts[1]);
      cek_promise = this.key_promise.then(function (key) {
        return this.cryptographer.unwrapCek(encrypted_cek, key);
      }.bind(this));
    }

    // part 3: decrypt the cipher text
    var plain_text_promise = this.cryptographer.decrypt(
      cek_promise,
      Operations.arrayFromString(parts[0]),
      this.base64UrlEncoder.decodeArray(parts[2]),
      this.base64UrlEncoder.decodeArray(parts[3]),
      this.base64UrlEncoder.decodeArray(parts[4]));

    return plain_text_promise.then(Operations.utf8StringFromArray);
  }
}