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
import * as Operations from './jose-operations';

/**
 * Handles encryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent).
 * @param key_promise    Promise<CryptoKey>, either RSA or shared key
 */
export class Encrypter {
  constructor(cryptographer, key_promise) {
    this.cryptographer = cryptographer;
    this.key_promise = key_promise;
    this.userHeaders = {};
  }

  /**
   * Adds a key/value pair which will be included in the header.
   *
   * The data lives in plaintext (an attacker can read the header) but is tamper
   * proof (an attacker cannot modify the header).
   *
   * Note: some headers have semantic implications. E.g. if you set the "zip"
   * header, you are responsible for properly compressing plain_text before
   * calling encrypt().
   *
   * @param k  String
   * @param v  String
   */
  addHeader(k, v) {
    this.userHeaders[k] = v;
  }

  /**
   * Performs encryption.
   *
   * @param plain_text  utf-8 string
   * @return Promise<String>
   */
  encrypt(plain_text) {
    /**
     * Encrypts plain_text with CEK.
     *
     * @param cek_promise  Promise<CryptoKey>
     * @param plain_text   string
     * @return Promise<json>
     */
    var encryptPlainText = function(cek_promise, plain_text) {
      // Create header
      var headers = {};
      for (var i in this.userHeaders) {
        headers[i] = this.userHeaders[i];
      }
      headers.alg = this.cryptographer.getKeyEncryptionAlgorithm();
      headers.enc = this.cryptographer.getContentEncryptionAlgorithm();
      var jwe_protected_header = new Operations.Base64Url().encode(JSON.stringify(headers));

      // Create the IV
      var iv = this.cryptographer.createIV();

      // Create the AAD
      var aad = Operations.arrayFromString(jwe_protected_header);
      plain_text = Operations.arrayFromUtf8String(plain_text);

      return this.cryptographer.encrypt(iv, aad, cek_promise, plain_text).then(function(r) {
        r.header = jwe_protected_header;
        r.iv = iv;
        return r;
      });
    };

    var cek_promise, encrypted_cek;

    if (this.cryptographer.getKeyEncryptionAlgorithm() == "dir") {
      // with direct encryption, this.key_promise provides the cek
      // and encrypted_cek is empty
      cek_promise = Promise.resolve(this.key_promise);
      encrypted_cek = [];
    } else {
      // Create a CEK key
      cek_promise = this.cryptographer.createCek();

      // Key & Cek allows us to create the encrypted_cek
      encrypted_cek = Promise.all([this.key_promise, cek_promise]).then(function (all) {
        var key = all[0];
        var cek = all[1];
        return this.cryptographer.wrapCek(cek, key);
      }.bind(this));
    }

    // Cek allows us to encrypy the plain text
    var enc_promise = encryptPlainText.bind(this, cek_promise, plain_text)();

    // Once we have all the promises, we can base64 encode all the pieces.
    return Promise.all([encrypted_cek, enc_promise]).then(function(all) {
      var encrypted_cek = all[0];
      var data = all[1];
      var base64UrlEncoder = new Operations.Base64Url();
      return data.header + "." +
        base64UrlEncoder.encodeArray(encrypted_cek) + "." +
        base64UrlEncoder.encodeArray(data.iv) + "." +
        base64UrlEncoder.encodeArray(data.cipher) + "." +
        base64UrlEncoder.encodeArray(data.tag);
    });
  }
}
