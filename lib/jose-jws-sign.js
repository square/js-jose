/*-
 * Copyright 2014 Patrizio Bruno <patrizio@desertconsulting.net>
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
 * @param rsa_key        private RSA key in json format. Parameters can be base64
 *                       encoded, strings or number (for 'e').
 */
JoseJWS.Signer = function(cryptographer, rsa_key) {
  this.cryptographer = cryptographer;
  this.key_promise = JoseJWE.Utils.importRsaPrivateKey(rsa_key, cryptographer.getContentSignAlgorithm(), "sign");

  this.headers = {};
};

JoseJWS.Signer.prototype.getHeaders = function() {
  return this.headers;
};

/**
 * Performs decryption.
 *
 * @param payload json or String to be signed
 * @param aad protected header (JS object)
 * @param header unprotected header (JS object)
 * @return Promise<String>
 */
JoseJWS.Signer.prototype.sign = function(payload, aad, header) {

  if (!aad) {
    aad = {};
  }

  if (!aad.alg) {
    aad.alg = cryptographer.getContentSignAlgorithm();
    aad.typ = "JWT";
  }

  if (Utils.isString(payload)) {
    payload = Utils.arrayFromString(payload);
  } else {
    try {
      payload = Utils.arrayish(payload);
    } catch (e) {
      if (payload instanceof Object) {
        payload = Utils.arrayFromString(JSON.stringify(payload));
      }
    }
  }

  return this.cryptographer.sign(aad, payload, this.key_promise).then(function(signature) {
    return new JWS(aad, header, payload, signature);
  });
};

/**
 * Initialize a JWS object.
 *
 * @param protectedHeader protected header (JS object)
 * @param payload Uint8Array payload to be signed
 * @param signature ArrayBuffer signature of the payload
 * @param header unprotected header (JS object)
 *
 * @constructor
 */
var JWS = function(protectedHeader, header, payload, signature) {
  this.header = header;
  this.payload = Utils.Base64Url.encodeArray(payload);
  this.signature = Utils.Base64Url.encodeArray(signature);
  this.protected = Utils.Base64Url.encode(JSON.stringify(protectedHeader));
};

/**
 * Serialize a JWS object using the JSON serialization format
 *
 * @returns {Object} a copy of this
 */
JWS.prototype.JsonSerialize = function() {
  var that = this;
  return Object.create(that);
};

/**
 * Serialize a JWS object using the Compact Serialization Format
 *
 * @returns {string} BASE64URL(UTF8(PROTECTED HEADER)).BASE64URL(PAYLOAD).BASE64URL(SIGNATURE)
 */
JWS.prototype.CompactSerialize = function() {
  return this.protected + '.' + this.payload + '.' + this.signature;
};
