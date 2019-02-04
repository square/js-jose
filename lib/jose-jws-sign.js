/*-
 * Copyright 2015 Peculiar Ventures
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
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */
export class Signer {
  constructor(cryptographer) {
    this.cryptographer = cryptographer;

    this.key_promises = {};
    this.waiting_kid = 0;
    this.headers = {};
    this.signer_aads = {};
    this.signer_headers = {};
  }

  /**
   * Adds a signer to JoseJWS instance. It'll be the on of the signers of the resulting JWS.
   *
   * @param rsa_key        private RSA key in json format, Parameters can be base64
   *                       encoded, strings or number (for 'e'). Or CryptoKey
   * @param key_id         a string identifying the rsa_key. OPTIONAL
   * @param aad            Object protected header
   * @param header         Object unprotected header
   */
  addSigner(rsa_key, key_id, aad, header) {
    var that = this;
    var key_promise;
    if (Utils.isCryptoKey(rsa_key)) {
      key_promise = new Promise(function(resolve) {
        resolve(rsa_key);
      });
    } else {
      var alg;
      if (aad && aad.alg) {
        alg = aad.alg;
      } else {
        alg = that.cryptographer.getContentSignAlgorithm();
      }
      key_promise = Utils.importRsaPrivateKey(rsa_key, alg, "sign");
    }

    var kid_promise;
    if (key_id) {
      kid_promise = new Promise(function(resolve) {
        resolve(key_id);
      });
    } else if (Utils.isCryptoKey(rsa_key)) {
      throw new Error("key_id is a mandatory argument when the key is a CryptoKey");
    } else {
      kid_promise = Jose.WebCryptographer.keyId(rsa_key);
    }

    that.waiting_kid++;

    return kid_promise.then(function(kid) {
      that.key_promises[kid] = key_promise;
      that.waiting_kid--;
      if (aad) {
        that.signer_aads[kid] = aad;
      }
      if (header) {
        that.signer_headers[kid] = header;
      }
      return kid;
    });
  }

  /**
   * Adds a signature to a JWS object
   * @param jws JWS Object to be signed or its representation
   * @param aad     Object protected header
   * @param header  Object unprotected header
   * @return Promise<String>
   */
  addSignature(jws, aad, header) {
    if (Utils.isString(jws)) {
      jws = JSON.parse(jws);
    }

    if (jws.payload && Utils.isString(jws.payload) &&
      jws.protected && Utils.isString(jws.protected) &&
      jws.header && jws.header instanceof Object &&
      jws.signature && Utils.isString(jws.signature)) {
      return this.sign(JWS.fromObject(jws), aad, header);
    } else {
      throw new Error("JWS is not a valid JWS object");
    }
  }

  /**
   * Computes signature.
   *
   * @param payload JWS Object or utf-8 string to be signed
   * @param aad     Object protected header
   * @param header  Object unprotected header
   * @return Promise<JWS>
   */
  sign(payload, aad, header) {

    var that = this;
    var kids = [];

    if (Object.keys(that.key_promises).length === 0) {
      throw new Error("No signers defined. At least one is required to sign the JWS.");
    }

    if (that.waiting_kid) {
      throw new Error("still generating key IDs");
    }

    function sign (message, protectedHeader, unprotectedHeader, rsa_key_promise, kid) {
      var toBeSigned;

      if (!protectedHeader) {
        protectedHeader = {};
      }

      if (!protectedHeader.alg) {
        protectedHeader.alg = that.cryptographer.getContentSignAlgorithm();
        protectedHeader.typ = "JWT";
      }

      if (!protectedHeader.kid) {
        protectedHeader.kid = kid;
      }

      if (Utils.isString(message)) {
        toBeSigned = Utils.arrayFromUtf8String(message);
      } else {
        try {
          toBeSigned = Utils.arrayish(message);
        } catch (e) {
          if (message instanceof JWS) {
            toBeSigned = Utils.arrayFromString(new Utils.Base64Url().decode(message.payload));
          } else if (message instanceof Object) {
            toBeSigned = Utils.arrayFromUtf8String(JSON.stringify(message));
          } else {
            throw new Error("cannot sign this message");
          }
        }
      }

      return that.cryptographer.sign(protectedHeader, toBeSigned, rsa_key_promise).then(function(signature) {
        var jws = new JWS(protectedHeader, unprotectedHeader, toBeSigned, signature);
        if (message instanceof JWS) {
          delete jws.payload;
          if (!message.signatures) {
            message.signatures = [jws];
          } else {
            message.signatures.push(jws);
          }
          return message;
        }
        return jws;
      });
    }

    function doSign (pl, ph, uh, kps, kids) {
      if (kids.length) {
        var k_id = kids.shift();
        var rv = sign(pl, that.signer_aads[k_id] || ph, that.signer_headers[k_id] || uh, kps[k_id], k_id);
        if (kids.length) {
          rv = rv.then(function(jws) {
            return doSign(jws, null, null, kps, kids);
          });
        }
        return rv;
      }
    }

    for(var kid in that.key_promises) {
      if (that.key_promises.hasOwnProperty(kid)) {
        kids.push(kid);
      }
    }
    return doSign(payload, aad, header, that.key_promises, kids);
  }
}

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
export class JWS { 
  constructor(protectedHeader, header, payload, signature) {
    this.header = header;
    var base64UrlEncoder = new Utils.Base64Url();
    this.payload = base64UrlEncoder.encodeArray(payload);
    if (signature) {
      this.signature = base64UrlEncoder.encodeArray(signature);
    }
    this.protected = base64UrlEncoder.encode(JSON.stringify(protectedHeader));
  }

  fromObject(obj) {
    var rv = new JWS(obj.protected, obj.header, obj.payload, null);
    rv.signature = obj.signature;
    rv.signatures = obj.signatures;
    return rv;
  }

  /**
   * Serialize a JWS object using the JSON serialization format
   *
   * @returns {Object} a copy of this
   */
  JsonSerialize() {
    return JSON.stringify(this);
  }

  /**
   * Serialize a JWS object using the Compact Serialization Format
   *
   * @returns {string} BASE64URL(UTF8(PROTECTED HEADER)).BASE64URL(PAYLOAD).BASE64URL(SIGNATURE)
   */
  CompactSerialize() {
    return this.protected + '.' + this.payload + '.' + this.signature;
  }
}