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

/**
 * Handles signature verification.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param message        a JWS message
 * @param rsa_key        public RSA key in json format. Parameters can be base64
 *                       encoded, strings or number (for 'e'). OPTIONAL
 * @param key_id         a string identifying the rsa_key. OPTIONAL
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */
JoseJWS.Verifier = function(cryptographer, message, rsa_key, key_id) {
  "use strict";

  var that = this,
    alg,
    jwt,
    aad,
    header,
    payload,
    signatures,
    protectedHeader,
    jwtRx = /^([a-z_\\-])\\.([a-z_\\-])\\.([a-z_\\-])$/i;

  that.cryptographer = cryptographer;

  alg = cryptographer.getContentSignAlgorithm();

  that.cryptographer = new Jose.WebCryptographer();

  if (Utils.isString(message)) {
    if ((jwt = jwtRx.exec(message))) {
      if (jwt.length != 4) {
        throw new Error("wrong JWS compact serialization format");
      }

      message = {
        protected: jwt[1],
        payload: jwt[2],
        signature: jwt[3]
      };
    } else {
      message = JSON.parse(message);
    }
  } else if (typeof message != "object") {
    throw new Error("data format not supported");
  }

  aad = message.protected;
  header = message.header;
  payload = message.payload;
  signatures = message.signatures || [];

  that.aad = aad;
  protectedHeader = Utils.Base64Url.decode(aad);
  try {
    protectedHeader = JSON.parse(protectedHeader);
  } catch (e) {
  }

  if (!protectedHeader && !header) {
    throw new Error("at least one header is required");
  }

  if (!protectedHeader.alg) {
    throw new Error("'alg' is a mandatory header");
  }

  if (protectedHeader.alg != alg) {
    throw new Error("the alg header '" + protectedHeader.alg + "' doesn't match the requested algorithm '" + alg + "'");
  }

  if (protectedHeader && protectedHeader.typ && protectedHeader.typ != "JWT") {
    throw new Error("typ '" + protectedHeader.typ + "' not supported");
  }

  if (message.signature) {
    signatures.unshift({kid: protectedHeader.kid, signature: message.signature});
  }

  that.signatures = {};
  for (var i = 0; i < signatures.length; i++) {
    that.signatures[signatures[i].kid] = Utils.arrayFromString(Utils.Base64Url.decode(signatures[i].signature));
  }

  that.payload = payload;

  if (rsa_key) {
    if (!key_id) {
      key_id = Jose.WebCryptographer.keyId(rsa_key);
    } else {
      console.warn("it's not safe to not pass a key_id");
    }

    that.key_promises = {};
    that.key_promises[key_id] = Jose.Utils.importRsaPublicKey(rsa_key, alg, "verify");
  }
};

/**
 * Add supported recipients to verify multiple signatures
 *
 * @param rsa_key        public RSA key in json format. Parameters can be base64
 *                       encoded, strings or number (for 'e').
 * @param key_id         a string identifying the rsa_key. OPTIONAL
 */
JoseJWS.Verifier.prototype.addRecipient = function(rsa_key, key_id) {

  var that = this,
    promise = Jose.Utils.importRsaPublicKey(rsa_key, alg, "verify");

  if (!key_id) {
    key_id = Jose.WebCryptographer.keyId(rsa_key);
  } else {
    console.warn("it's not safe to not pass a key_id");
  }

  if (!(that.recipients instanceof Object)) {
    that.key_promises = {};
  }

  that.key_promises[key_id] = promise;
};

/**
 * Verifies a JWS signature
 *
 * @returns Promise<bool>
 */
JoseJWS.Verifier.prototype.verify = function() {
  "use strict";
  var that = this,
    promises = [];

  if (that.key_promises instanceof  Object) {
    for (var kid in that.key_promises) {
      var k_id;
      if(that.key_promises.hasOwnProperty(kid)) {
        promises.push(that.cryptographer.verify(that.aad, that.payload, that.signatures[kid], that.key_promises[kid], kid).then(function(res) {
          return {kid: k_id, verified: res};
        }));
      }
    }
    return Promise.all(promises);
  } else {
    throw new Error("at least a recipient is needed to verify the JWS signature")
  }
};