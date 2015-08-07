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
 *                       encoded, strings or number (for 'e').
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */
JoseJWS.Verifier = function (cryptographer, message, rsa_key) {
  "use strict";

  var that = this,
    alg,
    jwt,
    aad,
    header,
    payload,
    signature,
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
    }
  } else if (typeof message != "object") {
    throw new Error("data format not supported");
  }

  aad = message.protected;
  header = message.header;
  payload = message.payload;
  signature = message.signature;

  that.signature = Utils.arrayFromString(Utils.Base64Url.decode(signature));

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

  that.payload = payload;

  that.key_promise = JoseJWE.Utils.importRsaPublicKey(rsa_key, alg, "verify");
};

/**
 * Verifies a JWS signature
 *
 * @returns Promise<bool>
 */
JoseJWS.Verifier.prototype.verify = function () {
  "use strict";
  var that = this;

  return that.cryptographer.verify(that.aad, that.payload, that.signature, that.key_promise);
};