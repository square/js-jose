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
 * @param message        a JWS message
 * @param rsa_key        public RSA key in json format. Parameters can be base64
 *                       encoded, strings or number (for 'e').
 */
JoseJWS.Verifier = function(message, rsa_key) {
  this.cryptographer = new JoseJWE.WebCryptographer();
  var jwt,
    aad,
    header,
    payload,
    signature,
    protectedHeader;


  if (Utils.isString(message)) {
    jwt = message.split('.');
    if (jwt.length != 3) {
      throw new Error("wrong JWS compact serialization format");
    }

    aad = jwt[0];
    payload = jwt[1];
    signature = jwt[2];
  } else if (typeof message == "object") {
    aad = message.protected;
    header = message.header;
    payload = message.payload;
    signature = message.signature;
  } else {
    throw new Error("data format not supported");
  }

  this.signature = Utils.arrayFromString(Utils.Base64Url.decode(signature));

  this.aad = aad;
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

  if (protectedHeader && protectedHeader.typ && protectedHeader.typ != "JWT") {
    throw new Error("typ '" + protectedHeader.typ + "' not supported");
  }

  this.payload = payload;

  this.key_promise = JoseJWE.Utils.importRsaPublicKey(rsa_key, protectedHeader.alg, "verify");

  cryptographer.setContentSignAlgorithm(protectedHeader.alg);
};

/**
 * Verify a JWS signature
 *
 * @returns Promise<json>
 */
JoseJWS.Verifier.prototype.verify = function() {

  return this.cryptographer.verify(this.aad, this.payload, this.signature, this.key_promise);
};