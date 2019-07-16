/* -
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
 * Handles signature verification.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param message        a JWS message
 * @param keyfinder (optional) a function returning a Promise<CryptoKey> given
 *                             a key id
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */
export class Verifier {
  constructor (cryptographer, message, keyfinder) {
    var that = this;
    var alg;
    var jwt;
    var aad;
    var header;
    var payload;
    var signatures;
    var protectedHeader;
    var jwtRx = /^([0-9a-z_-]+)\.([0-9a-z_-]+)\.([0-9a-z_-]+)$/i;

    that.cryptographer = cryptographer;

    alg = cryptographer.getContentSignAlgorithm();

    if (Utils.isString(message)) {
      if ((jwt = jwtRx.exec(message))) {
        if (jwt.length !== 4) {
          throw new Error('wrong JWS compact serialization format');
        }

        message = {
          protected: jwt[1],
          payload: jwt[2],
          signature: jwt[3]
        };
      } else {
        message = JSON.parse(message);
      }
    } else if (typeof message !== 'object') {
      throw new Error('data format not supported');
    }

    aad = message.protected;
    header = message.header;
    payload = message.payload;
    signatures = message.signatures instanceof Array ? message.signatures.slice(0) : [];

    signatures.forEach(function (sign) {
      sign.aad = sign.protected;
      sign.protected = JSON.parse(new Utils.Base64Url().decode(sign.protected));
    });

    that.aad = aad;
    protectedHeader = new Utils.Base64Url().decode(aad);
    try {
      protectedHeader = JSON.parse(protectedHeader);
    } catch (e) {
    }

    if (!protectedHeader && !header) {
      throw new Error('at least one header is required');
    }

    if (!protectedHeader.alg) {
      throw new Error("'alg' is a mandatory header");
    }

    if (protectedHeader.alg !== alg) {
      throw new Error("the alg header '" + protectedHeader.alg + "' doesn't match the requested algorithm '" + alg + "'");
    }

    if (protectedHeader && protectedHeader.typ && protectedHeader.typ !== 'JWT') {
      throw new Error("typ '" + protectedHeader.typ + "' not supported");
    }

    if (message.signature) {
      signatures.unshift({
        aad: aad,
        protected: protectedHeader,
        header: header,
        signature: message.signature
      });
    }

    that.signatures = [];
    for (var i = 0; i < signatures.length; i++) {
      that.signatures[i] = JSON.parse(JSON.stringify(signatures[i]));
      that.signatures[i].signature = Utils.arrayFromString(new Utils.Base64Url().decode(signatures[i].signature));
    }

    that.payload = payload;

    that.keyPromises = {};
    that.waiting_kid = 0;

    if (keyfinder) {
      that.keyfinder = keyfinder;
    }
  }

  /**
   * Add supported recipients to verify multiple signatures
   *
   * @param key            public key in json format. Parameters can be base64
   *                       encoded, strings or number (for 'e'), or CryptoKey.
   * @param keyId         a string identifying the key. OPTIONAL
   * @param alg            String signature algorithm. OPTIONAL
   * @returns Promise<string> a Promise of a key id
   */
  addRecipient (key, keyId, alg) {
    var that = this;
    var kidPromise;
    var keyPromise;
    if (Utils.isCryptoKey(key)) {
      keyPromise = new Promise(function (resolve) { resolve(key); });
    } else {
      keyPromise = Utils.importPublicKey(key, alg || that.cryptographer.getContentSignAlgorithm(), 'verify');
    }

    if (keyId) {
      kidPromise = new Promise(function (resolve) {
        resolve(keyId);
      });
    } else if (Utils.isCryptoKey(key)) {
      throw new Error('keyId is a mandatory argument when the key is a CryptoKey');
    } else {
      console.log("it's unsafe to omit a keyId");
      kidPromise = this.cryptographer.keyId(key);
    }

    that.waiting_kid++;

    return kidPromise.then(function (kid) {
      that.keyPromises[kid] = keyPromise;
      that.waiting_kid--;
      return kid;
    });
  }

  /**
   * Verifies a JWS signature
   *
   * @returns Promise<Array> a Promise of an array of objects { kid: string, verified: bool, payload?: string }
   *
   * payload is only populated and usable if verified is true
   */
  verify () {
    var that = this;
    var signatures = that.signatures;
    var keyPromises = that.keyPromises;
    var keyfinder = that.keyfinder;
    var promises = [];
    var check = !!keyfinder || Object.keys(that.keyPromises).length > 0;

    if (!check) {
      throw new Error('No recipients defined. At least one is required to verify the JWS.');
    }

    if (that.waiting_kid) {
      throw new Error('still generating key IDs');
    }

    signatures.forEach(function (sig) {
      var kid = sig.protected.kid;
      if (keyfinder) {
        keyPromises[kid] = keyfinder(kid);
      }
      promises.push(that.cryptographer.verify(sig.aad, that.payload, sig.signature, keyPromises[kid], kid)
        .then(function (vr) {
          if (vr.verified) {
            vr.payload = new Utils.Base64Url().decode(that.payload);
          }
          return vr;
        }));
    });
    return Promise.all(promises);
  }
}
