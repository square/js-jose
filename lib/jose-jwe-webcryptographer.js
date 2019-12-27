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

// TODO(eslint): figure out how to properly include Jose or expose crypto object

import * as Utils from './jose-utils';
import { Jose } from './jose-core';

/**
 * The WebCryptographer uses http://www.w3.org/TR/WebCryptoAPI/ to perform
 * various crypto operations. In theory, this should help build the library with
 * different underlying crypto APIs. I'm however unclear if we'll run into code
 * duplication or callback vs Promise based API issues.
 */
export class WebCryptographer {
  constructor () {
    this.setKeyEncryptionAlgorithm('RSA-OAEP');
    this.setContentEncryptionAlgorithm('A256GCM');
    this.setContentSignAlgorithm('RS256');
  }

  /**
   * Overrides the default key encryption algorithm
   * @param alg  string
   */
  setKeyEncryptionAlgorithm (alg) {
    this.keyEncryption = this.getCryptoConfig(alg);
  }

  getKeyEncryptionAlgorithm () {
    return this.keyEncryption.jweName;
  }

  /**
   * Overrides the default content encryption algorithm
   * @param alg  string
   */
  setContentEncryptionAlgorithm (alg) {
    this.content_encryption = this.getCryptoConfig(alg);
  }

  getContentEncryptionAlgorithm () {
    return this.content_encryption.jweName;
  }

  /**
   * Overrides the default content sign algorithm
   * @param alg  string
   */
  setContentSignAlgorithm (alg) {
    this.content_sign = this.getSignConfig(alg);
  }

  getContentSignAlgorithm () {
    return this.content_sign.jwa_name;
  }

  /**
   * Generates an IV.
   * This function mainly exists so that it can be mocked for testing purpose.
   *
   * @return Uint8Array with random bytes
   */
  createIV () {
    var iv = new Uint8Array(new Array(this.content_encryption.iv_bytes));
    return Jose.crypto.getRandomValues(iv);
  }

  /**
   * Creates a random content encryption key.
   * This function mainly exists so that it can be mocked for testing purpose.
   *
   * @return Promise<CryptoKey>
   */
  createCek () {
    var hack = this.getCekWorkaround(this.content_encryption);
    return Jose.crypto.subtle.generateKey(hack.id, true, hack.enc_op);
  }

  wrapCek (cek, key) {
    return Jose.crypto.subtle.wrapKey('raw', cek, key, this.keyEncryption.id);
  }

  unwrapCek (cek, key) {
    var hack = this.getCekWorkaround(this.content_encryption);
    var extractable = (this.content_encryption.specific_cekBytes > 0);
    var keyEncryption = this.keyEncryption.id;

    return Jose.crypto.subtle.unwrapKey('raw', cek, key, keyEncryption, hack.id, extractable, hack.dec_op);
  }

  /**
   * Returns algorithm and operation needed to create a CEK.
   *
   * In some cases, e.g. A128CBC-HS256, the CEK gets split into two keys. The Web
   * Crypto API does not allow us to generate an arbitrary number of bytes and
   * then create a CryptoKey without any associated algorithm. We therefore piggy
   * back on AES-CBS and HMAC which allows the creation of CEKs of size 16, 32, 64
   * and 128 bytes.
   */
  getCekWorkaround (alg) {
    var len = alg.specific_cekBytes;
    if (len) {
      if (len === 16) {
        return { id: { name: 'AES-CBC', length: 128 }, enc_op: ['encrypt'], dec_op: ['decrypt'] };
      } else if (len === 32) {
        return { id: { name: 'AES-CBC', length: 256 }, enc_op: ['encrypt'], dec_op: ['decrypt'] };
      } else if (len === 64) {
        return { id: { name: 'HMAC', hash: { name: 'SHA-256' } }, enc_op: ['sign'], dec_op: ['verify'] };
      } else if (len === 128) {
        return { id: { name: 'HMAC', hash: { name: 'SHA-384' } }, enc_op: ['sign'], dec_op: ['verify'] };
      } else {
        this.assert(false, 'getCekWorkaround: invalid len');
      }
    }
    return { id: alg.id, enc_op: ['encrypt'], dec_op: ['decrypt'] };
  }

  /**
   * Encrypts plainText with cek.
   *
   * @param iv          Uint8Array
   * @param aad         Uint8Array
   * @param cekPromise Promise<CryptoKey>
   * @param plainText  Uint8Array
   * @return Promise<json>
   */
  encrypt (iv, aad, cekPromise, plainText) {
    var config = this.content_encryption;
    if (iv.length !== config.iv_bytes) {
      return Promise.reject(Error('invalid IV length'));
    }
    if (config.auth.aead) {
      var tagBytes = config.auth.tagBytes;

      var enc = {
        name: config.id.name,
        iv: iv,
        additionalData: aad,
        tagLength: tagBytes * 8
      };

      return cekPromise.then(function (cek) {
        return Jose.crypto.subtle.encrypt(enc, cek, plainText).then(function (cipherText) {
          var offset = cipherText.byteLength - tagBytes;
          return {
            cipher: cipherText.slice(0, offset),
            tag: cipherText.slice(offset)
          };
        });
      });
    } else {
      var keys = this.splitKey(config, cekPromise, ['encrypt']);
      var macKeyPromise = keys[0];
      var encKeyPromise = keys[1];

      // Encrypt the plain text
      var cipherTextPromise = encKeyPromise.then(function (encKey) {
        var enc = {
          name: config.id.name,
          iv: iv
        };
        return Jose.crypto.subtle.encrypt(enc, encKey, plainText);
      });

      // compute MAC
      var macPromise = cipherTextPromise.then((cipherText) => {
        return this.truncatedMac(
          config,
          macKeyPromise,
          aad,
          iv,
          cipherText);
      });

      return Promise.all([cipherTextPromise, macPromise]).then(function (all) {
        var cipherText = all[0];
        var mac = all[1];
        return {
          cipher: cipherText,
          tag: mac
        };
      });
    }
  }

  /**
   * Compares two Uint8Arrays in constant time.
   *
   * @return Promise<void>
   */
  compare (config, macKeyPromise, arr1, arr2) {
    this.assert(arr1 instanceof Uint8Array, 'compare: invalid input');
    this.assert(arr2 instanceof Uint8Array, 'compare: invalid input');

    return macKeyPromise.then(function (macKey) {
      var hash1 = Jose.crypto.subtle.sign(config.auth.id, macKey, arr1);
      var hash2 = Jose.crypto.subtle.sign(config.auth.id, macKey, arr2);
      return Promise.all([hash1, hash2]).then(function (all) {
        var hash1 = new Uint8Array(all[0]);
        var hash2 = new Uint8Array(all[1]);
        if (hash1.length !== hash2.length) {
          throw new Error('compare failed');
        }
        for (var i = 0; i < hash1.length; i++) {
          if (hash1[i] !== hash2[i]) {
            throw new Error('compare failed');
          }
        }
        return Promise.resolve(null);
      });
    });
  }

  /**
   * Decrypts cipherText with cek. Validates the tag.
   *
   * @param cekPromise    Promise<CryptoKey>
   * @param aad protected header
   * @param iv IV
   * @param cipherText text to be decrypted
   * @param tag to be verified
   * @return Promise<string>
   */
  decrypt (cekPromise, aad, iv, cipherText, tag) {
    if (iv.length !== this.content_encryption.iv_bytes) {
      return Promise.reject(Error('decryptCiphertext: invalid IV'));
    }

    var config = this.content_encryption;
    if (config.auth.aead) {
      var dec = {
        name: config.id.name,
        iv: iv,
        additionalData: aad,
        tagLength: config.auth.tagBytes * 8
      };

      return cekPromise.then(function (cek) {
        var buf = Utils.arrayBufferConcat(cipherText, tag);
        return Jose.crypto.subtle.decrypt(dec, cek, buf);
      });
    } else {
      var keys = this.splitKey(config, cekPromise, ['decrypt']);
      var macKeyPromise = keys[0];
      var encKeyPromise = keys[1];

      // Validate the MAC
      var macPromise = this.truncatedMac(
        config,
        macKeyPromise,
        aad,
        iv,
        cipherText);

      return Promise.all([encKeyPromise, macPromise]).then((all) => {
        var encKey = all[0];
        var mac = all[1];

        return this.compare(config, macKeyPromise, new Uint8Array(mac), tag).then(() => {
          var dec = {
            name: config.id.name,
            iv: iv
          };
          return Jose.crypto.subtle.decrypt(dec, encKey, cipherText);
        }).catch(() => {
          return Promise.reject(Error('decryptCiphertext: MAC failed.'));
        });
      });
    }
  }

  /**
   * Signs plainText.
   *
   * @param aad         json
   * @param payload     String or json
   * @param keyPromise Promise<CryptoKey>
   * @return Promise<ArrayBuffer>
   */
  sign (aad, payload, keyPromise) {
    var config = this.content_sign;

    if (aad.alg) {
      config = this.getSignConfig(aad.alg);
    }

    // Encrypt the plain text
    return keyPromise.then(function (key) {
      var base64UrlEncoder = new Utils.Base64Url();
      return Jose.crypto.subtle.sign(config.id, key, Utils.arrayFromString(base64UrlEncoder.encode(JSON.stringify(aad)) + '.' + base64UrlEncoder.encodeArray(payload)));
    });
  }

  /**
   * Verify JWS.
   *
   * @param payload     Base64Url encoded payload
   * @param aad         String Base64Url encoded JSON representation of the protected JWS header
   * @param signature   Uint8Array containing the signature
   * @param keyPromise Promise<CryptoKey>
   * @param keyId      value of the kid JoseHeader, it'll be passed as part of the result to the returned promise
   * @return Promise<json>
   */
  verify (aad, payload, signature, keyPromise, keyId) {
    var config = this.content_sign;

    return keyPromise.then(function (key) {
      return Jose.crypto.subtle.verify(config.id, key, signature, Utils.arrayFromString(aad + '.' + payload)).then(function (res) {
        return { kid: keyId, verified: res };
      });
    });
  }

  keyId (rsaKey) {
    return Utils.sha256(rsaKey.n + '+' + rsaKey.d);
  }

  /**
   * Splits a CEK into two pieces: a MAC key and an ENC key.
   *
   * This code is structured around the fact that the crypto API does not provide
   * a way to validate truncated MACs. The MAC key is therefore always imported to
   * sign data.
   *
   * @param config (used for key lengths & algorithms)
   * @param cekPromise Promise<CryptoKey>  CEK key to split
   * @param purpose Array<String> usages of the imported key
   * @return [Promise<mac key>, Promise<enc key>]
   */
  splitKey (config, cekPromise, purpose) {
    // We need to split the CEK key into a MAC and ENC keys
    var cekBytesPromise = cekPromise.then(function (cek) {
      return Jose.crypto.subtle.exportKey('raw', cek);
    });
    var macKeyPromise = cekBytesPromise.then(function (cekBytes) {
      if (cekBytes.byteLength * 8 !== config.id.length + config.auth.key_bytes * 8) {
        return Promise.reject(Error('encryptPlainText: incorrect cek length'));
      }
      var bytes = cekBytes.slice(0, config.auth.key_bytes);
      return Jose.crypto.subtle.importKey('raw', bytes, config.auth.id, false, ['sign']);
    });
    var encKeyPromise = cekBytesPromise.then(function (cekBytes) {
      if (cekBytes.byteLength * 8 !== config.id.length + config.auth.key_bytes * 8) {
        return Promise.reject(Error('encryptPlainText: incorrect cek length'));
      }
      var bytes = cekBytes.slice(config.auth.key_bytes);
      return Jose.crypto.subtle.importKey('raw', bytes, config.id, false, purpose);
    });
    return [macKeyPromise, encKeyPromise];
  }

  /**
   * Converts the Jose web algorithms into data which is
   * useful for the Web Crypto API.
   *
   * length = in bits
   * bytes = in bytes
   */
  getCryptoConfig (alg) {
    switch (alg) {
      // Key encryption
      case 'RSA-OAEP':
        return {
          jweName: 'RSA-OAEP',
          id: { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }
        };
      case 'RSA-OAEP-256':
        return {
          jweName: 'RSA-OAEP-256',
          id: { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
        };
      case 'A128KW':
        return {
          jweName: 'A128KW',
          id: { name: 'AES-KW', length: 128 }
        };
      case 'A256KW':
        return {
          jweName: 'A256KW',
          id: { name: 'AES-KW', length: 256 }
        };
      case 'dir':
        return {
          jweName: 'dir'
        };

      // Content encryption
      case 'A128CBC-HS256':
        return {
          jweName: 'A128CBC-HS256',
          id: { name: 'AES-CBC', length: 128 },
          iv_bytes: 16,
          specific_cekBytes: 32,
          auth: {
            key_bytes: 16,
            id: { name: 'HMAC', hash: { name: 'SHA-256' } },
            truncated_bytes: 16
          }
        };
      case 'A256CBC-HS512':
        return {
          jweName: 'A256CBC-HS512',
          id: { name: 'AES-CBC', length: 256 },
          iv_bytes: 16,
          specific_cekBytes: 64,
          auth: {
            key_bytes: 32,
            id: { name: 'HMAC', hash: { name: 'SHA-512' } },
            truncated_bytes: 32
          }
        };
      case 'A128GCM':
        return {
          jweName: 'A128GCM',
          id: { name: 'AES-GCM', length: 128 },
          iv_bytes: 12,
          auth: {
            aead: true,
            tagBytes: 16
          }
        };
      case 'A256GCM':
        return {
          jweName: 'A256GCM',
          id: { name: 'AES-GCM', length: 256 },
          iv_bytes: 12,
          auth: {
            aead: true,
            tagBytes: 16
          }
        };
      default:
        throw Error('unsupported algorithm: ' + alg);
    }
  }

  /**
   * Computes a truncated MAC.
   *
   * @param config              configuration
   * @param macKeyPromise     Promise<CryptoKey>  mac key
   * @param aad                 Uint8Array
   * @param iv                  Uint8Array
   * @param cipherText         Uint8Array
   * @return Promise<buffer>    truncated MAC
   */
  truncatedMac (config, macKeyPromise, aad, iv, cipherText) {
    return macKeyPromise.then(function (macKey) {
      var al = new Uint8Array(Utils.arrayFromInt32(aad.length * 8));
      var alFull = new Uint8Array(8);
      alFull.set(al, 4);
      var buf = Utils.arrayBufferConcat(aad, iv, cipherText, alFull);
      return Jose.crypto.subtle.sign(config.auth.id, macKey, buf).then(function (bytes) {
        return bytes.slice(0, config.auth.truncated_bytes);
      });
    });
  }

  /**
   * Converts the Jose web algorithms into data which is
   * useful for the Web Crypto API.
   */
  getSignConfig (alg) {
    switch (alg) {
      case 'RS256':
        return {
          jwa_name: 'RS256',
          id: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }
        };
      case 'RS384':
        return {
          jwa_name: 'RS384',
          id: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } }
        };
      case 'RS512':
        return {
          jwa_name: 'RS512',
          id: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } }
        };
      case 'PS256':
        return {
          jwa_name: 'PS256',
          id: { name: 'RSA-PSS', hash: { name: 'SHA-256' }, saltLength: 20 }
        };
      case 'PS384':
        return {
          jwa_name: 'PS384',
          id: { name: 'RSA-PSS', hash: { name: 'SHA-384' }, saltLength: 20 }
        };
      case 'PS512':
        return {
          jwa_name: 'PS512',
          id: { name: 'RSA-PSS', hash: { name: 'SHA-512' }, saltLength: 20 }
        };
      case 'HS256':
        return {
          jwa_name: 'HS256',
          id: { name: 'HMAC', hash: { name: 'SHA-256' } }
        };
      case 'HS384':
        return {
          jwa_name: 'HS384',
          id: { name: 'HMAC', hash: { name: 'SHA-384' } }
        };
      case 'HS512':
        return {
          jwa_name: 'HS512',
          id: { name: 'HMAC', hash: { name: 'SHA-512' } }
        };
      case 'ES256':
        return {
          jwa_name: 'ES256',
          id: { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } }
        };
      case 'ES384':
        return {
          jwa_name: 'ES384',
          id: { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } }
        };
      case 'ES512':
        return {
          jwa_name: 'ES512',
          id: { name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-512' } }
        };
      default:
        throw Error('unsupported algorithm: ' + alg);
    }
  }

  /**
   * Derives key usage from algorithm's name
   *
   * @param alg String algorithm name
   * @returns {*}
   */
  getKeyUsageByAlg (alg) {
    switch (alg) {
      // signature
      case 'RS256':
      case 'RS384':
      case 'RS512':
      case 'PS256':
      case 'PS384':
      case 'PS512':
      case 'HS256':
      case 'HS384':
      case 'HS512':
      case 'ES256':
      case 'ES384':
      case 'ES512':
      case 'ES256K':
        return {
          publicKey: 'verify',
          privateKey: 'sign'
        };
      // key encryption
      case 'RSA-OAEP':
      case 'RSA-OAEP-256':
      case 'A128KW':
      case 'A256KW':
        return {
          publicKey: 'wrapKey',
          privateKey: 'unwrapKey'
        };
      default:
        throw Error('unsupported algorithm: ' + alg);
    }
  }

  /**
 * Feel free to override this function.
 */
  assert (expr, msg) {
    if (!expr) {
      throw new Error(msg);
    }
  }
}
