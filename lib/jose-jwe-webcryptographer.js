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

/**
 * The WebCryptographer uses http://www.w3.org/TR/WebCryptoAPI/ to perform
 * various crypto operations. In theory, this should help build the library with
 * different underlying crypto APIs. I'm however unclear if we'll run into code
 * duplication or callback vs Promise based API issues.
 */
export class WebCryptographer {
  constructor() {
    this.setKeyEncryptionAlgorithm("RSA-OAEP");
    this.setContentEncryptionAlgorithm("A256GCM");
    this.setContentSignAlgorithm("RS256");
  }

  /**
   * Overrides the default key encryption algorithm
   * @param alg  string
   */
  setKeyEncryptionAlgorithm(alg) {
    this.key_encryption = this.getCryptoConfig(alg);
  }

  getKeyEncryptionAlgorithm() {
    return this.key_encryption.jwe_name;
  }

  /**
   * Overrides the default content encryption algorithm
   * @param alg  string
   */
   setContentEncryptionAlgorithm(alg) {
    this.content_encryption = this.getCryptoConfig(alg);
  }

  getContentEncryptionAlgorithm() {
    return this.content_encryption.jwe_name;
  }

  /**
   * Overrides the default content sign algorithm
   * @param alg  string
   */
   setContentSignAlgorithm(alg) {
    this.content_sign = this.getSignConfig(alg);
  }

  getContentSignAlgorithm() {
    return this.content_sign.jwa_name;
  }

  /**
   * Generates an IV.
   * This function mainly exists so that it can be mocked for testing purpose.
   *
   * @return Uint8Array with random bytes
   */
  createIV() {
    var iv = new Uint8Array(new Array(this.content_encryption.iv_bytes));
    return Jose.crypto.getRandomValues(iv);
  }

  /**
   * Creates a random content encryption key.
   * This function mainly exists so that it can be mocked for testing purpose.
   *
   * @return Promise<CryptoKey>
   */
  createCek() {
    var hack = this.getCekWorkaround(this.content_encryption);
    return Jose.crypto.subtle.generateKey(hack.id, true, hack.enc_op);
  }

  wrapCek(cek, key) {
    return Jose.crypto.subtle.wrapKey("raw", cek, key, this.key_encryption.id);
  }

  unwrapCek(cek, key) {
    var hack = this.getCekWorkaround(this.content_encryption);
    var extractable = (this.content_encryption.specific_cek_bytes > 0);
    var key_encryption = this.key_encryption.id;

    return Jose.crypto.subtle.unwrapKey("raw", cek, key, key_encryption, hack.id, extractable, hack.dec_op);
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
  getCekWorkaround(alg) {
    var len = alg.specific_cek_bytes;
    if (len) {
      if (len == 16) {
        return {id: {name: "AES-CBC", length: 128}, enc_op: ["encrypt"], dec_op: ["decrypt"]};
      } else if (len == 32) {
        return {id: {name: "AES-CBC", length: 256}, enc_op: ["encrypt"], dec_op: ["decrypt"]};
      } else if (len == 64) {
        return {id: {name: "HMAC", hash: {name: "SHA-256"}}, enc_op: ["sign"], dec_op: ["verify"]};
      } else if (len == 128) {
        return {id: {name: "HMAC", hash: {name: "SHA-384"}}, enc_op: ["sign"], dec_op: ["verify"]};
      } else {
        this.assert(false, "getCekWorkaround: invalid len");
      }
    }
    return {id: alg.id, enc_op: ["encrypt"], dec_op: ["decrypt"]};
  }

  /**
   * Encrypts plain_text with cek.
   *
   * @param iv          Uint8Array
   * @param aad         Uint8Array
   * @param cek_promise Promise<CryptoKey>
   * @param plain_text  Uint8Array
   * @return Promise<json>
   */
  encrypt(iv, aad, cek_promise, plain_text) {
    var config = this.content_encryption;
    if (iv.length != config.iv_bytes) {
      return Promise.reject(Error("invalid IV length"));
    }
    if (config.auth.aead) {
      var tag_bytes = config.auth.tag_bytes;

      var enc = {
        name: config.id.name,
        iv: iv,
        additionalData: aad,
        tagLength: tag_bytes * 8
      };

      return cek_promise.then(function(cek) {
        return Jose.crypto.subtle.encrypt(enc, cek, plain_text).then(function(cipher_text) {
          var offset = cipher_text.byteLength - tag_bytes;
          return {
            cipher: cipher_text.slice(0, offset),
            tag: cipher_text.slice(offset)
          };
        });
      });
    } else {
      var keys = this.splitKey(config, cek_promise, ["encrypt"]);
      var mac_key_promise = keys[0];
      var enc_key_promise = keys[1];

      // Encrypt the plain text
      var cipher_text_promise = enc_key_promise.then(function(enc_key) {
        var enc = {
          name: config.id.name,
          iv: iv
        };
        return Jose.crypto.subtle.encrypt(enc, enc_key, plain_text);
      });

      // compute MAC
      var mac_promise = cipher_text_promise.then((cipher_text) => {
        return this.truncatedMac(
          config,
          mac_key_promise,
          aad,
          iv,
          cipher_text);
      });

      return Promise.all([cipher_text_promise, mac_promise]).then(function(all) {
        var cipher_text = all[0];
        var mac = all[1];
        return {
          cipher: cipher_text,
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
  compare(config, mac_key_promise, arr1, arr2){
    this.assert(arr1 instanceof Uint8Array, "compare: invalid input");
    this.assert(arr2 instanceof Uint8Array, "compare: invalid input");

    return mac_key_promise.then(function(mac_key) {
      var hash1 = Jose.crypto.subtle.sign(config.auth.id, mac_key, arr1);
      var hash2 = Jose.crypto.subtle.sign(config.auth.id, mac_key, arr2);
      return Promise.all([hash1, hash2]).then(function(all) {
        var hash1 = new Uint8Array(all[0]);
        var hash2 = new Uint8Array(all[1]);
        if (hash1.length != hash2.length) {
          throw new Error("compare failed");
        }
        for (var i = 0; i < hash1.length; i++) {
          if (hash1[i] != hash2[i]) {
            throw new Error("compare failed");
          }
        }
        return Promise.resolve(null);
      });
    });
  }

  /**
   * Decrypts cipher_text with cek. Validates the tag.
   *
   * @param cek_promise    Promise<CryptoKey>
   * @param aad protected header
   * @param iv IV
   * @param cipher_text text to be decrypted
   * @param tag to be verified
   * @return Promise<string>
   */
  decrypt(cek_promise, aad, iv, cipher_text, tag) {

    if (iv.length != this.content_encryption.iv_bytes) {
      return Promise.reject(Error("decryptCiphertext: invalid IV"));
    }

    var config = this.content_encryption;
    if (config.auth.aead) {
      var dec = {
        name: config.id.name,
        iv: iv,
        additionalData: aad,
        tagLength: config.auth.tag_bytes * 8
      };

      return cek_promise.then(function(cek) {
        var buf = Utils.arrayBufferConcat(cipher_text, tag);
        return Jose.crypto.subtle.decrypt(dec, cek, buf);
      });
    } else {
      var keys = this.splitKey(config, cek_promise, ["decrypt"]);
      var mac_key_promise = keys[0];
      var enc_key_promise = keys[1];

      // Validate the MAC
      var mac_promise = this.truncatedMac(
        config,
        mac_key_promise,
        aad,
        iv,
        cipher_text);

      return Promise.all([enc_key_promise, mac_promise]).then((all) => {
        var enc_key = all[0];
        var mac = all[1];

        return this.compare(config, mac_key_promise, new Uint8Array(mac), tag).then(() => {
          var dec = {
            name: config.id.name,
            iv: iv
          };
          return Jose.crypto.subtle.decrypt(dec, enc_key, cipher_text);
        }).catch((err) => {
          return Promise.reject(Error("decryptCiphertext: MAC failed."));
        });
      });
    }
  }

  /**
   * Signs plain_text.
   *
   * @param aad         json
   * @param payload     String or json
   * @param key_promise Promise<CryptoKey>
   * @return Promise<ArrayBuffer>
   */
  sign(aad, payload, key_promise) {
    var config = this.content_sign;

    if (aad.alg) {
      config = this.getSignConfig(aad.alg);
    }

    // Encrypt the plain text
    return key_promise.then(function(key) {
      var base64UrlEncoder = new Utils.Base64Url();
      return Jose.crypto.subtle.sign(config.id, key, Utils.arrayFromString( base64UrlEncoder.encode(JSON.stringify(aad)) + '.' + base64UrlEncoder.encodeArray(payload)));
    });
  }

  /**
   * Verify JWS.
   *
   * @param payload     Base64Url encoded payload
   * @param aad         String Base64Url encoded JSON representation of the protected JWS header
   * @param signature   Uint8Array containing the signature
   * @param key_promise Promise<CryptoKey>
   * @param key_id      value of the kid JoseHeader, it'll be passed as part of the result to the returned promise
   * @return Promise<json>
   */
  verify(aad, payload, signature, key_promise, key_id) {
    var that = this;
    var config = this.content_sign;

    return key_promise.then(function(key) {
      config = that.getSignConfig(that.getJwaNameForSignKey(key));
      return Jose.crypto.subtle.verify(config.id, key, signature, Utils.arrayFromString(aad + "." + payload)).then(function(res) {
        return {kid: key_id, verified: res};
      });
    });
  }

  keyId(rsa_key) {
    return Utils.sha256(rsa_key.n + "+" + rsa_key.d);
  }

  /**
   * Splits a CEK into two pieces: a MAC key and an ENC key.
   *
   * This code is structured around the fact that the crypto API does not provide
   * a way to validate truncated MACs. The MAC key is therefore always imported to
   * sign data.
   *
   * @param config (used for key lengths & algorithms)
   * @param cek_promise Promise<CryptoKey>  CEK key to split
   * @param purpose Array<String> usages of the imported key
   * @return [Promise<mac key>, Promise<enc key>]
   */
  splitKey(config, cek_promise, purpose) {
    // We need to split the CEK key into a MAC and ENC keys
    var cek_bytes_promise = cek_promise.then(function(cek) {
      return Jose.crypto.subtle.exportKey("raw", cek);
    });
    var mac_key_promise = cek_bytes_promise.then(function(cek_bytes) {
      if (cek_bytes.byteLength * 8 != config.id.length + config.auth.key_bytes * 8) {
        return Promise.reject(Error("encryptPlainText: incorrect cek length"));
      }
      var bytes = cek_bytes.slice(0, config.auth.key_bytes);
      return Jose.crypto.subtle.importKey("raw", bytes, config.auth.id, false, ["sign"]);
    });
    var enc_key_promise = cek_bytes_promise.then(function(cek_bytes) {
      if (cek_bytes.byteLength * 8 != config.id.length + config.auth.key_bytes * 8) {
        return Promise.reject(Error("encryptPlainText: incorrect cek length"));
      }
      var bytes = cek_bytes.slice(config.auth.key_bytes);
      return Jose.crypto.subtle.importKey("raw", bytes, config.id, false, purpose);
    });
    return [mac_key_promise, enc_key_promise];
  }

  /**
   * Converts the Jose web algorithms into data which is
   * useful for the Web Crypto API.
   *
   * length = in bits
   * bytes = in bytes
   */
  getCryptoConfig(alg) {
    switch (alg) {
      // Key encryption
      case "RSA-OAEP":
        return {
          jwe_name: "RSA-OAEP",
          id: {name: "RSA-OAEP", hash: {name: "SHA-1"}}
        };
      case "RSA-OAEP-256":
        return {
          jwe_name: "RSA-OAEP-256",
          id: {name: "RSA-OAEP", hash: {name: "SHA-256"}}
        };
      case "A128KW":
        return {
          jwe_name: "A128KW",
          id: {name: "AES-KW", length: 128}
        };
      case "A256KW":
        return {
          jwe_name: "A256KW",
          id: {name: "AES-KW", length: 256}
        };
      case "dir":
        return {
          jwe_name: "dir"
        };

      // Content encryption
      case "A128CBC-HS256":
        return {
          jwe_name: "A128CBC-HS256",
          id: {name: "AES-CBC", length: 128},
          iv_bytes: 16,
          specific_cek_bytes: 32,
          auth: {
            key_bytes: 16,
            id: {name: "HMAC", hash: {name: "SHA-256"}},
            truncated_bytes: 16
          }
        };
      case "A256CBC-HS512":
        return {
          jwe_name: "A256CBC-HS512",
          id: {name: "AES-CBC", length: 256},
          iv_bytes: 16,
          specific_cek_bytes: 64,
          auth: {
            key_bytes: 32,
            id: {name: "HMAC", hash: {name: "SHA-512"}},
            truncated_bytes: 32
          }
        };
      case "A128GCM":
        return {
          jwe_name: "A128GCM",
          id: {name: "AES-GCM", length: 128},
          iv_bytes: 12,
          auth: {
            aead: true,
            tag_bytes: 16
          }
        };
      case "A256GCM":
        return {
          jwe_name: "A256GCM",
          id: {name: "AES-GCM", length: 256},
          iv_bytes: 12,
          auth: {
            aead: true,
            tag_bytes: 16
          }
        };
      default:
        throw Error("unsupported algorithm: " + alg);
    }
  }

  /**
   * Computes a truncated MAC.
   *
   * @param config              configuration
   * @param mac_key_promise     Promise<CryptoKey>  mac key
   * @param aad                 Uint8Array
   * @param iv                  Uint8Array
   * @param cipher_text         Uint8Array
   * @return Promise<buffer>    truncated MAC
   */
  truncatedMac(config, mac_key_promise, aad, iv, cipher_text) {
    return mac_key_promise.then(function(mac_key) {
      var al = new Uint8Array(Utils.arrayFromInt32(aad.length * 8));
      var al_full = new Uint8Array(8);
      al_full.set(al, 4);
      var buf = Utils.arrayBufferConcat(aad, iv, cipher_text, al_full);
      return Jose.crypto.subtle.sign(config.auth.id, mac_key, buf).then(function(bytes) {
        return bytes.slice(0, config.auth.truncated_bytes);
      });
    });
  }

  /**
   * Converts the Jose web algorithms into data which is
   * useful for the Web Crypto API.
   */
  getSignConfig(alg) {

    switch (alg) {
      case "RS256":
        return {
          jwa_name: "RS256",
          id: {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}}
        };
      case "RS384":
        return {
          jwa_name: "RS384",
          id: {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-384"}}
        };
      case "RS512":
        return {
          jwa_name: "RS512",
          id: {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-512"}}
        };
      case "PS256":
        return {
          jwa_name: "PS256",
          id: {name: "RSA-PSS", hash: {name: "SHA-256"}, saltLength: 20}
        };
      case "PS384":
        return {
          jwa_name: "PS384",
          id: {name: "RSA-PSS", hash: {name: "SHA-384"}, saltLength: 20}
        };
      case "PS512":
        return {
          jwa_name: "PS512",
          id: {name: "RSA-PSS", hash: {name: "SHA-512"}, saltLength: 20}
        };
      case "HS256":
        return {
          jwa_name: "HS256",
          id: {name: "HMAC", hash: {name: "SHA-256"}}
        };
      case "HS384":
        return {
          jwa_name: "HS384",
          id: {name: "HMAC", hash: {name: "SHA-384"}}
        };
      case "HS512":
        return {
          jwa_name: "HS512",
          id: {name: "HMAC", hash: {name: "SHA-512"}}
        };
      case "ES256":
        return {
          jwa_name: "ES256",
          id: {name: "ECDSA", hash: {name: "SHA-256"}}
        };
      case "ES384":
        return {
          jwa_name: "ES384",
          id: {name: "ECDSA", hash: {name: "SHA-384"}}
        };
      case "ES512":
        return {
          jwa_name: "ES512",
          id: {name: "ECDSA", hash: {name: "SHA-512"}}
        };
      default:
        throw Error("unsupported algorithm: " + alg);
    }
  }

  /**
   * Returns JWA name for a given CryptoKey
   * @param key CryptoKey
   */
  getJwaNameForSignKey(key) {
    var rv = "",
      sign_algo = key.algorithm.name,
      hash_algo = key.algorithm.hash.name;

    if(sign_algo == "RSASSA-PKCS1-v1_5") {
      rv = "R";
    } else if(sign_algo == "RSA-PSS") {
      rv = "P";
    } else {
      throw new Error("unsupported sign/verify algorithm " + sign_algo);
    }

    if(hash_algo.indexOf("SHA-") === 0) {
      rv += "S";
    } else {
      throw new Error("unsupported hash algorithm " + sign_algo);
    }

    rv += hash_algo.substring(4);

    return rv;
  }

  /**
   * Derives key usage from algorithm's name
   *
   * @param alg String algorithm name
   * @returns {*}
   */
  getKeyUsageByAlg(alg) {
    switch (alg) {
      // signature
      case "RS256":
      case "RS384":
      case "RS512":
      case "PS256":
      case "PS384":
      case "PS512":
      case "HS256":
      case "HS384":
      case "HS512":
      case "ES256":
      case "ES384":
      case "ES512":
      case "ES256K":
        return {
          publicKey: "verify",
          privateKey: "sign"
        };
      // key encryption
      case "RSA-OAEP":
      case "RSA-OAEP-256":
      case "A128KW":
      case "A256KW":
        return {
          publicKey: "wrapKey",
          privateKey: "unwrapKey"
        };
      default:
        throw Error("unsupported algorithm: " + alg);
    }
  }

  /**
 * Feel free to override this function.
 */
  assert(expr, msg) {
    if (!expr) {
      throw new Error(msg);
    }
  }
}
