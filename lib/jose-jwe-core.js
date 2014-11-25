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

/**
 * JSON Web Encryption (JWE) library for JavaScript.
 *
 * @author Alok Menghrajani <alok@squareup.com>
 */

/**
 * TODO:
 * 1. consider mixing entropy from the server side (e.g. <div id="entropy">...</div>)
 * 2. jslint
 * 3. more unittests
 * 4. improve error handling. Having everything be a Promise might simplify
 *    error handling?
 */

/**
 * Initializes a JoseJWE object.
 */
function JoseJWE() {
  this.setKeyEncryptionAlgorithm("RSA-OAEP");
  this.setContentEncryptionAlgorithm("A256GCM");
}

/**
 * Feel free to override this function.
 */
JoseJWE.assert = function(expr, msg) {
  if (!expr) {
    throw new Error(msg);
  }
};

/**
 * Overrides the default key encryption algorithm
 * @param alg  string
 */
JoseJWE.prototype.setKeyEncryptionAlgorithm = function(alg) {
  this.key_encryption = JoseJWE.getCryptoConfig(alg);
};

/**
 * Overrides the default content encryption algorithm
 * @param alg  string
 */
JoseJWE.prototype.setContentEncryptionAlgorithm = function(alg) {
  this.content_encryption = JoseJWE.getCryptoConfig(alg);
};

// Private functions

/**
 * Converts the Jose web algorithms into data which is
 * useful for the Web Crypto API.
 *
 * length = in bits
 * bytes = in bytes
 */
JoseJWE.getCryptoConfig = function(alg) {
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
      JoseJWE.assert(false, "unsupported algorithm: " + alg);
  }
};

