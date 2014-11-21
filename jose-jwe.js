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
				iv_length: 16,
				auth: {
					key_size: 128,
					id: {name: "HMAC", hash: {name: "SHA-256"}},
					truncated_length: 128
				}
			}
        case "A256CBC-HS512":
            return {
                id: {name: "AES-CBC", length: 256},
                iv_length: 16,
                auth: {
                    key_size: 256,
                    id: {name: "HMAC", hash: {name: "SHA-512"}},
                    truncated_length: 256
                }
            };
        case "A128GCM":
            return {
                id: {name: "AES-GCM", length: 128},
                iv_length: 12,
                auth: {
                    aead: true,
                    tag_length: 128
                }
            };
		case "A256GCM":
			return {
				jwe_name: "A256GCM",
				id: {name: "AES-GCM", length: 256},
				iv_length: 12,
				auth: {
					aead: true,
					tag_length: 128
				}
			};
		default:
			JoseJWE.assert(false, "unsupported algorithm: " + alg);
	}
};

