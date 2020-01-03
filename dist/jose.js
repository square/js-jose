var Jose =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./lib/jose-core.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./lib/jose-core.js":
/*!**************************!*\
  !*** ./lib/jose-core.js ***!
  \**************************/
/*! exports provided: crypto, Utils, setCrypto, default, Jose, JoseJWE, JoseJWS, WebCryptographer, caniuse */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* WEBPACK VAR INJECTION */(function(Buffer, global) {/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "crypto", function() { return crypto; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Utils", function() { return Utils; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "setCrypto", function() { return setCrypto; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Jose", function() { return Jose; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "JoseJWE", function() { return JoseJWE; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "JoseJWS", function() { return JoseJWS; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "caniuse", function() { return caniuse; });
/* harmony import */ var _jose_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-utils */ "./lib/jose-utils.js");
/* harmony import */ var _jose_jwe_encrypt__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./jose-jwe-encrypt */ "./lib/jose-jwe-encrypt.js");
/* harmony import */ var _jose_jwe_decrypt__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./jose-jwe-decrypt */ "./lib/jose-jwe-decrypt.js");
/* harmony import */ var _jose_jws_sign__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./jose-jws-sign */ "./lib/jose-jws-sign.js");
/* harmony import */ var _jose_jws_verify__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./jose-jws-verify */ "./lib/jose-jws-verify.js");
/* harmony import */ var _jose_jwe_webcryptographer__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./jose-jwe-webcryptographer */ "./lib/jose-jwe-webcryptographer.js");
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "WebCryptographer", function() { return _jose_jwe_webcryptographer__WEBPACK_IMPORTED_MODULE_5__["WebCryptographer"]; });

function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

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






var crypto;
/**
 * Javascript Object Signing and Encryption library.
 *
 * @author Alok Menghrajani <alok@squareup.com>
 */

var Utils = _jose_utils__WEBPACK_IMPORTED_MODULE_0__;
/**
 * Initializes a JoseJWE object.
 */

var JoseJWE = {
  Encrypter: _jose_jwe_encrypt__WEBPACK_IMPORTED_MODULE_1__["Encrypter"],
  Decrypter: _jose_jwe_decrypt__WEBPACK_IMPORTED_MODULE_2__["Decrypter"]
};
/**
 * Initializes a JoseJWS object.
 */

var JoseJWS = {
  Signer: _jose_jws_sign__WEBPACK_IMPORTED_MODULE_3__["Signer"],
  Verifier: _jose_jws_verify__WEBPACK_IMPORTED_MODULE_4__["Verifier"]
};
/**
 * Set crypto provider to use (window.crypto, node-webcrypto-ossl, node-webcrypto-pkcs11 etc.).
 */

var setCrypto = function setCrypto(cp) {
  crypto = cp;
};
/**
 * Default to the global "crypto" variable
 */

if (typeof window !== 'undefined') {
  if (typeof window.crypto !== 'undefined') {
    setCrypto(window.crypto);

    if (!crypto.subtle) {
      crypto.subtle = crypto.webkitSubtle;
    }
  }
}

var Jose = {
  JoseJWS: JoseJWS,
  JoseJWE: JoseJWE,
  WebCryptographer: _jose_jwe_webcryptographer__WEBPACK_IMPORTED_MODULE_5__["WebCryptographer"],
  crypto: crypto,
  Utils: Utils
};
/* harmony default export */ __webpack_exports__["default"] = ({
  Jose: Jose,
  WebCryptographer: _jose_jwe_webcryptographer__WEBPACK_IMPORTED_MODULE_5__["WebCryptographer"]
});

/**
 * Use Node versions of atob, btoa functions outside the browser
 */

if (typeof atob !== 'function') {
  // eslint-disable-next-line no-global-assign
  atob = function atob(str) {
    return Buffer.from(str, 'base64').toString('binary');
  };
}

if (typeof btoa !== 'function') {
  // eslint-disable-next-line no-global-assign
  btoa = function btoa(str) {
    var buffer;

    if (str instanceof Buffer) {
      buffer = str;
    } else {
      buffer = Buffer.from(str.toString(), 'binary');
    }

    return buffer.toString('base64');
  };
}
/**
 * Checks if we have all the required APIs.
 *
 * It might make sense to take a Cryptographer and delegate some of the checks
 * to the cryptographer. I however wanted to keep things simple, so I put all
 * the checks here for now.
 *
 * This list is generated manually and needs to be kept up-to-date.
 *
 * Casual testing shows that:
 * - things work in Chrome 40.0.2214.115
 * - things work in Firefox 35.0.1
 * - Safari 7.1.3 doesn't support JWK keys.
 * - Internet Explorer doesn't support Promises.
 *
 * Note: We don't check if the browser supports specific crypto operations.
 *       I.e. it's possible for this function to return true, but encryption or
 *       decryption to subsequently fail because the browser does not support a
 *       given encryption, decryption, key wrapping, key unwrapping or hmac
 *       operation.
 *
 * @return bool
 */


var caniuse = function caniuse() {
  var r = true; // Promises/A+ (https://promisesaplus.com/)

  r = r && typeof Promise === 'function';
  r = r && typeof Promise.reject === 'function';
  r = r && typeof Promise.prototype.then === 'function';
  r = r && typeof Promise.all === 'function';
  var globalObject = window || global; // Crypto (http://www.w3.org/TR/WebCryptoAPI/)

  r = r && _typeof(globalObject.crypto) === 'object';
  r = r && _typeof(globalObject.crypto.subtle) === 'object';
  r = r && typeof globalObject.crypto.getRandomValues === 'function';
  r = r && typeof globalObject.crypto.subtle.importKey === 'function';
  r = r && typeof globalObject.crypto.subtle.generateKey === 'function';
  r = r && typeof globalObject.crypto.subtle.exportKey === 'function';
  r = r && typeof globalObject.crypto.subtle.wrapKey === 'function';
  r = r && typeof globalObject.crypto.subtle.unwrapKey === 'function';
  r = r && typeof globalObject.crypto.subtle.encrypt === 'function';
  r = r && typeof globalObject.crypto.subtle.decrypt === 'function';
  r = r && typeof globalObject.crypto.subtle.sign === 'function'; // ArrayBuffer (http://people.mozilla.org/~jorendorff/es6-draft.html#sec-arraybuffer-constructor)

  r = r && typeof ArrayBuffer === 'function';
  r = r && (typeof Uint8Array === 'function' || (typeof Uint8Array === "undefined" ? "undefined" : _typeof(Uint8Array)) === 'object'); // Safari uses "object"

  r = r && (typeof Uint32Array === 'function' || (typeof Uint32Array === "undefined" ? "undefined" : _typeof(Uint32Array)) === 'object'); // Safari uses "object"
  // skipping Uint32Array.prototype.buffer because https://people.mozilla.org/~jorendorff/es6-draft.html#sec-properties-of-the-%typedarrayprototype%-object
  // JSON (http://www.ecma-international.org/ecma-262/5.1/#sec-15.12.3)

  r = r && (typeof JSON === "undefined" ? "undefined" : _typeof(JSON)) === 'object';
  r = r && typeof JSON.parse === 'function';
  r = r && typeof JSON.stringify === 'function'; // Base64 (http://www.w3.org/TR/html5/webappapis.html#dom-windowbase64-atob)

  r = r && typeof atob === 'function';
  r = r && typeof btoa === 'function'; // skipping Array functions (map, join, push, length, etc.)
  // skipping String functions (split, charCodeAt, fromCharCode, replace, etc.)
  // skipping regexp.test and parseInt

  return r;
};
/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(/*! ./../node_modules/buffer/index.js */ "./node_modules/buffer/index.js").Buffer, __webpack_require__(/*! ./../node_modules/webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js")))

/***/ }),

/***/ "./lib/jose-jwe-decrypt.js":
/*!*********************************!*\
  !*** ./lib/jose-jwe-decrypt.js ***!
  \*********************************/
/*! exports provided: Decrypter */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Decrypter", function() { return Decrypter; });
/* harmony import */ var _jose_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-utils */ "./lib/jose-utils.js");
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

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

/**
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param keyPromise    Promise<CryptoKey>, either RSA or shared key
 */

var Decrypter =
/*#__PURE__*/
function () {
  function Decrypter(cryptographer, keyPromise) {
    _classCallCheck(this, Decrypter);

    this.cryptographer = cryptographer;
    this.keyPromise = keyPromise;
    this.headers = {};
    this.base64UrlEncoder = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]();
  }

  _createClass(Decrypter, [{
    key: "getHeaders",
    value: function getHeaders() {
      return this.headers;
    }
    /**
     * Performs decryption.
     *
     * @param cipherText  String
     * @return Promise<String>
     */

  }, {
    key: "decrypt",
    value: function decrypt(cipherText) {
      // Split cipherText in 5 parts
      var parts = cipherText.split('.');

      if (parts.length !== 5) {
        return Promise.reject(Error('decrypt: invalid input'));
      } // part 1: header


      this.headers = JSON.parse(this.base64UrlEncoder.decode(parts[0]));

      if (!this.headers.alg) {
        return Promise.reject(Error('decrypt: missing alg'));
      }

      if (!this.headers.enc) {
        return Promise.reject(Error('decrypt: missing enc'));
      }

      this.cryptographer.setKeyEncryptionAlgorithm(this.headers.alg);
      this.cryptographer.setContentEncryptionAlgorithm(this.headers.enc);

      if (this.headers.crit) {
        // We don't support the crit header
        return Promise.reject(Error('decrypt: crit is not supported'));
      }

      var cekPromise;

      if (this.headers.alg === 'dir') {
        // with direct mode, we already have the cek
        cekPromise = Promise.resolve(this.keyPromise);
      } else {
        // part 2: decrypt the CEK
        // In some modes (e.g. RSA-PKCS1v1.5), you must take precautions to prevent
        // chosen-ciphertext attacks as described in RFC 3218, "Preventing
        // the Million Message Attack on Cryptographic Message Syntax". We currently
        // only support RSA-OAEP, so we don't generate a key if unwrapping fails.
        var encryptedCek = this.base64UrlEncoder.decodeArray(parts[1]);
        cekPromise = this.keyPromise.then(function (key) {
          return this.cryptographer.unwrapCek(encryptedCek, key);
        }.bind(this));
      } // part 3: decrypt the cipher text


      var plainTextPromise = this.cryptographer.decrypt(cekPromise, _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromString"](parts[0]), this.base64UrlEncoder.decodeArray(parts[2]), this.base64UrlEncoder.decodeArray(parts[3]), this.base64UrlEncoder.decodeArray(parts[4]));
      return plainTextPromise.then(_jose_utils__WEBPACK_IMPORTED_MODULE_0__["utf8StringFromArray"]);
    }
  }]);

  return Decrypter;
}();

/***/ }),

/***/ "./lib/jose-jwe-encrypt.js":
/*!*********************************!*\
  !*** ./lib/jose-jwe-encrypt.js ***!
  \*********************************/
/*! exports provided: Encrypter */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Encrypter", function() { return Encrypter; });
/* harmony import */ var _jose_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-utils */ "./lib/jose-utils.js");
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

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

/**
 * Handles encryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent).
 * @param keyPromise    Promise<CryptoKey>, either RSA or shared key
 */

var Encrypter =
/*#__PURE__*/
function () {
  function Encrypter(cryptographer, keyPromise) {
    _classCallCheck(this, Encrypter);

    this.cryptographer = cryptographer;
    this.keyPromise = keyPromise;
    this.userHeaders = {};
  }
  /**
   * Adds a key/value pair which will be included in the header.
   *
   * The data lives in plaintext (an attacker can read the header) but is tamper
   * proof (an attacker cannot modify the header).
   *
   * Note: some headers have semantic implications. E.g. if you set the "zip"
   * header, you are responsible for properly compressing plainText before
   * calling encrypt().
   *
   * @param k  String
   * @param v  String
   */


  _createClass(Encrypter, [{
    key: "addHeader",
    value: function addHeader(k, v) {
      this.userHeaders[k] = v;
    }
    /**
     * Performs encryption.
     *
     * @param plainText  utf-8 string
     * @return Promise<String>
     */

  }, {
    key: "encrypt",
    value: function encrypt(plainText) {
      /**
       * Encrypts plainText with CEK.
       *
       * @param cekPromise  Promise<CryptoKey>
       * @param plainText   string
       * @return Promise<json>
       */
      var encryptPlainText = function encryptPlainText(cekPromise, plainText) {
        // Create header
        var headers = {};

        for (var i in this.userHeaders) {
          headers[i] = this.userHeaders[i];
        }

        headers.alg = this.cryptographer.getKeyEncryptionAlgorithm();
        headers.enc = this.cryptographer.getContentEncryptionAlgorithm();
        var jweProtectedHeader = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]().encode(JSON.stringify(headers)); // Create the IV

        var iv = this.cryptographer.createIV(); // Create the AAD

        var aad = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromString"](jweProtectedHeader);
        plainText = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromUtf8String"](plainText);
        return this.cryptographer.encrypt(iv, aad, cekPromise, plainText).then(function (r) {
          r.header = jweProtectedHeader;
          r.iv = iv;
          return r;
        });
      };

      var cekPromise, encryptedCek;

      if (this.cryptographer.getKeyEncryptionAlgorithm() === 'dir') {
        // with direct encryption, this.keyPromise provides the cek
        // and encryptedCek is empty
        cekPromise = Promise.resolve(this.keyPromise);
        encryptedCek = [];
      } else {
        // Create a CEK key
        cekPromise = this.cryptographer.createCek(); // Key & Cek allows us to create the encryptedCek

        encryptedCek = Promise.all([this.keyPromise, cekPromise]).then(function (all) {
          var key = all[0];
          var cek = all[1];
          return this.cryptographer.wrapCek(cek, key);
        }.bind(this));
      } // Cek allows us to encrypy the plain text


      var encPromise = encryptPlainText.bind(this, cekPromise, plainText)(); // Once we have all the promises, we can base64 encode all the pieces.

      return Promise.all([encryptedCek, encPromise]).then(function (all) {
        var encryptedCek = all[0];
        var data = all[1];
        var base64UrlEncoder = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]();
        return data.header + '.' + base64UrlEncoder.encodeArray(encryptedCek) + '.' + base64UrlEncoder.encodeArray(data.iv) + '.' + base64UrlEncoder.encodeArray(data.cipher) + '.' + base64UrlEncoder.encodeArray(data.tag);
      });
    }
  }]);

  return Encrypter;
}();

/***/ }),

/***/ "./lib/jose-jwe-webcryptographer.js":
/*!******************************************!*\
  !*** ./lib/jose-jwe-webcryptographer.js ***!
  \******************************************/
/*! exports provided: WebCryptographer */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "WebCryptographer", function() { return WebCryptographer; });
/* harmony import */ var _jose_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-utils */ "./lib/jose-utils.js");
/* harmony import */ var _jose_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./jose-core */ "./lib/jose-core.js");
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

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


/**
 * The WebCryptographer uses http://www.w3.org/TR/WebCryptoAPI/ to perform
 * various crypto operations. In theory, this should help build the library with
 * different underlying crypto APIs. I'm however unclear if we'll run into code
 * duplication or callback vs Promise based API issues.
 */

var WebCryptographer =
/*#__PURE__*/
function () {
  function WebCryptographer() {
    _classCallCheck(this, WebCryptographer);

    this.setKeyEncryptionAlgorithm('RSA-OAEP');
    this.setContentEncryptionAlgorithm('A256GCM');
    this.setContentSignAlgorithm('RS256');
  }
  /**
   * Overrides the default key encryption algorithm
   * @param alg  string
   */


  _createClass(WebCryptographer, [{
    key: "setKeyEncryptionAlgorithm",
    value: function setKeyEncryptionAlgorithm(alg) {
      this.keyEncryption = this.getCryptoConfig(alg);
    }
  }, {
    key: "getKeyEncryptionAlgorithm",
    value: function getKeyEncryptionAlgorithm() {
      return this.keyEncryption.jweName;
    }
    /**
     * Overrides the default content encryption algorithm
     * @param alg  string
     */

  }, {
    key: "setContentEncryptionAlgorithm",
    value: function setContentEncryptionAlgorithm(alg) {
      this.content_encryption = this.getCryptoConfig(alg);
    }
  }, {
    key: "getContentEncryptionAlgorithm",
    value: function getContentEncryptionAlgorithm() {
      return this.content_encryption.jweName;
    }
    /**
     * Overrides the default content sign algorithm
     * @param alg  string
     */

  }, {
    key: "setContentSignAlgorithm",
    value: function setContentSignAlgorithm(alg) {
      this.content_sign = this.getSignConfig(alg);
    }
  }, {
    key: "getContentSignAlgorithm",
    value: function getContentSignAlgorithm() {
      return this.content_sign.jwa_name;
    }
    /**
     * Generates an IV.
     * This function mainly exists so that it can be mocked for testing purpose.
     *
     * @return Uint8Array with random bytes
     */

  }, {
    key: "createIV",
    value: function createIV() {
      var iv = new Uint8Array(new Array(this.content_encryption.iv_bytes));
      return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.getRandomValues(iv);
    }
    /**
     * Creates a random content encryption key.
     * This function mainly exists so that it can be mocked for testing purpose.
     *
     * @return Promise<CryptoKey>
     */

  }, {
    key: "createCek",
    value: function createCek() {
      var hack = this.getCekWorkaround(this.content_encryption);
      return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.generateKey(hack.id, true, hack.enc_op);
    }
  }, {
    key: "wrapCek",
    value: function wrapCek(cek, key) {
      return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.wrapKey('raw', cek, key, this.keyEncryption.id);
    }
  }, {
    key: "unwrapCek",
    value: function unwrapCek(cek, key) {
      var hack = this.getCekWorkaround(this.content_encryption);
      var extractable = this.content_encryption.specific_cekBytes > 0;
      var keyEncryption = this.keyEncryption.id;
      return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.unwrapKey('raw', cek, key, keyEncryption, hack.id, extractable, hack.dec_op);
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

  }, {
    key: "getCekWorkaround",
    value: function getCekWorkaround(alg) {
      var len = alg.specific_cekBytes;

      if (len) {
        if (len === 16) {
          return {
            id: {
              name: 'AES-CBC',
              length: 128
            },
            enc_op: ['encrypt'],
            dec_op: ['decrypt']
          };
        } else if (len === 32) {
          return {
            id: {
              name: 'AES-CBC',
              length: 256
            },
            enc_op: ['encrypt'],
            dec_op: ['decrypt']
          };
        } else if (len === 64) {
          return {
            id: {
              name: 'HMAC',
              hash: {
                name: 'SHA-256'
              }
            },
            enc_op: ['sign'],
            dec_op: ['verify']
          };
        } else if (len === 128) {
          return {
            id: {
              name: 'HMAC',
              hash: {
                name: 'SHA-384'
              }
            },
            enc_op: ['sign'],
            dec_op: ['verify']
          };
        } else {
          this.assert(false, 'getCekWorkaround: invalid len');
        }
      }

      return {
        id: alg.id,
        enc_op: ['encrypt'],
        dec_op: ['decrypt']
      };
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

  }, {
    key: "encrypt",
    value: function encrypt(iv, aad, cekPromise, plainText) {
      var _this = this;

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
          return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.encrypt(enc, cek, plainText).then(function (cipherText) {
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
        var encKeyPromise = keys[1]; // Encrypt the plain text

        var cipherTextPromise = encKeyPromise.then(function (encKey) {
          var enc = {
            name: config.id.name,
            iv: iv
          };
          return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.encrypt(enc, encKey, plainText);
        }); // compute MAC

        var macPromise = cipherTextPromise.then(function (cipherText) {
          return _this.truncatedMac(config, macKeyPromise, aad, iv, cipherText);
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

  }, {
    key: "compare",
    value: function compare(config, macKeyPromise, arr1, arr2) {
      this.assert(arr1 instanceof Uint8Array, 'compare: invalid input');
      this.assert(arr2 instanceof Uint8Array, 'compare: invalid input');
      return macKeyPromise.then(function (macKey) {
        var hash1 = _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.sign(config.auth.id, macKey, arr1);
        var hash2 = _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.sign(config.auth.id, macKey, arr2);
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

  }, {
    key: "decrypt",
    value: function decrypt(cekPromise, aad, iv, cipherText, tag) {
      var _this2 = this;

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
          var buf = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayBufferConcat"](cipherText, tag);
          return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.decrypt(dec, cek, buf);
        });
      } else {
        var keys = this.splitKey(config, cekPromise, ['decrypt']);
        var macKeyPromise = keys[0];
        var encKeyPromise = keys[1]; // Validate the MAC

        var macPromise = this.truncatedMac(config, macKeyPromise, aad, iv, cipherText);
        return Promise.all([encKeyPromise, macPromise]).then(function (all) {
          var encKey = all[0];
          var mac = all[1];
          return _this2.compare(config, macKeyPromise, new Uint8Array(mac), tag).then(function () {
            var dec = {
              name: config.id.name,
              iv: iv
            };
            return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.decrypt(dec, encKey, cipherText);
          })["catch"](function () {
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

  }, {
    key: "sign",
    value: function sign(aad, payload, keyPromise) {
      var config = this.content_sign;

      if (aad.alg) {
        config = this.getSignConfig(aad.alg);
      } // Encrypt the plain text


      return keyPromise.then(function (key) {
        var base64UrlEncoder = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]();
        return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.sign(config.id, key, _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromString"](base64UrlEncoder.encode(JSON.stringify(aad)) + '.' + base64UrlEncoder.encodeArray(payload)));
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

  }, {
    key: "verify",
    value: function verify(aad, payload, signature, keyPromise, keyId) {
      var config = this.content_sign;
      return keyPromise.then(function (key) {
        return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.verify(config.id, key, signature, _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromString"](aad + '.' + payload)).then(function (res) {
          return {
            kid: keyId,
            verified: res
          };
        });
      });
    }
  }, {
    key: "keyId",
    value: function keyId(rsaKey) {
      return _jose_utils__WEBPACK_IMPORTED_MODULE_0__["sha256"](rsaKey.n + '+' + rsaKey.d);
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

  }, {
    key: "splitKey",
    value: function splitKey(config, cekPromise, purpose) {
      // We need to split the CEK key into a MAC and ENC keys
      var cekBytesPromise = cekPromise.then(function (cek) {
        return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.exportKey('raw', cek);
      });
      var macKeyPromise = cekBytesPromise.then(function (cekBytes) {
        if (cekBytes.byteLength * 8 !== config.id.length + config.auth.key_bytes * 8) {
          return Promise.reject(Error('encryptPlainText: incorrect cek length'));
        }

        var bytes = cekBytes.slice(0, config.auth.key_bytes);
        return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.importKey('raw', bytes, config.auth.id, false, ['sign']);
      });
      var encKeyPromise = cekBytesPromise.then(function (cekBytes) {
        if (cekBytes.byteLength * 8 !== config.id.length + config.auth.key_bytes * 8) {
          return Promise.reject(Error('encryptPlainText: incorrect cek length'));
        }

        var bytes = cekBytes.slice(config.auth.key_bytes);
        return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.importKey('raw', bytes, config.id, false, purpose);
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

  }, {
    key: "getCryptoConfig",
    value: function getCryptoConfig(alg) {
      switch (alg) {
        // Key encryption
        case 'RSA-OAEP':
          return {
            jweName: 'RSA-OAEP',
            id: {
              name: 'RSA-OAEP',
              hash: {
                name: 'SHA-1'
              }
            }
          };

        case 'RSA-OAEP-256':
          return {
            jweName: 'RSA-OAEP-256',
            id: {
              name: 'RSA-OAEP',
              hash: {
                name: 'SHA-256'
              }
            }
          };

        case 'A128KW':
          return {
            jweName: 'A128KW',
            id: {
              name: 'AES-KW',
              length: 128
            }
          };

        case 'A256KW':
          return {
            jweName: 'A256KW',
            id: {
              name: 'AES-KW',
              length: 256
            }
          };

        case 'dir':
          return {
            jweName: 'dir'
          };
        // Content encryption

        case 'A128CBC-HS256':
          return {
            jweName: 'A128CBC-HS256',
            id: {
              name: 'AES-CBC',
              length: 128
            },
            iv_bytes: 16,
            specific_cekBytes: 32,
            auth: {
              key_bytes: 16,
              id: {
                name: 'HMAC',
                hash: {
                  name: 'SHA-256'
                }
              },
              truncated_bytes: 16
            }
          };

        case 'A256CBC-HS512':
          return {
            jweName: 'A256CBC-HS512',
            id: {
              name: 'AES-CBC',
              length: 256
            },
            iv_bytes: 16,
            specific_cekBytes: 64,
            auth: {
              key_bytes: 32,
              id: {
                name: 'HMAC',
                hash: {
                  name: 'SHA-512'
                }
              },
              truncated_bytes: 32
            }
          };

        case 'A128GCM':
          return {
            jweName: 'A128GCM',
            id: {
              name: 'AES-GCM',
              length: 128
            },
            iv_bytes: 12,
            auth: {
              aead: true,
              tagBytes: 16
            }
          };

        case 'A256GCM':
          return {
            jweName: 'A256GCM',
            id: {
              name: 'AES-GCM',
              length: 256
            },
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

  }, {
    key: "truncatedMac",
    value: function truncatedMac(config, macKeyPromise, aad, iv, cipherText) {
      return macKeyPromise.then(function (macKey) {
        var al = new Uint8Array(_jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromInt32"](aad.length * 8));
        var alFull = new Uint8Array(8);
        alFull.set(al, 4);
        var buf = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayBufferConcat"](aad, iv, cipherText, alFull);
        return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.sign(config.auth.id, macKey, buf).then(function (bytes) {
          return bytes.slice(0, config.auth.truncated_bytes);
        });
      });
    }
    /**
     * Converts the Jose web algorithms into data which is
     * useful for the Web Crypto API.
     */

  }, {
    key: "getSignConfig",
    value: function getSignConfig(alg) {
      switch (alg) {
        case 'RS256':
          return {
            jwa_name: 'RS256',
            id: {
              name: 'RSASSA-PKCS1-v1_5',
              hash: {
                name: 'SHA-256'
              }
            }
          };

        case 'RS384':
          return {
            jwa_name: 'RS384',
            id: {
              name: 'RSASSA-PKCS1-v1_5',
              hash: {
                name: 'SHA-384'
              }
            }
          };

        case 'RS512':
          return {
            jwa_name: 'RS512',
            id: {
              name: 'RSASSA-PKCS1-v1_5',
              hash: {
                name: 'SHA-512'
              }
            }
          };

        case 'PS256':
          return {
            jwa_name: 'PS256',
            id: {
              name: 'RSA-PSS',
              hash: {
                name: 'SHA-256'
              },
              saltLength: 20
            }
          };

        case 'PS384':
          return {
            jwa_name: 'PS384',
            id: {
              name: 'RSA-PSS',
              hash: {
                name: 'SHA-384'
              },
              saltLength: 20
            }
          };

        case 'PS512':
          return {
            jwa_name: 'PS512',
            id: {
              name: 'RSA-PSS',
              hash: {
                name: 'SHA-512'
              },
              saltLength: 20
            }
          };

        case 'HS256':
          return {
            jwa_name: 'HS256',
            id: {
              name: 'HMAC',
              hash: {
                name: 'SHA-256'
              }
            }
          };

        case 'HS384':
          return {
            jwa_name: 'HS384',
            id: {
              name: 'HMAC',
              hash: {
                name: 'SHA-384'
              }
            }
          };

        case 'HS512':
          return {
            jwa_name: 'HS512',
            id: {
              name: 'HMAC',
              hash: {
                name: 'SHA-512'
              }
            }
          };

        case 'ES256':
          return {
            jwa_name: 'ES256',
            id: {
              name: 'ECDSA',
              namedCurve: 'P-256',
              hash: {
                name: 'SHA-256'
              }
            }
          };

        case 'ES384':
          return {
            jwa_name: 'ES384',
            id: {
              name: 'ECDSA',
              namedCurve: 'P-384',
              hash: {
                name: 'SHA-384'
              }
            }
          };

        case 'ES512':
          return {
            jwa_name: 'ES512',
            id: {
              name: 'ECDSA',
              namedCurve: 'P-521',
              hash: {
                name: 'SHA-512'
              }
            }
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

  }, {
    key: "getKeyUsageByAlg",
    value: function getKeyUsageByAlg(alg) {
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

  }, {
    key: "assert",
    value: function assert(expr, msg) {
      if (!expr) {
        throw new Error(msg);
      }
    }
  }]);

  return WebCryptographer;
}();

/***/ }),

/***/ "./lib/jose-jws-sign.js":
/*!******************************!*\
  !*** ./lib/jose-jws-sign.js ***!
  \******************************/
/*! exports provided: Signer, JWS */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Signer", function() { return Signer; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "JWS", function() { return JWS; });
/* harmony import */ var _jose_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-utils */ "./lib/jose-utils.js");
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

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

/**
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */

var Signer =
/*#__PURE__*/
function () {
  function Signer(cryptographer) {
    _classCallCheck(this, Signer);

    this.cryptographer = cryptographer;
    this.keyPromises = {};
    this.waiting_kid = 0;
    this.headers = {};
    this.signer_aads = {};
    this.signer_headers = {};
  }
  /**
   * Adds a signer to JoseJWS instance.
   *
   * @param key            private key in json format. Parameters can be base64
   *                       encoded, strings or number (for e.g. 'e'), or CryptoKey.
   * @param keyId         a string identifying the key. OPTIONAL
   * @param aad            Object protected header
   * @param header         Object unprotected header
   */


  _createClass(Signer, [{
    key: "addSigner",
    value: function addSigner(key, keyId, aad, header) {
      var that = this;
      var keyPromise;

      if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isCryptoKey"](key)) {
        keyPromise = new Promise(function (resolve) {
          resolve(key);
        });
      } else {
        var alg;

        if (aad && aad.alg) {
          alg = aad.alg;
        } else {
          alg = that.cryptographer.getContentSignAlgorithm();
        }

        keyPromise = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["importPrivateKey"](key, alg, 'sign');
      }

      var kidPromise;

      if (keyId) {
        kidPromise = new Promise(function (resolve) {
          resolve(keyId);
        });
      } else if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isCryptoKey"](key)) {
        throw new Error('keyId is a mandatory argument when the key is a CryptoKey');
      } else {
        kidPromise = this.cryptographer.keyId(key);
      }

      that.waiting_kid++;
      return kidPromise.then(function (kid) {
        that.keyPromises[kid] = keyPromise;
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
     * @param jws     JWS Object to be signed or its representation
     * @param aad     Object protected header
     * @param header  Object unprotected header
     * @return Promise<String>
     */

  }, {
    key: "addSignature",
    value: function addSignature(jws, aad, header) {
      if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isString"](jws)) {
        jws = JSON.parse(jws);
      }

      if (jws.payload && _jose_utils__WEBPACK_IMPORTED_MODULE_0__["isString"](jws.payload) && jws["protected"] && _jose_utils__WEBPACK_IMPORTED_MODULE_0__["isString"](jws["protected"]) && jws.header && jws.header instanceof Object && jws.signature && _jose_utils__WEBPACK_IMPORTED_MODULE_0__["isString"](jws.signature)) {
        return this.sign(JWS.fromObject(jws), aad, header);
      } else {
        throw new Error('JWS is not a valid JWS object');
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

  }, {
    key: "sign",
    value: function sign(payload, aad, header) {
      var that = this;
      var kids = [];

      if (Object.keys(that.keyPromises).length === 0) {
        throw new Error('No signers defined. At least one is required to sign the JWS.');
      }

      if (that.waiting_kid) {
        throw new Error('still generating key IDs');
      }

      function sign(message, protectedHeader, unprotectedHeader, keyPromise, kid) {
        var toBeSigned;

        if (!protectedHeader) {
          protectedHeader = {};
        }

        if (!protectedHeader.alg) {
          protectedHeader.alg = that.cryptographer.getContentSignAlgorithm();
          protectedHeader.typ = 'JWT';
        }

        if (!protectedHeader.kid) {
          protectedHeader.kid = kid;
        }

        if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isString"](message)) {
          toBeSigned = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromUtf8String"](message);
        } else {
          try {
            toBeSigned = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayish"](message);
          } catch (e) {
            if (message instanceof JWS) {
              toBeSigned = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromString"](new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]().decode(message.payload));
            } else if (message instanceof Object) {
              toBeSigned = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromUtf8String"](JSON.stringify(message));
            } else {
              throw new Error('cannot sign this message');
            }
          }
        }

        return that.cryptographer.sign(protectedHeader, toBeSigned, keyPromise).then(function (signature) {
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

      function doSign(pl, ph, uh, kps, kids) {
        if (kids.length) {
          var kid = kids.shift();
          var rv = sign(pl, that.signer_aads[kid] || ph, that.signer_headers[kid] || uh, kps[kid], kid);

          if (kids.length) {
            rv = rv.then(function (jws) {
              return doSign(jws, null, null, kps, kids);
            });
          }

          return rv;
        }
      }

      for (var kid in that.keyPromises) {
        if (Object.prototype.hasOwnProperty.call(that.keyPromises, kid)) {
          kids.push(kid);
        }
      }

      return doSign(payload, aad, header, that.keyPromises, kids);
    }
  }]);

  return Signer;
}();
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

var JWS =
/*#__PURE__*/
function () {
  function JWS(protectedHeader, header, payload, signature) {
    _classCallCheck(this, JWS);

    this.header = header;
    var base64UrlEncoder = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]();
    this.payload = base64UrlEncoder.encodeArray(payload);

    if (signature) {
      this.signature = base64UrlEncoder.encodeArray(signature);
    }

    this["protected"] = base64UrlEncoder.encode(JSON.stringify(protectedHeader));
  }

  _createClass(JWS, [{
    key: "fromObject",
    value: function fromObject(obj) {
      var rv = new JWS(obj["protected"], obj.header, obj.payload, null);
      rv.signature = obj.signature;
      rv.signatures = obj.signatures;
      return rv;
    }
    /**
     * Serialize a JWS object using the JSON serialization format
     *
     * @returns {Object} a copy of this
     */

  }, {
    key: "JsonSerialize",
    value: function JsonSerialize() {
      return JSON.stringify(this);
    }
    /**
     * Serialize a JWS object using the Compact Serialization Format
     *
     * @returns {string} BASE64URL(UTF8(PROTECTED HEADER)).BASE64URL(PAYLOAD).BASE64URL(SIGNATURE)
     */

  }, {
    key: "CompactSerialize",
    value: function CompactSerialize() {
      return this["protected"] + '.' + this.payload + '.' + this.signature;
    }
  }]);

  return JWS;
}();

/***/ }),

/***/ "./lib/jose-jws-verify.js":
/*!********************************!*\
  !*** ./lib/jose-jws-verify.js ***!
  \********************************/
/*! exports provided: Verifier */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Verifier", function() { return Verifier; });
/* harmony import */ var _jose_utils__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-utils */ "./lib/jose-utils.js");
function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

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

var Verifier =
/*#__PURE__*/
function () {
  function Verifier(cryptographer, message, keyfinder) {
    _classCallCheck(this, Verifier);

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

    if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isString"](message)) {
      if (jwt = jwtRx.exec(message)) {
        if (jwt.length !== 4) {
          throw new Error('wrong JWS compact serialization format');
        }

        message = {
          "protected": jwt[1],
          payload: jwt[2],
          signature: jwt[3]
        };
      } else {
        message = JSON.parse(message);
      }
    } else if (_typeof(message) !== 'object') {
      throw new Error('data format not supported');
    }

    aad = message["protected"];
    header = message.header;
    payload = message.payload;
    signatures = message.signatures instanceof Array ? message.signatures.slice(0) : [];
    signatures.forEach(function (sign) {
      sign.aad = sign["protected"];
      sign["protected"] = JSON.parse(new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]().decode(sign["protected"]));
    });
    that.aad = aad;
    protectedHeader = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]().decode(aad);

    try {
      protectedHeader = JSON.parse(protectedHeader);
    } catch (e) {}

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
        "protected": protectedHeader,
        header: header,
        signature: message.signature
      });
    }

    that.signatures = [];

    for (var i = 0; i < signatures.length; i++) {
      that.signatures[i] = JSON.parse(JSON.stringify(signatures[i]));
      that.signatures[i].signature = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["arrayFromString"](new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]().decode(signatures[i].signature));
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


  _createClass(Verifier, [{
    key: "addRecipient",
    value: function addRecipient(key, keyId, alg) {
      var that = this;
      var kidPromise;
      var keyPromise;

      if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isCryptoKey"](key)) {
        keyPromise = new Promise(function (resolve) {
          resolve(key);
        });
      } else {
        keyPromise = _jose_utils__WEBPACK_IMPORTED_MODULE_0__["importPublicKey"](key, alg || that.cryptographer.getContentSignAlgorithm(), 'verify');
      }

      if (keyId) {
        kidPromise = new Promise(function (resolve) {
          resolve(keyId);
        });
      } else if (_jose_utils__WEBPACK_IMPORTED_MODULE_0__["isCryptoKey"](key)) {
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

  }, {
    key: "verify",
    value: function verify() {
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
        var kid = sig["protected"].kid;

        if (keyfinder) {
          keyPromises[kid] = keyfinder(kid);
        }

        promises.push(that.cryptographer.verify(sig.aad, that.payload, sig.signature, keyPromises[kid], kid).then(function (vr) {
          if (vr.verified) {
            vr.payload = new _jose_utils__WEBPACK_IMPORTED_MODULE_0__["Base64Url"]().decode(that.payload);
          }

          return vr;
        }));
      });
      return Promise.all(promises);
    }
  }]);

  return Verifier;
}();

/***/ }),

/***/ "./lib/jose-utils.js":
/*!***************************!*\
  !*** ./lib/jose-utils.js ***!
  \***************************/
/*! exports provided: importPublicKey, importPrivateKey, importEcPublicKey, importEcPrivateKey, importRsaPublicKey, importRsaPrivateKey, isString, arrayish, convertRsaKey, arrayFromString, arrayFromUtf8String, stringFromArray, utf8StringFromArray, stripLeadingZeros, arrayFromInt32, arrayBufferConcat, sha256, isCryptoKey, Base64Url */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "importPublicKey", function() { return importPublicKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "importPrivateKey", function() { return importPrivateKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "importEcPublicKey", function() { return importEcPublicKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "importEcPrivateKey", function() { return importEcPrivateKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "importRsaPublicKey", function() { return importRsaPublicKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "importRsaPrivateKey", function() { return importRsaPrivateKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "isString", function() { return isString; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "arrayish", function() { return arrayish; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "convertRsaKey", function() { return convertRsaKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "arrayFromString", function() { return arrayFromString; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "arrayFromUtf8String", function() { return arrayFromUtf8String; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "stringFromArray", function() { return stringFromArray; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "utf8StringFromArray", function() { return utf8StringFromArray; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "stripLeadingZeros", function() { return stripLeadingZeros; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "arrayFromInt32", function() { return arrayFromInt32; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "arrayBufferConcat", function() { return arrayBufferConcat; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "sha256", function() { return sha256; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "isCryptoKey", function() { return isCryptoKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Base64Url", function() { return Base64Url; });
/* harmony import */ var _jose_jwe_webcryptographer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jose-jwe-webcryptographer */ "./lib/jose-jwe-webcryptographer.js");
/* harmony import */ var _jose_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./jose-core */ "./lib/jose-core.js");
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

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


var webCryptographer = new _jose_jwe_webcryptographer__WEBPACK_IMPORTED_MODULE_0__["WebCryptographer"]();
/**
 * Import a public key in JWK format, either RSA or ECDSA.
 *
 * @param key   JWK public key
 * @param alg   Name of the JWA signing algorithm (e.g. RS256)
 * @return Promise<CryptoKey>
 */

var importPublicKey = function importPublicKey(key, alg) {
  switch (alg) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return importRsaPublicKey(key, alg);

    case 'ES256':
    case 'ES384':
    case 'ES512':
      return importEcPublicKey(key, alg);

    default:
      throw Error('unsupported algorithm: ' + alg);
  }
};
/**
 * Import a private key in JWK format, either RSA or EC.
 *
 * @param key   JWK private key
 * @param alg   Name of the JWA signing algorithm (e.g. RS256)
 * @return Promise<CryptoKey>
 */

var importPrivateKey = function importPrivateKey(key, alg) {
  switch (alg) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return importRsaPrivateKey(key, alg);

    case 'ES256':
    case 'ES384':
    case 'ES512':
      return importEcPrivateKey(key, alg);

    default:
      throw Error('unsupported algorithm: ' + alg);
  }
};
/**
 * Import a public EC key in JWK format.
 *
 * @param ecKey   JWK public key
 * @param alg   Name of the JWA signing algorithm (e.g. ES256)
 * @return Promise<CryptoKey>
 */

var importEcPublicKey = function importEcPublicKey(ecKey, alg) {
  var config = webCryptographer.getSignConfig(alg);
  var usage = webCryptographer.getKeyUsageByAlg(alg);
  return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.importKey('jwk', ecKey, config.id, false, [usage.publicKey]);
};
/**
 * Import a private EC key in JWK format.
 *
 * @param ecKey   JWK private key
 * @param alg   Name of the JWA signing algorithm (e.g. ES256)
 * @return Promise<CryptoKey>
 */

var importEcPrivateKey = function importEcPrivateKey(ecKey, alg) {
  var config = webCryptographer.getSignConfig(alg);
  var usage = webCryptographer.getKeyUsageByAlg(alg);
  return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.importKey('jwk', ecKey, config.id, false, [usage.privateKey]);
};
/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsaKey  public RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @return Promise<CryptoKey>
 */

var importRsaPublicKey = function importRsaPublicKey(rsaKey, alg) {
  var jwk;
  var config;
  var usage = webCryptographer.getKeyUsageByAlg(alg);

  if (usage.publicKey === 'wrapKey') {
    if (!rsaKey.alg) {
      rsaKey.alg = alg;
    }

    jwk = convertRsaKey(rsaKey, ['n', 'e']);
    config = webCryptographer.getCryptoConfig(alg);
  } else {
    var rk = {};

    for (var name in rsaKey) {
      if (Object.prototype.hasOwnProperty.call(rsaKey, name)) {
        rk[name] = rsaKey[name];
      }
    }

    if (!rk.alg && alg) {
      rk.alg = alg;
    }

    config = webCryptographer.getSignConfig(rk.alg);
    jwk = convertRsaKey(rk, ['n', 'e']);
    jwk.ext = true;
  }

  return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.importKey('jwk', jwk, config.id, false, [usage.publicKey]);
};
/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP and RSA. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsaKey  private RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @return Promise<CryptoKey>
 */

var importRsaPrivateKey = function importRsaPrivateKey(rsaKey, alg) {
  var jwk;
  var config;
  var usage = webCryptographer.getKeyUsageByAlg(alg);

  if (usage.privateKey === 'unwrapKey') {
    if (!rsaKey.alg) {
      rsaKey.alg = alg;
    }

    jwk = convertRsaKey(rsaKey, ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']);
    config = webCryptographer.getCryptoConfig(alg);
  } else {
    var rk = {};

    for (var name in rsaKey) {
      if (Object.prototype.hasOwnProperty.call(rsaKey, name)) {
        rk[name] = rsaKey[name];
      }
    }

    config = webCryptographer.getSignConfig(alg);

    if (!rk.alg && alg) {
      rk.alg = alg;
    }

    jwk = convertRsaKey(rk, ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']);
    jwk.ext = true;
  }

  return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.importKey('jwk', jwk, config.id, false, [usage.privateKey]);
}; // Private functions

var isString = function isString(str) {
  return typeof str === 'string' || str instanceof String;
};
/**
 * Takes an arrayish (an array, ArrayBuffer or Uint8Array)
 * and returns an array or a Uint8Array.
 *
 * @param arr  arrayish
 * @return array or Uint8Array
 */

var arrayish = function arrayish(arr) {
  if (arr instanceof Array) {
    return arr;
  }

  if (arr instanceof Uint8Array) {
    return arr;
  }

  if (arr instanceof ArrayBuffer) {
    return new Uint8Array(arr);
  }

  webCryptographer.assert(false, 'arrayish: invalid input');
};
/**
 * Checks if an RSA key contains all the expected parameters. Also checks their
 * types. Converts hex encoded strings (or numbers) to base64.
 *
 * @param rsaKey     RSA key in json format. Parameters can be base64 encoded,
 *                    strings or number (for 'e').
 * @param parameters  array<string>
 * @return json
 */

var convertRsaKey = function convertRsaKey(rsaKey, parameters) {
  var r = {};
  var alg; // Check that we have all the parameters

  var missing = [];
  parameters.map(function (p) {
    if (typeof rsaKey[p] === 'undefined') {
      missing.push(p);
    }
  });

  if (missing.length > 0) {
    webCryptographer.assert(false, 'convertRsaKey: Was expecting ' + missing.join());
  } // kty is either missing or is set to "RSA"


  if (typeof rsaKey.kty !== 'undefined') {
    webCryptographer.assert(rsaKey.kty === 'RSA', "convertRsaKey: expecting rsaKey['kty'] to be 'RSA'");
  }

  r.kty = 'RSA';

  try {
    webCryptographer.getSignConfig(rsaKey.alg);
    alg = rsaKey.alg;
  } catch (err) {
    try {
      webCryptographer.getCryptoConfig(rsaKey.alg);
      alg = rsaKey.alg;
    } catch (er) {
      webCryptographer.assert(alg, "convertRsaKey: expecting rsaKey['alg'] to have a valid value");
    }
  }

  r.alg = alg; // note: we punt on checking key_ops

  var intFromHex = function intFromHex(e) {
    return parseInt(e, 16);
  };

  for (var i = 0; i < parameters.length; i++) {
    var p = parameters[i];
    var v = rsaKey[p];
    var base64UrlEncoder = new Base64Url();

    if (p === 'e') {
      if (typeof v === 'number') {
        v = base64UrlEncoder.encodeArray(stripLeadingZeros(arrayFromInt32(v)));
      }
    } else if (/^([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$/.test(v)) {
      var arr = v.split(':').map(intFromHex);
      v = base64UrlEncoder.encodeArray(stripLeadingZeros(arr));
    } else if (typeof v !== 'string') {
      webCryptographer.assert(false, "convertRsaKey: expecting rsaKey['" + p + "'] to be a string");
    }

    r[p] = v;
  }

  return r;
};
/**
 * Converts a string into an array of ascii codes.
 *
 * @param str  ascii string
 * @return Uint8Array
 */

var arrayFromString = function arrayFromString(str) {
  webCryptographer.assert(isString(str), 'arrayFromString: invalid input');
  var arr = str.split('').map(function (c) {
    return c.charCodeAt(0);
  });
  return new Uint8Array(arr);
};
/**
 * Converts a string into an array of utf-8 codes.
 *
* @param str  utf-8 string
 * @return Uint8Array
 */

var arrayFromUtf8String = function arrayFromUtf8String(str) {
  webCryptographer.assert(isString(str), 'arrayFromUtf8String: invalid input'); // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.

  str = unescape(encodeURIComponent(str));
  return arrayFromString(str);
};
/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  arrayish
 * @return ascii string
 */

var stringFromArray = function stringFromArray(arr) {
  arr = arrayish(arr);
  var r = '';

  for (var i = 0; i < arr.length; i++) {
    r += String.fromCharCode(arr[i]);
  }

  return r;
};
/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  ArrayBuffer
 * @return ascii string
 */

var utf8StringFromArray = function utf8StringFromArray(arr) {
  webCryptographer.assert(arr instanceof ArrayBuffer, 'utf8StringFromArray: invalid input'); // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.

  var r = stringFromArray(arr);
  return decodeURIComponent(escape(r));
};
/**
 * Strips leading zero in an array.
 *
 * @param arr  arrayish
 * @return array
 */

var stripLeadingZeros = function stripLeadingZeros(arr) {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }

  var isLeadingZero = true;
  var r = [];

  for (var i = 0; i < arr.length; i++) {
    if (isLeadingZero && arr[i] === 0) {
      continue;
    }

    isLeadingZero = false;
    r.push(arr[i]);
  }

  return r;
};
/**
 * Converts a number into an array of 4 bytes (big endian).
 *
 * @param i  number
 * @return ArrayBuffer
 */

var arrayFromInt32 = function arrayFromInt32(i) {
  webCryptographer.assert(typeof i === 'number', 'arrayFromInt32: invalid input'); // TODO(eslint): figure out if there's a better way to validate i
  // eslint-disable-next-line eqeqeq, no-self-compare

  webCryptographer.assert(i == i | 0, 'arrayFromInt32: out of range');
  var buf = new Uint8Array(new Uint32Array([i]).buffer);
  var r = new Uint8Array(4);

  for (var j = 0; j < 4; j++) {
    r[j] = buf[3 - j];
  }

  return r.buffer;
};
/**
 * Concatenates arrayishes.
 *
 * note: cannot be a Arrow function, because Arrow functions do not expose 'arguments' object
 * and Rest parameters are not supported in Babel yet.
 *
 * @param arguments two or more arrayishes
 * @return Uint8Array
 */

function arrayBufferConcat()
/* ... */
{
  // Compute total size
  var args = [];
  var total = 0;

  for (var i = 0; i < arguments.length; i++) {
    args.push(arrayish(arguments[i]));
    total += args[i].length;
  }

  var r = new Uint8Array(total);
  var offset = 0;

  for (i = 0; i < arguments.length; i++) {
    for (var j = 0; j < args[i].length; j++) {
      r[offset++] = args[i][j];
    }
  }

  webCryptographer.assert(offset === total, 'arrayBufferConcat: unexpected offset');
  return r;
}
var sha256 = function sha256(str) {
  // Browser docs indicate the first parameter to crypto.subtle.digest to be a
  // DOMString. This was initially implemented as an object and continues to be
  // supported, so we favor the older form for backwards compatibility.
  return _jose_core__WEBPACK_IMPORTED_MODULE_1__["Jose"].crypto.subtle.digest({
    name: 'SHA-256'
  }, arrayFromString(str)).then(function (hash) {
    return new Base64Url().encodeArray(hash);
  });
};
var isCryptoKey = function isCryptoKey(rsaKey) {
  // Some browsers don't expose the CryptoKey as an object, so we need to check
  // the constructor's name.
  if (rsaKey.constructor.name === 'CryptoKey') {
    return true;
  } // In the presence of minifiers, relying on class names can be problematic,
  // so let's also allow objects that have an 'algorithm' property.


  if (Object.prototype.hasOwnProperty.call(rsaKey, 'algorithm')) {
    return true;
  }

  return false;
};
var Base64Url =
/*#__PURE__*/
function () {
  function Base64Url() {
    _classCallCheck(this, Base64Url);
  }

  _createClass(Base64Url, [{
    key: "encode",

    /**
     * Base64Url encodes a string (no trailing '=')
     *
     * @param str  string
     * @return string
     */
    value: function encode(str) {
      webCryptographer.assert(isString(str), 'Base64Url.encode: invalid input');
      return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    /**
     * Base64Url encodes an array
     *
     * @param arr array or ArrayBuffer
     * @return string
     */

  }, {
    key: "encodeArray",
    value: function encodeArray(arr) {
      return this.encode(stringFromArray(arr));
    }
    /**
     * Base64Url decodes a string
     *
     * @param str  string
     * @return string
     */

  }, {
    key: "decode",
    value: function decode(str) {
      webCryptographer.assert(isString(str), 'Base64Url.decode: invalid input'); // atob is nice and ignores missing '='

      return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    }
  }, {
    key: "decodeArray",
    value: function decodeArray(str) {
      webCryptographer.assert(isString(str), 'Base64Url.decodeArray: invalid input');
      return arrayFromString(this.decode(str));
    }
  }]);

  return Base64Url;
}();

/***/ }),

/***/ "./node_modules/base64-js/index.js":
/*!*****************************************!*\
  !*** ./node_modules/base64-js/index.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.byteLength = byteLength;
exports.toByteArray = toByteArray;
exports.fromByteArray = fromByteArray;
var lookup = [];
var revLookup = [];
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array;
var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i];
  revLookup[code.charCodeAt(i)] = i;
} // Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications


revLookup['-'.charCodeAt(0)] = 62;
revLookup['_'.charCodeAt(0)] = 63;

function getLens(b64) {
  var len = b64.length;

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4');
  } // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42


  var validLen = b64.indexOf('=');
  if (validLen === -1) validLen = len;
  var placeHoldersLen = validLen === len ? 0 : 4 - validLen % 4;
  return [validLen, placeHoldersLen];
} // base64 is 4/3 + up to two characters of the original data


function byteLength(b64) {
  var lens = getLens(b64);
  var validLen = lens[0];
  var placeHoldersLen = lens[1];
  return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
}

function _byteLength(b64, validLen, placeHoldersLen) {
  return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
}

function toByteArray(b64) {
  var tmp;
  var lens = getLens(b64);
  var validLen = lens[0];
  var placeHoldersLen = lens[1];
  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));
  var curByte = 0; // if there are placeholders, only get up to the last complete 4 chars

  var len = placeHoldersLen > 0 ? validLen - 4 : validLen;

  for (var i = 0; i < len; i += 4) {
    tmp = revLookup[b64.charCodeAt(i)] << 18 | revLookup[b64.charCodeAt(i + 1)] << 12 | revLookup[b64.charCodeAt(i + 2)] << 6 | revLookup[b64.charCodeAt(i + 3)];
    arr[curByte++] = tmp >> 16 & 0xFF;
    arr[curByte++] = tmp >> 8 & 0xFF;
    arr[curByte++] = tmp & 0xFF;
  }

  if (placeHoldersLen === 2) {
    tmp = revLookup[b64.charCodeAt(i)] << 2 | revLookup[b64.charCodeAt(i + 1)] >> 4;
    arr[curByte++] = tmp & 0xFF;
  }

  if (placeHoldersLen === 1) {
    tmp = revLookup[b64.charCodeAt(i)] << 10 | revLookup[b64.charCodeAt(i + 1)] << 4 | revLookup[b64.charCodeAt(i + 2)] >> 2;
    arr[curByte++] = tmp >> 8 & 0xFF;
    arr[curByte++] = tmp & 0xFF;
  }

  return arr;
}

function tripletToBase64(num) {
  return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F];
}

function encodeChunk(uint8, start, end) {
  var tmp;
  var output = [];

  for (var i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16 & 0xFF0000) + (uint8[i + 1] << 8 & 0xFF00) + (uint8[i + 2] & 0xFF);
    output.push(tripletToBase64(tmp));
  }

  return output.join('');
}

function fromByteArray(uint8) {
  var tmp;
  var len = uint8.length;
  var extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes

  var parts = [];
  var maxChunkLength = 16383; // must be multiple of 3
  // go through the array every three bytes, we'll deal with trailing stuff later

  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, i + maxChunkLength > len2 ? len2 : i + maxChunkLength));
  } // pad the end with zeros, but make sure to not forget the extra bytes


  if (extraBytes === 1) {
    tmp = uint8[len - 1];
    parts.push(lookup[tmp >> 2] + lookup[tmp << 4 & 0x3F] + '==');
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1];
    parts.push(lookup[tmp >> 10] + lookup[tmp >> 4 & 0x3F] + lookup[tmp << 2 & 0x3F] + '=');
  }

  return parts.join('');
}

/***/ }),

/***/ "./node_modules/buffer/index.js":
/*!**************************************!*\
  !*** ./node_modules/buffer/index.js ***!
  \**************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global) {/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */

/* eslint-disable no-proto */


var base64 = __webpack_require__(/*! base64-js */ "./node_modules/base64-js/index.js");

var ieee754 = __webpack_require__(/*! ieee754 */ "./node_modules/ieee754/index.js");

var isArray = __webpack_require__(/*! isarray */ "./node_modules/isarray/index.js");

exports.Buffer = Buffer;
exports.SlowBuffer = SlowBuffer;
exports.INSPECT_MAX_BYTES = 50;
/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Use Object implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * Due to various browser bugs, sometimes the Object implementation will be used even
 * when the browser supports typed arrays.
 *
 * Note:
 *
 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
 *
 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
 *
 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
 *     incorrect length in some situations.

 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
 * get the Object implementation, which is slower but behaves correctly.
 */

Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined ? global.TYPED_ARRAY_SUPPORT : typedArraySupport();
/*
 * Export kMaxLength after typed array support is determined.
 */

exports.kMaxLength = kMaxLength();

function typedArraySupport() {
  try {
    var arr = new Uint8Array(1);
    arr.__proto__ = {
      __proto__: Uint8Array.prototype,
      foo: function foo() {
        return 42;
      }
    };
    return arr.foo() === 42 && // typed array instances can be augmented
    typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
    arr.subarray(1, 1).byteLength === 0; // ie10 has broken `subarray`
  } catch (e) {
    return false;
  }
}

function kMaxLength() {
  return Buffer.TYPED_ARRAY_SUPPORT ? 0x7fffffff : 0x3fffffff;
}

function createBuffer(that, length) {
  if (kMaxLength() < length) {
    throw new RangeError('Invalid typed array length');
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = new Uint8Array(length);
    that.__proto__ = Buffer.prototype;
  } else {
    // Fallback: Return an object instance of the Buffer class
    if (that === null) {
      that = new Buffer(length);
    }

    that.length = length;
  }

  return that;
}
/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */


function Buffer(arg, encodingOrOffset, length) {
  if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
    return new Buffer(arg, encodingOrOffset, length);
  } // Common case.


  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error('If encoding is specified then the first argument must be a string');
    }

    return allocUnsafe(this, arg);
  }

  return from(this, arg, encodingOrOffset, length);
}

Buffer.poolSize = 8192; // not used by this implementation
// TODO: Legacy, not needed anymore. Remove in next major version.

Buffer._augment = function (arr) {
  arr.__proto__ = Buffer.prototype;
  return arr;
};

function from(that, value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number');
  }

  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    return fromArrayBuffer(that, value, encodingOrOffset, length);
  }

  if (typeof value === 'string') {
    return fromString(that, value, encodingOrOffset);
  }

  return fromObject(that, value);
}
/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/


Buffer.from = function (value, encodingOrOffset, length) {
  return from(null, value, encodingOrOffset, length);
};

if (Buffer.TYPED_ARRAY_SUPPORT) {
  Buffer.prototype.__proto__ = Uint8Array.prototype;
  Buffer.__proto__ = Uint8Array;

  if (typeof Symbol !== 'undefined' && Symbol.species && Buffer[Symbol.species] === Buffer) {
    // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
    Object.defineProperty(Buffer, Symbol.species, {
      value: null,
      configurable: true
    });
  }
}

function assertSize(size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number');
  } else if (size < 0) {
    throw new RangeError('"size" argument must not be negative');
  }
}

function alloc(that, size, fill, encoding) {
  assertSize(size);

  if (size <= 0) {
    return createBuffer(that, size);
  }

  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string' ? createBuffer(that, size).fill(fill, encoding) : createBuffer(that, size).fill(fill);
  }

  return createBuffer(that, size);
}
/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/


Buffer.alloc = function (size, fill, encoding) {
  return alloc(null, size, fill, encoding);
};

function allocUnsafe(that, size) {
  assertSize(size);
  that = createBuffer(that, size < 0 ? 0 : checked(size) | 0);

  if (!Buffer.TYPED_ARRAY_SUPPORT) {
    for (var i = 0; i < size; ++i) {
      that[i] = 0;
    }
  }

  return that;
}
/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */


Buffer.allocUnsafe = function (size) {
  return allocUnsafe(null, size);
};
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */


Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(null, size);
};

function fromString(that, string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8';
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding');
  }

  var length = byteLength(string, encoding) | 0;
  that = createBuffer(that, length);
  var actual = that.write(string, encoding);

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    that = that.slice(0, actual);
  }

  return that;
}

function fromArrayLike(that, array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0;
  that = createBuffer(that, length);

  for (var i = 0; i < length; i += 1) {
    that[i] = array[i] & 255;
  }

  return that;
}

function fromArrayBuffer(that, array, byteOffset, length) {
  array.byteLength; // this throws if `array` is not a valid ArrayBuffer

  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds');
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds');
  }

  if (byteOffset === undefined && length === undefined) {
    array = new Uint8Array(array);
  } else if (length === undefined) {
    array = new Uint8Array(array, byteOffset);
  } else {
    array = new Uint8Array(array, byteOffset, length);
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = array;
    that.__proto__ = Buffer.prototype;
  } else {
    // Fallback: Return an object instance of the Buffer class
    that = fromArrayLike(that, array);
  }

  return that;
}

function fromObject(that, obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0;
    that = createBuffer(that, len);

    if (that.length === 0) {
      return that;
    }

    obj.copy(that, 0, 0, len);
    return that;
  }

  if (obj) {
    if (typeof ArrayBuffer !== 'undefined' && obj.buffer instanceof ArrayBuffer || 'length' in obj) {
      if (typeof obj.length !== 'number' || isnan(obj.length)) {
        return createBuffer(that, 0);
      }

      return fromArrayLike(that, obj);
    }

    if (obj.type === 'Buffer' && isArray(obj.data)) {
      return fromArrayLike(that, obj.data);
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.');
}

function checked(length) {
  // Note: cannot use `length < kMaxLength()` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= kMaxLength()) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' + 'size: 0x' + kMaxLength().toString(16) + ' bytes');
  }

  return length | 0;
}

function SlowBuffer(length) {
  if (+length != length) {
    // eslint-disable-line eqeqeq
    length = 0;
  }

  return Buffer.alloc(+length);
}

Buffer.isBuffer = function isBuffer(b) {
  return !!(b != null && b._isBuffer);
};

Buffer.compare = function compare(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers');
  }

  if (a === b) return 0;
  var x = a.length;
  var y = b.length;

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i];
      y = b[i];
      break;
    }
  }

  if (x < y) return -1;
  if (y < x) return 1;
  return 0;
};

Buffer.isEncoding = function isEncoding(encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true;

    default:
      return false;
  }
};

Buffer.concat = function concat(list, length) {
  if (!isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers');
  }

  if (list.length === 0) {
    return Buffer.alloc(0);
  }

  var i;

  if (length === undefined) {
    length = 0;

    for (i = 0; i < list.length; ++i) {
      length += list[i].length;
    }
  }

  var buffer = Buffer.allocUnsafe(length);
  var pos = 0;

  for (i = 0; i < list.length; ++i) {
    var buf = list[i];

    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers');
    }

    buf.copy(buffer, pos);
    pos += buf.length;
  }

  return buffer;
};

function byteLength(string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length;
  }

  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' && (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
    return string.byteLength;
  }

  if (typeof string !== 'string') {
    string = '' + string;
  }

  var len = string.length;
  if (len === 0) return 0; // Use a for loop to avoid recursion

  var loweredCase = false;

  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len;

      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length;

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2;

      case 'hex':
        return len >>> 1;

      case 'base64':
        return base64ToBytes(string).length;

      default:
        if (loweredCase) return utf8ToBytes(string).length; // assume utf8

        encoding = ('' + encoding).toLowerCase();
        loweredCase = true;
    }
  }
}

Buffer.byteLength = byteLength;

function slowToString(encoding, start, end) {
  var loweredCase = false; // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.
  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.

  if (start === undefined || start < 0) {
    start = 0;
  } // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.


  if (start > this.length) {
    return '';
  }

  if (end === undefined || end > this.length) {
    end = this.length;
  }

  if (end <= 0) {
    return '';
  } // Force coersion to uint32. This will also coerce falsey/NaN values to 0.


  end >>>= 0;
  start >>>= 0;

  if (end <= start) {
    return '';
  }

  if (!encoding) encoding = 'utf8';

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end);

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end);

      case 'ascii':
        return asciiSlice(this, start, end);

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end);

      case 'base64':
        return base64Slice(this, start, end);

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end);

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding);
        encoding = (encoding + '').toLowerCase();
        loweredCase = true;
    }
  }
} // The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
// Buffer instances.


Buffer.prototype._isBuffer = true;

function swap(b, n, m) {
  var i = b[n];
  b[n] = b[m];
  b[m] = i;
}

Buffer.prototype.swap16 = function swap16() {
  var len = this.length;

  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits');
  }

  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1);
  }

  return this;
};

Buffer.prototype.swap32 = function swap32() {
  var len = this.length;

  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits');
  }

  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3);
    swap(this, i + 1, i + 2);
  }

  return this;
};

Buffer.prototype.swap64 = function swap64() {
  var len = this.length;

  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits');
  }

  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7);
    swap(this, i + 1, i + 6);
    swap(this, i + 2, i + 5);
    swap(this, i + 3, i + 4);
  }

  return this;
};

Buffer.prototype.toString = function toString() {
  var length = this.length | 0;
  if (length === 0) return '';
  if (arguments.length === 0) return utf8Slice(this, 0, length);
  return slowToString.apply(this, arguments);
};

Buffer.prototype.equals = function equals(b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer');
  if (this === b) return true;
  return Buffer.compare(this, b) === 0;
};

Buffer.prototype.inspect = function inspect() {
  var str = '';
  var max = exports.INSPECT_MAX_BYTES;

  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ');
    if (this.length > max) str += ' ... ';
  }

  return '<Buffer ' + str + '>';
};

Buffer.prototype.compare = function compare(target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer');
  }

  if (start === undefined) {
    start = 0;
  }

  if (end === undefined) {
    end = target ? target.length : 0;
  }

  if (thisStart === undefined) {
    thisStart = 0;
  }

  if (thisEnd === undefined) {
    thisEnd = this.length;
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index');
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0;
  }

  if (thisStart >= thisEnd) {
    return -1;
  }

  if (start >= end) {
    return 1;
  }

  start >>>= 0;
  end >>>= 0;
  thisStart >>>= 0;
  thisEnd >>>= 0;
  if (this === target) return 0;
  var x = thisEnd - thisStart;
  var y = end - start;
  var len = Math.min(x, y);
  var thisCopy = this.slice(thisStart, thisEnd);
  var targetCopy = target.slice(start, end);

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i];
      y = targetCopy[i];
      break;
    }
  }

  if (x < y) return -1;
  if (y < x) return 1;
  return 0;
}; // Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf


function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1; // Normalize byteOffset

  if (typeof byteOffset === 'string') {
    encoding = byteOffset;
    byteOffset = 0;
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff;
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000;
  }

  byteOffset = +byteOffset; // Coerce to Number.

  if (isNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : buffer.length - 1;
  } // Normalize byteOffset: negative offsets start from the end of the buffer


  if (byteOffset < 0) byteOffset = buffer.length + byteOffset;

  if (byteOffset >= buffer.length) {
    if (dir) return -1;else byteOffset = buffer.length - 1;
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0;else return -1;
  } // Normalize val


  if (typeof val === 'string') {
    val = Buffer.from(val, encoding);
  } // Finally, search either indexOf (if dir is true) or lastIndexOf


  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1;
    }

    return arrayIndexOf(buffer, val, byteOffset, encoding, dir);
  } else if (typeof val === 'number') {
    val = val & 0xFF; // Search for a byte value [0-255]

    if (Buffer.TYPED_ARRAY_SUPPORT && typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset);
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset);
      }
    }

    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir);
  }

  throw new TypeError('val must be string, number or Buffer');
}

function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
  var indexSize = 1;
  var arrLength = arr.length;
  var valLength = val.length;

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase();

    if (encoding === 'ucs2' || encoding === 'ucs-2' || encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1;
      }

      indexSize = 2;
      arrLength /= 2;
      valLength /= 2;
      byteOffset /= 2;
    }
  }

  function read(buf, i) {
    if (indexSize === 1) {
      return buf[i];
    } else {
      return buf.readUInt16BE(i * indexSize);
    }
  }

  var i;

  if (dir) {
    var foundIndex = -1;

    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i;
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize;
      } else {
        if (foundIndex !== -1) i -= i - foundIndex;
        foundIndex = -1;
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength;

    for (i = byteOffset; i >= 0; i--) {
      var found = true;

      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false;
          break;
        }
      }

      if (found) return i;
    }
  }

  return -1;
}

Buffer.prototype.includes = function includes(val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1;
};

Buffer.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
};

Buffer.prototype.lastIndexOf = function lastIndexOf(val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
};

function hexWrite(buf, string, offset, length) {
  offset = Number(offset) || 0;
  var remaining = buf.length - offset;

  if (!length) {
    length = remaining;
  } else {
    length = Number(length);

    if (length > remaining) {
      length = remaining;
    }
  } // must be an even number of digits


  var strLen = string.length;
  if (strLen % 2 !== 0) throw new TypeError('Invalid hex string');

  if (length > strLen / 2) {
    length = strLen / 2;
  }

  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16);
    if (isNaN(parsed)) return i;
    buf[offset + i] = parsed;
  }

  return i;
}

function utf8Write(buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length);
}

function asciiWrite(buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length);
}

function latin1Write(buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length);
}

function base64Write(buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length);
}

function ucs2Write(buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length);
}

Buffer.prototype.write = function write(string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8';
    length = this.length;
    offset = 0; // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset;
    length = this.length;
    offset = 0; // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset | 0;

    if (isFinite(length)) {
      length = length | 0;
      if (encoding === undefined) encoding = 'utf8';
    } else {
      encoding = length;
      length = undefined;
    } // legacy write(string, encoding, offset, length) - remove in v0.13

  } else {
    throw new Error('Buffer.write(string, encoding, offset[, length]) is no longer supported');
  }

  var remaining = this.length - offset;
  if (length === undefined || length > remaining) length = remaining;

  if (string.length > 0 && (length < 0 || offset < 0) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds');
  }

  if (!encoding) encoding = 'utf8';
  var loweredCase = false;

  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length);

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length);

      case 'ascii':
        return asciiWrite(this, string, offset, length);

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length);

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length);

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length);

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding);
        encoding = ('' + encoding).toLowerCase();
        loweredCase = true;
    }
  }
};

Buffer.prototype.toJSON = function toJSON() {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  };
};

function base64Slice(buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf);
  } else {
    return base64.fromByteArray(buf.slice(start, end));
  }
}

function utf8Slice(buf, start, end) {
  end = Math.min(buf.length, end);
  var res = [];
  var i = start;

  while (i < end) {
    var firstByte = buf[i];
    var codePoint = null;
    var bytesPerSequence = firstByte > 0xEF ? 4 : firstByte > 0xDF ? 3 : firstByte > 0xBF ? 2 : 1;

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint;

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte;
          }

          break;

        case 2:
          secondByte = buf[i + 1];

          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | secondByte & 0x3F;

            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint;
            }
          }

          break;

        case 3:
          secondByte = buf[i + 1];
          thirdByte = buf[i + 2];

          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | thirdByte & 0x3F;

            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint;
            }
          }

          break;

        case 4:
          secondByte = buf[i + 1];
          thirdByte = buf[i + 2];
          fourthByte = buf[i + 3];

          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | fourthByte & 0x3F;

            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint;
            }
          }

      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD;
      bytesPerSequence = 1;
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000;
      res.push(codePoint >>> 10 & 0x3FF | 0xD800);
      codePoint = 0xDC00 | codePoint & 0x3FF;
    }

    res.push(codePoint);
    i += bytesPerSequence;
  }

  return decodeCodePointsArray(res);
} // Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety


var MAX_ARGUMENTS_LENGTH = 0x1000;

function decodeCodePointsArray(codePoints) {
  var len = codePoints.length;

  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints); // avoid extra slice()
  } // Decode in chunks to avoid "call stack size exceeded".


  var res = '';
  var i = 0;

  while (i < len) {
    res += String.fromCharCode.apply(String, codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH));
  }

  return res;
}

function asciiSlice(buf, start, end) {
  var ret = '';
  end = Math.min(buf.length, end);

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F);
  }

  return ret;
}

function latin1Slice(buf, start, end) {
  var ret = '';
  end = Math.min(buf.length, end);

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i]);
  }

  return ret;
}

function hexSlice(buf, start, end) {
  var len = buf.length;
  if (!start || start < 0) start = 0;
  if (!end || end < 0 || end > len) end = len;
  var out = '';

  for (var i = start; i < end; ++i) {
    out += toHex(buf[i]);
  }

  return out;
}

function utf16leSlice(buf, start, end) {
  var bytes = buf.slice(start, end);
  var res = '';

  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256);
  }

  return res;
}

Buffer.prototype.slice = function slice(start, end) {
  var len = this.length;
  start = ~~start;
  end = end === undefined ? len : ~~end;

  if (start < 0) {
    start += len;
    if (start < 0) start = 0;
  } else if (start > len) {
    start = len;
  }

  if (end < 0) {
    end += len;
    if (end < 0) end = 0;
  } else if (end > len) {
    end = len;
  }

  if (end < start) end = start;
  var newBuf;

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    newBuf = this.subarray(start, end);
    newBuf.__proto__ = Buffer.prototype;
  } else {
    var sliceLen = end - start;
    newBuf = new Buffer(sliceLen, undefined);

    for (var i = 0; i < sliceLen; ++i) {
      newBuf[i] = this[i + start];
    }
  }

  return newBuf;
};
/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */


function checkOffset(offset, ext, length) {
  if (offset % 1 !== 0 || offset < 0) throw new RangeError('offset is not uint');
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length');
}

Buffer.prototype.readUIntLE = function readUIntLE(offset, byteLength, noAssert) {
  offset = offset | 0;
  byteLength = byteLength | 0;
  if (!noAssert) checkOffset(offset, byteLength, this.length);
  var val = this[offset];
  var mul = 1;
  var i = 0;

  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul;
  }

  return val;
};

Buffer.prototype.readUIntBE = function readUIntBE(offset, byteLength, noAssert) {
  offset = offset | 0;
  byteLength = byteLength | 0;

  if (!noAssert) {
    checkOffset(offset, byteLength, this.length);
  }

  var val = this[offset + --byteLength];
  var mul = 1;

  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul;
  }

  return val;
};

Buffer.prototype.readUInt8 = function readUInt8(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length);
  return this[offset];
};

Buffer.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length);
  return this[offset] | this[offset + 1] << 8;
};

Buffer.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length);
  return this[offset] << 8 | this[offset + 1];
};

Buffer.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length);
  return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 0x1000000;
};

Buffer.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length);
  return this[offset] * 0x1000000 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
};

Buffer.prototype.readIntLE = function readIntLE(offset, byteLength, noAssert) {
  offset = offset | 0;
  byteLength = byteLength | 0;
  if (!noAssert) checkOffset(offset, byteLength, this.length);
  var val = this[offset];
  var mul = 1;
  var i = 0;

  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul;
  }

  mul *= 0x80;
  if (val >= mul) val -= Math.pow(2, 8 * byteLength);
  return val;
};

Buffer.prototype.readIntBE = function readIntBE(offset, byteLength, noAssert) {
  offset = offset | 0;
  byteLength = byteLength | 0;
  if (!noAssert) checkOffset(offset, byteLength, this.length);
  var i = byteLength;
  var mul = 1;
  var val = this[offset + --i];

  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul;
  }

  mul *= 0x80;
  if (val >= mul) val -= Math.pow(2, 8 * byteLength);
  return val;
};

Buffer.prototype.readInt8 = function readInt8(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length);
  if (!(this[offset] & 0x80)) return this[offset];
  return (0xff - this[offset] + 1) * -1;
};

Buffer.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length);
  var val = this[offset] | this[offset + 1] << 8;
  return val & 0x8000 ? val | 0xFFFF0000 : val;
};

Buffer.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length);
  var val = this[offset + 1] | this[offset] << 8;
  return val & 0x8000 ? val | 0xFFFF0000 : val;
};

Buffer.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length);
  return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
};

Buffer.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length);
  return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
};

Buffer.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length);
  return ieee754.read(this, offset, true, 23, 4);
};

Buffer.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length);
  return ieee754.read(this, offset, false, 23, 4);
};

Buffer.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length);
  return ieee754.read(this, offset, true, 52, 8);
};

Buffer.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length);
  return ieee754.read(this, offset, false, 52, 8);
};

function checkInt(buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance');
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
  if (offset + ext > buf.length) throw new RangeError('Index out of range');
}

Buffer.prototype.writeUIntLE = function writeUIntLE(value, offset, byteLength, noAssert) {
  value = +value;
  offset = offset | 0;
  byteLength = byteLength | 0;

  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1;
    checkInt(this, value, offset, byteLength, maxBytes, 0);
  }

  var mul = 1;
  var i = 0;
  this[offset] = value & 0xFF;

  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = value / mul & 0xFF;
  }

  return offset + byteLength;
};

Buffer.prototype.writeUIntBE = function writeUIntBE(value, offset, byteLength, noAssert) {
  value = +value;
  offset = offset | 0;
  byteLength = byteLength | 0;

  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1;
    checkInt(this, value, offset, byteLength, maxBytes, 0);
  }

  var i = byteLength - 1;
  var mul = 1;
  this[offset + i] = value & 0xFF;

  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = value / mul & 0xFF;
  }

  return offset + byteLength;
};

Buffer.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0);
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
  this[offset] = value & 0xff;
  return offset + 1;
};

function objectWriteUInt16(buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffff + value + 1;

  for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; ++i) {
    buf[offset + i] = (value & 0xff << 8 * (littleEndian ? i : 1 - i)) >>> (littleEndian ? i : 1 - i) * 8;
  }
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value & 0xff;
    this[offset + 1] = value >>> 8;
  } else {
    objectWriteUInt16(this, value, offset, true);
  }

  return offset + 2;
};

Buffer.prototype.writeUInt16BE = function writeUInt16BE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value >>> 8;
    this[offset + 1] = value & 0xff;
  } else {
    objectWriteUInt16(this, value, offset, false);
  }

  return offset + 2;
};

function objectWriteUInt32(buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffffffff + value + 1;

  for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; ++i) {
    buf[offset + i] = value >>> (littleEndian ? i : 3 - i) * 8 & 0xff;
  }
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset + 3] = value >>> 24;
    this[offset + 2] = value >>> 16;
    this[offset + 1] = value >>> 8;
    this[offset] = value & 0xff;
  } else {
    objectWriteUInt32(this, value, offset, true);
  }

  return offset + 4;
};

Buffer.prototype.writeUInt32BE = function writeUInt32BE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value >>> 24;
    this[offset + 1] = value >>> 16;
    this[offset + 2] = value >>> 8;
    this[offset + 3] = value & 0xff;
  } else {
    objectWriteUInt32(this, value, offset, false);
  }

  return offset + 4;
};

Buffer.prototype.writeIntLE = function writeIntLE(value, offset, byteLength, noAssert) {
  value = +value;
  offset = offset | 0;

  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1);
    checkInt(this, value, offset, byteLength, limit - 1, -limit);
  }

  var i = 0;
  var mul = 1;
  var sub = 0;
  this[offset] = value & 0xFF;

  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1;
    }

    this[offset + i] = (value / mul >> 0) - sub & 0xFF;
  }

  return offset + byteLength;
};

Buffer.prototype.writeIntBE = function writeIntBE(value, offset, byteLength, noAssert) {
  value = +value;
  offset = offset | 0;

  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1);
    checkInt(this, value, offset, byteLength, limit - 1, -limit);
  }

  var i = byteLength - 1;
  var mul = 1;
  var sub = 0;
  this[offset + i] = value & 0xFF;

  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1;
    }

    this[offset + i] = (value / mul >> 0) - sub & 0xFF;
  }

  return offset + byteLength;
};

Buffer.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80);
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
  if (value < 0) value = 0xff + value + 1;
  this[offset] = value & 0xff;
  return offset + 1;
};

Buffer.prototype.writeInt16LE = function writeInt16LE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value & 0xff;
    this[offset + 1] = value >>> 8;
  } else {
    objectWriteUInt16(this, value, offset, true);
  }

  return offset + 2;
};

Buffer.prototype.writeInt16BE = function writeInt16BE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value >>> 8;
    this[offset + 1] = value & 0xff;
  } else {
    objectWriteUInt16(this, value, offset, false);
  }

  return offset + 2;
};

Buffer.prototype.writeInt32LE = function writeInt32LE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000);

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value & 0xff;
    this[offset + 1] = value >>> 8;
    this[offset + 2] = value >>> 16;
    this[offset + 3] = value >>> 24;
  } else {
    objectWriteUInt32(this, value, offset, true);
  }

  return offset + 4;
};

Buffer.prototype.writeInt32BE = function writeInt32BE(value, offset, noAssert) {
  value = +value;
  offset = offset | 0;
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000);
  if (value < 0) value = 0xffffffff + value + 1;

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = value >>> 24;
    this[offset + 1] = value >>> 16;
    this[offset + 2] = value >>> 8;
    this[offset + 3] = value & 0xff;
  } else {
    objectWriteUInt32(this, value, offset, false);
  }

  return offset + 4;
};

function checkIEEE754(buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range');
  if (offset < 0) throw new RangeError('Index out of range');
}

function writeFloat(buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38);
  }

  ieee754.write(buf, value, offset, littleEndian, 23, 4);
  return offset + 4;
}

Buffer.prototype.writeFloatLE = function writeFloatLE(value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert);
};

Buffer.prototype.writeFloatBE = function writeFloatBE(value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert);
};

function writeDouble(buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308);
  }

  ieee754.write(buf, value, offset, littleEndian, 52, 8);
  return offset + 8;
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE(value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert);
};

Buffer.prototype.writeDoubleBE = function writeDoubleBE(value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert);
}; // copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)


Buffer.prototype.copy = function copy(target, targetStart, start, end) {
  if (!start) start = 0;
  if (!end && end !== 0) end = this.length;
  if (targetStart >= target.length) targetStart = target.length;
  if (!targetStart) targetStart = 0;
  if (end > 0 && end < start) end = start; // Copy 0 bytes; we're done

  if (end === start) return 0;
  if (target.length === 0 || this.length === 0) return 0; // Fatal error conditions

  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds');
  }

  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds');
  if (end < 0) throw new RangeError('sourceEnd out of bounds'); // Are we oob?

  if (end > this.length) end = this.length;

  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start;
  }

  var len = end - start;
  var i;

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start];
    }
  } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
    // ascending copy from start
    for (i = 0; i < len; ++i) {
      target[i + targetStart] = this[i + start];
    }
  } else {
    Uint8Array.prototype.set.call(target, this.subarray(start, start + len), targetStart);
  }

  return len;
}; // Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])


Buffer.prototype.fill = function fill(val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start;
      start = 0;
      end = this.length;
    } else if (typeof end === 'string') {
      encoding = end;
      end = this.length;
    }

    if (val.length === 1) {
      var code = val.charCodeAt(0);

      if (code < 256) {
        val = code;
      }
    }

    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string');
    }

    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding);
    }
  } else if (typeof val === 'number') {
    val = val & 255;
  } // Invalid ranges are not set to a default, so can range check early.


  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index');
  }

  if (end <= start) {
    return this;
  }

  start = start >>> 0;
  end = end === undefined ? this.length : end >>> 0;
  if (!val) val = 0;
  var i;

  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val;
    }
  } else {
    var bytes = Buffer.isBuffer(val) ? val : utf8ToBytes(new Buffer(val, encoding).toString());
    var len = bytes.length;

    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len];
    }
  }

  return this;
}; // HELPER FUNCTIONS
// ================


var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g;

function base64clean(str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = stringtrim(str).replace(INVALID_BASE64_RE, ''); // Node converts strings with length < 2 to ''

  if (str.length < 2) return ''; // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not

  while (str.length % 4 !== 0) {
    str = str + '=';
  }

  return str;
}

function stringtrim(str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
}

function toHex(n) {
  if (n < 16) return '0' + n.toString(16);
  return n.toString(16);
}

function utf8ToBytes(string, units) {
  units = units || Infinity;
  var codePoint;
  var length = string.length;
  var leadSurrogate = null;
  var bytes = [];

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i); // is surrogate component

    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
          continue;
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
          continue;
        } // valid lead


        leadSurrogate = codePoint;
        continue;
      } // 2 leads in a row


      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
        leadSurrogate = codePoint;
        continue;
      } // valid surrogate pair


      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000;
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
    }

    leadSurrogate = null; // encode utf8

    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break;
      bytes.push(codePoint);
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break;
      bytes.push(codePoint >> 0x6 | 0xC0, codePoint & 0x3F | 0x80);
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break;
      bytes.push(codePoint >> 0xC | 0xE0, codePoint >> 0x6 & 0x3F | 0x80, codePoint & 0x3F | 0x80);
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break;
      bytes.push(codePoint >> 0x12 | 0xF0, codePoint >> 0xC & 0x3F | 0x80, codePoint >> 0x6 & 0x3F | 0x80, codePoint & 0x3F | 0x80);
    } else {
      throw new Error('Invalid code point');
    }
  }

  return bytes;
}

function asciiToBytes(str) {
  var byteArray = [];

  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF);
  }

  return byteArray;
}

function utf16leToBytes(str, units) {
  var c, hi, lo;
  var byteArray = [];

  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break;
    c = str.charCodeAt(i);
    hi = c >> 8;
    lo = c % 256;
    byteArray.push(lo);
    byteArray.push(hi);
  }

  return byteArray;
}

function base64ToBytes(str) {
  return base64.toByteArray(base64clean(str));
}

function blitBuffer(src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if (i + offset >= dst.length || i >= src.length) break;
    dst[i + offset] = src[i];
  }

  return i;
}

function isnan(val) {
  return val !== val; // eslint-disable-line no-self-compare
}
/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(/*! ./../webpack/buildin/global.js */ "./node_modules/webpack/buildin/global.js")))

/***/ }),

/***/ "./node_modules/ieee754/index.js":
/*!***************************************!*\
  !*** ./node_modules/ieee754/index.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports) {

exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m;
  var eLen = nBytes * 8 - mLen - 1;
  var eMax = (1 << eLen) - 1;
  var eBias = eMax >> 1;
  var nBits = -7;
  var i = isLE ? nBytes - 1 : 0;
  var d = isLE ? -1 : 1;
  var s = buffer[offset + i];
  i += d;
  e = s & (1 << -nBits) - 1;
  s >>= -nBits;
  nBits += eLen;

  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & (1 << -nBits) - 1;
  e >>= -nBits;
  nBits += mLen;

  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias;
  } else if (e === eMax) {
    return m ? NaN : (s ? -1 : 1) * Infinity;
  } else {
    m = m + Math.pow(2, mLen);
    e = e - eBias;
  }

  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
};

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c;
  var eLen = nBytes * 8 - mLen - 1;
  var eMax = (1 << eLen) - 1;
  var eBias = eMax >> 1;
  var rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0;
  var i = isLE ? 0 : nBytes - 1;
  var d = isLE ? 1 : -1;
  var s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
  value = Math.abs(value);

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0;
    e = eMax;
  } else {
    e = Math.floor(Math.log(value) / Math.LN2);

    if (value * (c = Math.pow(2, -e)) < 1) {
      e--;
      c *= 2;
    }

    if (e + eBias >= 1) {
      value += rt / c;
    } else {
      value += rt * Math.pow(2, 1 - eBias);
    }

    if (value * c >= 2) {
      e++;
      c /= 2;
    }

    if (e + eBias >= eMax) {
      m = 0;
      e = eMax;
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen);
      e = e + eBias;
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
      e = 0;
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = e << mLen | m;
  eLen += mLen;

  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128;
};

/***/ }),

/***/ "./node_modules/isarray/index.js":
/*!***************************************!*\
  !*** ./node_modules/isarray/index.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports) {

var toString = {}.toString;

module.exports = Array.isArray || function (arr) {
  return toString.call(arr) == '[object Array]';
};

/***/ }),

/***/ "./node_modules/webpack/buildin/global.js":
/*!***********************************!*\
  !*** (webpack)/buildin/global.js ***!
  \***********************************/
/*! no static exports found */
/***/ (function(module, exports) {

function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

var g; // This works in non-strict mode

g = function () {
  return this;
}();

try {
  // This works if eval is allowed (see CSP)
  g = g || new Function("return this")();
} catch (e) {
  // This works if the window reference is available
  if ((typeof window === "undefined" ? "undefined" : _typeof(window)) === "object") g = window;
} // g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}


module.exports = g;

/***/ })

/******/ });
//# sourceMappingURL=jose.js.map