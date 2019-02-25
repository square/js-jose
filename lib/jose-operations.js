/**
 * Check if the given parameter is a string.
 * 
 * @param {*} str 
 * @returns boolean
 */
export const isString = (str) => {
  return ((typeof(str) == "string") || (str instanceof String));
};

/**
 * Takes an arrayish (an array, ArrayBuffer or Uint8Array)
 * and returns an array or a Uint8Array.
 *
 * @param arr  arrayish
 * @return array or Uint8Array
 */
export const arrayish = (arr) => {
  if (arr instanceof Array) {
    return arr;
  }
  if (arr instanceof Uint8Array) {
    return arr;
  }
  if (arr instanceof ArrayBuffer) {
    return new Uint8Array(arr);
  }
  assert(false, "arrayish: invalid input");
};

/**
 * Converts a string into an array of ascii codes.
 *
 * @param str  ascii string
 * @return Uint8Array
 */
export const arrayFromString = (str) => {
  assert(isString(str), "arrayFromString: invalid input");
  var arr = str.split('').map(function(c) {
    return c.charCodeAt(0);
  });
  return new Uint8Array(arr);
};

/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  arrayish
 * @return ascii string
 */
export const stringFromArray = (arr) => {
  arr = arrayish(arr);
  var r = '';
  for (var i = 0; i < arr.length; i++) {
    r += String.fromCharCode(arr[i]);
  }

  return r;
};

/**
 * Converts a string into an array of utf-8 codes.
 *
* @param str  utf-8 string
 * @return Uint8Array
 */
export const arrayFromUtf8String = (str) => {
  assert(isString(str), "arrayFromUtf8String: invalid input");
  // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.
  str = unescape(encodeURIComponent(str));
  return arrayFromString(str);
};

/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  ArrayBuffer
 * @return ascii string
 */
export const utf8StringFromArray = (arr) => {
  assert(arr instanceof ArrayBuffer, "utf8StringFromArray: invalid input");

  // javascript represents strings as utf-16. Jose imposes the use of
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
export const stripLeadingZeros = (arr) => {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }
  var is_leading_zero = true;
  var r = [];
  for (var i = 0; i < arr.length; i++) {
    if (is_leading_zero && arr[i] === 0) {
      continue;
    }
    is_leading_zero = false;
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
export const arrayFromInt32 = (i) => {
  assert(typeof(i) == "number", "arrayFromInt32: invalid input");
  assert(i == i | 0, "arrayFromInt32: out of range");

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
export function arrayBufferConcat( /* ... */){
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
  assert(offset == total, "arrayBufferConcat: unexpected offset");
  return r;
}

export const sha256 = (str) => {
  // Browser docs indicate the first parameter to crypto.subtle.digest to be a
  // DOMString. This was initially implemented as an object and continues to be
  // supported, so we favor the older form for backwards compatibility.
  return Jose.crypto.subtle.digest({name: "SHA-256"}, arrayFromString(str)).then(function(hash) {
    return this.encodeArray(hash);
  });
};

export const isCryptoKey = (rsa_key) => {
  // Some browsers don't expose the CryptoKey as an object, so we need to check
  // the constructor's name.
  if (rsa_key.constructor.name == 'CryptoKey') {
    return true;
  }

  // In the presence of minifiers, relying on class names can be problematic,
  // so let's also allow objects that have an 'algorithm' property.
  if (rsa_key.hasOwnProperty('algorithm')) {
    return true;
  }

  return false;
};

/**
 * Feel free to override this function.
 */
const assert = (expr, msg) => {
  if (!expr) {
    throw new Error(msg);
  }
};

export class Base64Url {
  /**
   * Base64Url encodes a string (no trailing '=')
   *
   * @param str  string
   * @return string
   */
  encode(str) {
    assert(isString(str), "Base64Url.encode: invalid input");
    return btoa(str)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  /**
   * Base64Url encodes an array
   *
   * @param arr array or ArrayBuffer
   * @return string
   */
  encodeArray(arr) {
    return this.encode(stringFromArray(arr));
  }

  /**
   * Base64Url decodes a string
   *
   * @param str  string
   * @return string
   */
  decode(str) {
    assert(isString(str), "Base64Url.decode: invalid input");
    // atob is nice and ignores missing '='
    return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  }

  decodeArray(str) {
    assert(isString(str), "Base64Url.decodeArray: invalid input");
    return arrayFromString(this.decode(str));
  }
}
