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
export class Base64Url {
  /**
   * Base64Url encodes an array (no trailing '=', and '+/' are replaced by '-_')
   */
  static encode(arr: ArrayLike<number>): string {
    var str = String.fromCharCode.apply(null, arr);
    return btoa(str)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  /**
   * Base64Url decodes a string
   */
  static decode(str: string): Uint8Array {
    // atob is nice and ignores missing '='
    str = atob(str.replace(/-/g, "+").replace(/_/g,"/"));

    return new Uint8Array(str.split('').map(c => c.charCodeAt(0)));
  }
}
