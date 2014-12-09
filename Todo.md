
TODO List
=========

* improve README. Explain the purpose of doing crypto in the browser.
* make sure code works on all browsers which implement Web Crypto API
* implement polyfill for older browsers
  * inject entropy from server side (e.g. <div id="entropy">...bytes...</div>)
* add more tests
* unittest coverage maps
* address all TODOs
* improve error handling. Use Promise everywhere instead of throwing
  (exceptions become Promise.reject anyways).
