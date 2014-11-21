Javascript library for Jose JWE
===============================

Overview
--------
JavaScript library to encrypt data in JSON Web Encryption (JWE) format.

Note: this library currently only implements a subset of the JWE spec. For
example, the code only performs encryption.

The library uses the Web Crypto API, which is available in recent browsers
(http://caniuse.com/#feat=cryptographyexists). As of Nov 2014, it seems ~50%
of users have some form of Web Crypto support.

This code has been tested in Chrome 38 and with our Golang code for decryption.

JSON web encryption is currently a set of draft. This code is based on the
following versions of the drafts:

* https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-36
* https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-36
* https://tools.ietf.org/html/draft-ietf-jose-json-web-key-36
* https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36

Example usage
-------------

    <script src="jose-jwe.js"></script>
    <script src="jose-jwe-encrypt.js"></script>
    <script src="jose-jwe-utils.js"></script>
    var joseJWE = new JoseJWE();
    var rsa_key = JoseJWE.Utils.importRsaKeyFromHex({
    	"n": "c2:4b:af:0f:2d:2b:ad:36:72:a7:91:0f:ee:30:a0:95:d5:3a:46:82:86:96:7e:42:c6:fe:8f:20:97:af:49:f6:48:a3:91:53:ac:2e:e6:ec:9a:9a:e0:0a:fb:1c:db:44:40:5b:8c:fc:d5:1c:cb:b6:9b:60:c0:a8:ac:06:f1:6b:29:5e:2f:7b:09:d9:93:32:da:3f:db:53:9c:2e:ea:3b:41:7f:6b:c9:7b:88:9f:2e:c5:dd:42:1e:7f:8f:04:f6:60:3c:fe:43:6d:32:10:ce:8d:99:cb:76:f7:10:97:05:af:28:1e:39:0f:78:35:50:7b:8e:28:22:a4:7d:11:51:22:d1:0e:ab:6b:6f:96:cb:cf:7d:eb:c6:aa:a2:6a:2e:97:2a:93:af:a5:89:e6:c8:bc:9f:fd:85:2b:0f:b4:c0:e4:ca:b5:a7:9a:01:05:81:93:6b:f5:8d:1c:f7:f3:77:0e:6e:53:34:92:0f:48:21:34:33:44:14:5e:4a:00:41:3a:7d:cb:38:82:c1:65:e0:79:ea:a1:05:84:b2:6e:40:19:77:1a:0e:38:4b:28:1f:34:b5:cb:ac:c5:2f:58:51:d7:ec:a8:08:0e:7c:c0:20:c1:5e:a1:4d:b1:30:17:63:0e:e7:58:8e:7f:6e:9f:a4:77:8b:1e:a2:d2:2e:1b:e9",
        "e": 65537
    }, ["encrypt"]);
    joseJWE.encrypt(rsa_key, plaintext.textContent).then(function(result) {
    	console.log(result);
    }).catch(function(err){
    	console.error(err);
    });


Encrypton algorithms used by this library
-----------------------------------------

Key Encryption:

* RSA-OAEP (default)
* RSA-OAEP-256
* A128KW (not recommended for use)
* A256KW (not recommended for use)

Content Encryption:

* A128CBC-HS256
* A256CBC-HS512
* A128GCM
* A256GCM (default)


Some background info
--------------------

The Web Crypto API is still pretty new and isn't very well documented. The
following resources are useful:

* [www.w3.org](http://www.w3.org/TR/WebCryptoAPI/)
* [msdn.microsoft.com](http://msdn.microsoft.com/en-us/library/ie/dn302338(v=vs.85).aspx)
* [docs.google.com](https://docs.google.com/document/d/184AgXzLAoUjQjrtNdbimceyXVYzrn3tGpf3xQGCN10g)

Note: Internet Explorer's Web Crypto API differs from Chrome's. This library
probably needs a thin abstraction layer.

Some other interesting resources:

* Web Crypto API polyfill (_no longer under active development_): http://polycrypt.net/ 
* Netflix' Web Crypto API polyfill: https://github.com/Netflix/NfWebCrypto 
* JWT: https://github.com/michaelrhanson/jwt-js
* BigInt, RSA, ECC: http://www-cs-students.stanford.edu/~tjw/jsbn/
* asn1, pem, x509 and more: http://kjur.github.io/jsrsasign/ and
  https://github.com/michaelrhanson/jwt-js/tree/master/lib/kurushima-jsrsa 
* Stanford Javascript Crypto library: https://github.com/bitwiseshiftleft/sjcl
