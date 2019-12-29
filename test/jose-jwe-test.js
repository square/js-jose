QUnit.test('encryption using RSAES OAEP and AES GCM (keys & IV from appendix-A.1)', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.createIV = () => {
    return new Uint8Array([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
  };
  cryptographer.createCek = () => {
    const cek = new Uint8Array([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]);
    return crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, true, ['encrypt']);
  };
  const rsaKey =
  {
    'kty': 'RSA',
    'n': 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW' +
      'cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S' +
      'psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a' +
      'sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS' +
      'tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj' +
      'YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
    'e': 'AQAB',
    'd': 'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N' +
      'WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9' +
      '3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk' +
      'qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl' +
      't3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd' +
      'VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
    'p': '1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-' +
      'SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf' +
      'fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0',
    'q': 'wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm' +
      'UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX' +
      'IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc',
    'dp': 'ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL' +
      'hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827' +
      'rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE',
    'dq': 'Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj' +
      'ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB' +
      'UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis',
    'qi': 'VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7' +
      'AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3' +
      'eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY'
  };
  const publicRsaKey = Jose.Utils.importRsaPublicKey(rsaKey, 'RSA-OAEP');
  const plaintext = 'The true sign of intelligence is not knowledge but imagination.';
  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, publicRsaKey);
  const cipherTextPromise = encrypter.encrypt(plaintext);

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.').length; }),
    5, 'got right number of components');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[0]; }),
    'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ',
    'got expected header');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[2]; }),
    '48V1_ALb6US04U3b',
    'got expected IV');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[3]; }),
    '5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A',
    'got expected cipher text');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[4]; }),
    'XFBoMYUZodetZdvTiFvSkQ',
    'got expected tag');

  const privateRsaKey = Jose.Utils.importRsaPrivateKey(rsaKey, 'RSA-OAEP');
  const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, privateRsaKey);
  const decryptedPlaintextPromise = cipherTextPromise.then(function (ciphertext) {
    return decrypter.decrypt(ciphertext);
  });
  assert.willEqual(decryptedPlaintextPromise, plaintext, 'Error: got expected decrypted plain text');

  // Modify string and check for invalid tag
  const macFailure = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.');
    ciphertext.pop();
    ciphertext.push('WFBoMYUZodetZdvTiFvSkQ');
    return decrypter.decrypt(ciphertext.join('.'));
  });
  assert.wont(macFailure, 'invalid tag did not cause failure');
});

// We can't test appendix-A.2 because Chrome dropped support for RSAES-PKCS1-V1_5.
QUnit.test('encryption using AES Key Wrap and AES_128_CBC_HMAC_SHA_256 (keys & IV from appendix-A.3)', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('A128KW');
  cryptographer.setContentEncryptionAlgorithm('A128CBC-HS256');

  cryptographer.createIV = function () {
    return new Uint8Array([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]);
  };
  cryptographer.createCek = function () {
    const cek = new Uint8Array([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207]);
    return crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, true, ['encrypt']);
  };
  let sharedKey = { 'kty': 'oct', 'k': 'GawgguFyGrWKav7AX4VKUg' };
  sharedKey = crypto.subtle.importKey('jwk', sharedKey, { name: 'AES-KW' }, true, ['wrapKey', 'unwrapKey']);

  const plaintext = 'Live long and prosper.';
  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, sharedKey);
  const cipherTextPromise = encrypter.encrypt(plaintext);

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.').length; }),
    5, 'got right number of components');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[0]; }),
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    'got expected header');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[1]; }),
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    'got expected encrypted key');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[2]; }),
    'AxY8DCtDaGlsbGljb3RoZQ',
    'got expected IV');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[3]; }),
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    'got expected cipher text');

  assert.willEqual(cipherTextPromise.then(function (result) { return result.split('.')[4]; }),
    'U0m_YmjN04DJvceFICbCVQ',
    'got expected tag');

  const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, sharedKey);
  const decryptedPlaintextPromise = cipherTextPromise.then(function (ciphertext) {
    return decrypter.decrypt(ciphertext);
  });
  assert.willEqual(decryptedPlaintextPromise, plaintext, 'got expected decrypted plain text');

  // Modify string and check for invalid tag
  const macFailure = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.');
    ciphertext.pop();
    ciphertext.push('WEm_YmjN04DJvceFICbCVQ');
    return decrypter.decrypt(ciphertext.join('.'));
  });
  assert.wontEqual(macFailure, 'Error: decryptCiphertext: MAC failed.', 'invalid tag did not cause failure');
});

QUnit.test('key import', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setContentEncryptionAlgorithm('A128CBC-HS256');

  // Key was generated with: `openssl genrsa 1024 | openssl rsa -text`
  const rsaKey = {
    'e': 65537,
    'n': '00:bf:53:bf:5b:19:bc:80:5c:88:15:d8:a5:f7:70:cf:c7:0c:aa:f5:b4:07:b8:d1:7b:3a:34:fc:b3:d8:25:46:86:58:5a:d5:69:49:8d:83:23:cd:e2:87:cd:4a:6d:39:a6:8a:dd:dd:c2:e4:d0:ce:7b:a3:d8:28:f8:f0:af:eb:87:2f:f5:c5:bc:5b:c2:08:ec:67:8a:96:57:bb:b6:6b:b5:a2:7d:ab:ff:67:13:09:1b:32:ba:89:c2:27:fd:1b:00:8b:1b:a0:44:3f:a5:4c:39:75:cd:dd:be:75:e6:c7:a5:4f:27:e3:e8:91:0b:1f:38:b7:f5:f7:03:88:f5:1e:b5',
    'd': '0d:f4:61:c4:97:3f:f4:6c:cb:50:2c:99:0e:4f:20:18:78:88:0f:9b:ad:e4:81:02:e7:df:ed:7e:80:89:57:77:7d:02:43:06:86:e2:d7:69:c9:1e:78:a1:34:88:7a:e7:f6:c0:ef:e7:c3:20:a7:ae:c4:e8:83:34:84:f9:8f:c8:10:22:b5:19:ad:07:de:18:5d:d2:ff:27:c2:a7:42:1b:9a:6b:64:43:75:6e:e7:6d:5e:3a:77:fd:2a:65:18:a5:e9:46:79:ea:50:60:a9:27:21:7b:da:71:9b:00:0d:07:63:0f:e4:a7:f7:d7:3c:32:19:b2:73:a5:2b:24:8d:01',
    'p': '00:de:16:f5:44:0a:bf:b5:4c:00:ce:1b:fe:e9:33:6b:47:66:0e:f9:a8:b1:44:ee:54:3f:1c:51:0d:36:fb:40:3a:53:61:46:3b:63:ee:6b:95:54:1d:b2:49:30:47:92:fd:b7:69:87:a5:f0:91:ab:16:ed:1d:0a:c3:ee:27:3c:71',
    'q': '00:dc:8a:57:d7:1a:ba:2d:e9:07:39:bf:64:ef:b2:f2:91:20:6c:32:4b:0d:15:2e:78:ab:a5:99:c5:4f:25:40:cc:8a:9c:d4:f5:3d:ab:a7:e1:e6:d4:97:90:66:bc:fb:45:af:c6:84:1d:1c:56:f6:18:7a:b2:81:27:e3:fa:38:85',
    'dp': '00:9b:4b:2e:61:4f:aa:d1:98:bd:8f:61:a0:13:6c:b2:fd:0f:ee:34:c0:b2:83:e2:aa:e2:1e:68:c6:76:c5:a5:19:a3:a8:07:36:0c:20:70:f5:d0:05:9b:de:f5:75:76:e1:16:59:22:52:f4:2e:c7:95:96:63:92:5d:82:af:c8:e1',
    'dq': '74:1d:fb:05:ec:b2:9e:3d:95:6a:58:55:82:c7:4b:64:12:18:25:9a:d2:76:96:93:3e:7c:e0:ab:bc:72:36:dd:fb:15:7c:22:eb:a7:97:ab:1f:68:4b:ac:e2:0b:1a:99:a4:64:f7:66:84:67:5d:07:a2:82:9d:f2:2c:dc:b0:29',
    'qi': '0c:c8:32:20:2e:df:d7:85:0f:e6:50:ec:ba:1b:6f:60:dd:18:79:3f:d4:ac:d8:6c:bf:05:d7:68:11:3f:2e:1b:26:d5:63:9d:c7:02:0f:e0:c2:70:49:c9:d1:7b:68:66:da:17:36:f5:f2:6b:4e:06:bd:db:29:04:c6:34:7a:e0'
  };

  const publicRsaKey = Jose.Utils.importRsaPublicKey(rsaKey, 'RSA-OAEP');
  const plaintext = 'Look deep into nature, and then you will understand everything better. --Albert Einstein';
  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, publicRsaKey);
  const cipherTextPromise = encrypter.encrypt(plaintext);

  const privateRsaKey = Jose.Utils.importRsaPrivateKey(rsaKey, 'RSA-OAEP');
  const decryptedPlaintextPromise = cipherTextPromise.then(function (ciphertext) {
    const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, privateRsaKey);
    return decrypter.decrypt(ciphertext);
  });
  assert.willEqual(decryptedPlaintextPromise, plaintext, 'got expected decrypted plain text');
});

QUnit.test('extra headers', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('A128KW');
  let sharedKey = { 'kty': 'oct', 'k': 'GawgguFyGrWKav7AX4VKUg' };
  sharedKey = crypto.subtle.importKey('jwk', sharedKey, cryptographer.keyEncryption.id, true, ['wrapKey', 'unwrapKey']);
  const plaintext = 'I only went out for a walk and finally concluded to stay out till sundown, for going out, I found, was really going in. --John Muir';

  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, sharedKey);
  encrypter.addHeader('cty', 'text/plain');
  const cipherTextPromise = encrypter.encrypt(plaintext);

  const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, sharedKey);
  const decryptedPlaintextPromise = cipherTextPromise.then(function (ciphertext) {
    return decrypter.decrypt(ciphertext);
  });
  assert.willEqual(decryptedPlaintextPromise.then(function (_) { return decrypter.getHeaders()['cty']; }), 'text/plain', 'got expected header');
});

QUnit.test('RSA-OAEP-256 with A256CBC-HS512', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('RSA-OAEP-256');
  cryptographer.setContentEncryptionAlgorithm('A256CBC-HS512');
  const keyPromise = crypto.subtle.generateKey({
    name: 'RSA-OAEP',
    hash: { name: 'SHA-256' },
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01])
  }, false, ['wrapKey', 'unwrapKey']);
  const plaintext = 'Always remember that you are absolutely unique. Just like everyone else. --Margaret Mead';

  const decryptedPlaintextPromise = keyPromise.then(function (key) {
    const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, Promise.resolve(key.publicKey));
    return encrypter.encrypt(plaintext).then(function (ciphertext) {
      const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, Promise.resolve(key.privateKey));
      return decrypter.decrypt(ciphertext);
    });
  });
  assert.willEqual(decryptedPlaintextPromise, plaintext, 'got expected decrypted plain text');
});

QUnit.test('A256KW with A128GCM', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('A256KW');
  cryptographer.setContentEncryptionAlgorithm('A128GCM');

  let sharedKey = { 'kty': 'oct', 'k': 'GawgguFyGrWKav7AX4VKUg' };
  sharedKey = crypto.subtle.importKey('jwk', sharedKey, cryptographer.keyEncryption.id, true, ['wrapKey', 'unwrapKey']);

  const plaintext = 'All generalizations are false, including this one.  --Mark Twain';
  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, sharedKey);
  const cipherTextPromise = encrypter.encrypt(plaintext);

  const decryptedPlaintextPromise = cipherTextPromise.then(function (ciphertext) {
    const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, sharedKey);
    return decrypter.decrypt(ciphertext);
  });
  assert.willEqual(decryptedPlaintextPromise, plaintext, 'got expected decrypted plain text');
});

QUnit.test('direct A256GCM', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('dir');

  const sharedJwk = { 'alg': 'A256GCM', 'ext': true, 'k': 'Wx5b1Z2nZFgZ8wrEXHo497ZWuvpej1m3PVCgTReiMic', 'key_ops': ['encrypt', 'decrypt'], 'kty': 'oct' };
  const plaintext = "Idealism increases in direct proportion to one's distance from the problem. --John Galsworthy";
  let sharedKey;

  var roundtrip = crypto.subtle.importKey('jwk', sharedJwk, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
    .then(function (key) {
      sharedKey = key;
      var encrypter = new Jose.JoseJWE.Encrypter(cryptographer, sharedKey);
      return encrypter.encrypt(plaintext);
    })
    .then(function (ciphertext) {
      var decrypter = new Jose.JoseJWE.Decrypter(cryptographer, sharedKey);
      return decrypter.decrypt(ciphertext);
    });

  assert.willEqual(roundtrip, plaintext, 'got expected decrypted plain text');
});

QUnit.test('unicode encryption using RSAES OAEP and AES GCM (keys & IV from appendix-A.1)', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.createIV = function () {
    return new Uint8Array([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
  };
  cryptographer.createCek = function () {
    const cek = new Uint8Array([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]);
    return crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, true, ['encrypt']);
  };
  const rsaKey =
  {
    'kty': 'RSA',
    'n': 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW' +
      'cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S' +
      'psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a' +
      'sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS' +
      'tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj' +
      'YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
    'e': 'AQAB',
    'd': 'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N' +
      'WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9' +
      '3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk' +
      'qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl' +
      't3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd' +
      'VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
    'p': '1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-' +
      'SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf' +
      'fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0',
    'q': 'wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm' +
      'UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX' +
      'IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc',
    'dp': 'ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL' +
      'hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827' +
      'rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE',
    'dq': 'Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj' +
      'ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB' +
      'UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis',
    'qi': 'VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7' +
      'AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3' +
      'eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY'
  };
  const publicRsaKey = Jose.Utils.importRsaPublicKey(rsaKey, 'RSA-OAEP');
  const plaintext = '古池や・蛙飛びこむ・水の音 --松尾芭蕉';
  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, publicRsaKey);
  const cipherTextPromise = encrypter.encrypt(plaintext);

  const privateRsaKey = Jose.Utils.importRsaPrivateKey(rsaKey, 'RSA-OAEP');
  const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, privateRsaKey);
  const decryptedPlaintextPromise = cipherTextPromise.then(function (ciphertext) {
    return decrypter.decrypt(ciphertext);
  });
  assert.willEqual(decryptedPlaintextPromise, plaintext, 'Error: got expected decrypted plain text');
});

QUnit.test('unicode direct A256GCM', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('dir');

  const sharedJwk = { 'alg': 'A256GCM', 'ext': true, 'k': 'Wx5b1Z2nZFgZ8wrEXHo497ZWuvpej1m3PVCgTReiMic', 'key_ops': ['encrypt', 'decrypt'], 'kty': 'oct' };
  const plaintext = '古池や・蛙飛びこむ・水の音 --松尾芭蕉';
  let sharedKey;

  var roundtrip = crypto.subtle.importKey('jwk', sharedJwk, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
    .then(function (key) {
      sharedKey = key;
      const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, sharedKey);
      return encrypter.encrypt(plaintext);
    })
    .then(function (ciphertext) {
      const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, sharedKey);
      return decrypter.decrypt(ciphertext);
    });

  assert.willEqual(roundtrip, plaintext, 'got expected decrypted plain text');
});

QUnit.test('setting invalid algorithm', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  assert.throws(function () { cryptographer.setKeyEncryptionAlgorithm('blah'); }, 'got exception when setting invalid algorithm');
});

QUnit.test('importing public key', function (assert) {
  let rsaKey = {
    'e': 65537
  };
  assert.throws(function () { Jose.Utils.importRsaPublicKey(rsaKey, 'RSA-OAEP'); }, 'got exception when importing invalid key');

  rsaKey = {
    'alg': 'foo',
    'e': 65537,
    'n': 'bf:53:bf:5b:19:bc:80'
  };
  assert.throws(function () { Jose.Utils.importRsaPublicKey(rsaKey, 'RSA-OAEP'); }, 'got exception when importing invalid key');

  rsaKey = {
    'e': 65537,
    'n': []
  };
  assert.throws(function () { Jose.Utils.importRsaPublicKey(rsaKey, 'RSA-OAEP'); }, 'got exception when importing invalid key');
});

QUnit.test('various decryption failures', function (assert) {
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('A128KW');

  let sharedKey = { 'kty': 'oct', 'k': 'GawgguFyGrWKav7AX4VKUg' };
  sharedKey = crypto.subtle.importKey('jwk', sharedKey, { name: 'AES-KW' }, true, ['wrapKey', 'unwrapKey']);

  const plaintext = 'A yawn is a silent scream for coffee. --unknown';
  const encrypter = new Jose.JoseJWE.Encrypter(cryptographer, sharedKey);
  const cipherTextPromise = encrypter.encrypt(plaintext);

  const decrypter = new Jose.JoseJWE.Decrypter(cryptographer, sharedKey);
  const decryptTruncatedInputPromise = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.').slice(1).join('.');
    return decrypter.decrypt(ciphertext);
  });
  assert.wontEqual(decryptTruncatedInputPromise, 'Error: decrypt: invalid input', 'truncated input did not cause failure');

  const decryptMissingAlgPromise = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.');
    ciphertext[0] = 'eyJlbmMiOiJBMjU2R0NNIn0=';
    return decrypter.decrypt(ciphertext.join('.'));
  });
  assert.wontEqual(decryptMissingAlgPromise, 'Error: decrypt: missing alg', 'missing alg in header did not cause failure');

  const decryptMissingEncPromise = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.');
    ciphertext[0] = 'eyJhbGciOiJBMTI4S1cifQ==';
    return decrypter.decrypt(ciphertext.join('.'));
  });
  assert.wontEqual(decryptMissingEncPromise, 'Error: decrypt: missing enc', 'missing enc in header did not cause failure');

  const decryptCritHeaderPromise = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.');
    ciphertext[0] = 'eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTEyOEtXIiwiY3JpdCI6ImJsYWgifQ==';
    return decrypter.decrypt(ciphertext.join('.'));
  });
  assert.wontEqual(decryptCritHeaderPromise, 'Error: decrypt: crit is not supported', 'crit in header did not cause failure');

  const decryptInvalidIvPromise = cipherTextPromise.then(function (ciphertext) {
    ciphertext = ciphertext.split('.');
    ciphertext[2] = 'w4kHDJEum_fHW-U';
    return decrypter.decrypt(ciphertext.join('.'));
  });
  assert.wontEqual(decryptInvalidIvPromise, 'Error: decryptCiphertext: invalid IV', 'invalid IV did not cause failure');

  const cryptographer2 = new Jose.WebCryptographer();
  cryptographer2.setKeyEncryptionAlgorithm('A128KW');
  cryptographer2.createIV = function () { return new Uint8Array(new Array(11)); };
  const encrypter2 = new Jose.JoseJWE.Encrypter(cryptographer2, sharedKey);
  assert.wontEqual(encrypter2.encrypt(plaintext), 'Error: invalid IV length', "fails to encrypt when we don't have the right IV length");
});

QUnit.test('caniuse', function (assert) {
  assert.equal(Jose.caniuse(), true);
});
