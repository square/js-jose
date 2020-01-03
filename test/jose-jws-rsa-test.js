QUnit.test('signature using RSASSA-PKCS1-v1_5 with SHA-256 (keys from appendix-A.2.1)', function (assert) {
  const rsaKey = {
    'n': 'A1:F8:16:0A:E2:E3:C9:B4:65:CE:8D:2D:65:62:63:36:2B:92:7D:BE:29:E1:F0:24:77:FC:16:25:CC:90:A1:36:E3:8B:D9:34:97:C5:B6:EA:63:DD:77:11:E6:7C:74:29:F9:56:B0:FB:8A:8F:08:9A:DC:4B:69:89:3C:C1:33:3F:53:ED:D0:19:B8:77:84:25:2F:EC:91:4F:E4:85:77:69:59:4B:EA:42:80:D3:2C:0F:55:BF:62:94:4F:13:03:96:BC:6E:9B:DF:6E:BD:D2:BD:A3:67:8E:EC:A0:C6:68:F7:01:B3:8D:BF:FB:38:C8:34:2C:E2:FE:6D:27:FA:DE:4A:5A:48:74:97:9D:D4:B9:CF:9A:DE:C4:C7:5B:05:85:2C:2C:0F:5E:F8:A5:C1:75:03:92:F9:44:E8:ED:64:C1:10:C6:B6:47:60:9A:A4:78:3A:EB:9C:6C:9A:D7:55:31:30:50:63:8B:83:66:5C:6F:6F:7A:82:A3:96:70:2A:1F:64:1B:82:D3:EB:F2:39:22:19:49:1F:B6:86:87:2C:57:16:F5:0A:F8:35:8D:9A:8B:9D:17:C3:40:72:8F:7F:87:D8:9A:18:D8:FC:AB:67:AD:84:59:0C:2E:CF:75:93:39:36:3C:07:03:4D:6F:60:6F:9E:21:E0:54:56:CA:E5:E9:A1',
    'e': 65537,
    'd': '12:AE:71:A4:69:CD:0A:2B:C3:7E:52:6C:45:00:57:1F:1D:61:75:1D:64:E9:49:70:7B:62:59:0F:9D:0B:A5:7C:96:3C:40:1E:3F:CF:2F:2C:D3:BD:EC:88:E5:03:BF:C6:43:9B:0B:28:C8:2F:7D:37:97:67:1F:52:13:EE:D8:C1:5A:25:D8:D5:CE:A0:02:5E:E3:AB:2E:8B:7F:79:21:6F:C6:3B:EA:56:27:53:B4:06:44:C6:A1:51:27:D9:B2:95:45:40:A0:BB:E1:A3:05:56:98:2D:4E:9F:DE:5F:64:25:F1:4D:4B:71:34:41:B5:5D:C7:3B:9B:4A:ED:CC:92:AC:E3:92:7E:37:F5:7D:0C:FD:5E:75:81:FA:51:2C:8F:49:61:A9:EB:0B:80:F8:A8:07:46:72:8A:55:FF:46:47:1F:34:25:06:3B:9D:53:64:2F:5E:DE:1E:84:D6:13:08:1A:FA:5C:22:D0:51:28:5B:D6:3B:94:3B:56:5D:89:8A:05:68:54:13:E5:3C:3C:6C:65:25:FF:1F:E3:4E:3D:DC:70:F0:D5:64:50:FD:A4:8B:A1:2E:10:4E:9D:EB:9F:B8:18:81:E1:C4:BD:F2:5D:92:47:F4:50:C8:65:92:79:68:E7:73:34:F4:41:4F:75:A7:50:E1:39:54:6E:3A:8A:73:9D',
    'p': 'E0:1C:C4:10:EB:48:A6:65:5D:54:46:4D:0A:A4:BB:6D:A0:B8:72:B7:74:A6:A9:D1:1F:FE:48:07:78:F0:DD:B7:31:1A:7E:90:2E:F9:C4:B5:F7:54:76:26:2B:A8:17:6C:B3:59:79:F0:14:37:2A:1A:28:29:E4:13:6B:D0:01:D0:7C:3F:3F:2E:4F:25:D4:C9:34:F6:3C:71:09:FB:A2:E6:76:28:A0:DC:9A:73:C6:05:8E:6D:EF:22:DC:D5:09:50:E7:11:DD:C1:6D:55:86:F2:A7:FA:75:EA:84:94:C1:80:83:E0:B6:57:42:F8:A0:D5:E7:3F:B2:D9:70:F0:19:47',
    'q': 'B9:03:C4:7E:09:95:B6:32:F4:53:2C:B1:F3:C1:99:14:5D:5F:3A:E9:C7:DF:EE:DC:7A:92:A6:B4:7E:29:C6:1B:42:A0:7A:A9:5A:64:FC:60:09:99:C5:A7:B0:1E:01:C0:8C:B6:2C:A7:56:52:7B:BC:C5:60:78:FB:0B:AB:A5:ED:38:DE:2D:07:99:0F:F6:30:0F:AE:AD:EB:6C:03:9A:97:BF:1E:50:7E:4E:70:40:FA:78:DB:82:57:C8:B1:12:ED:5E:59:C3:CD:09:2F:E5:D4:E5:B5:12:75:D4:12:81:07:2A:5E:78:5E:BA:F3:DA:E3:70:92:03:13:3F:51:59:D7',
    'dp': '07:02:9F:57:70:24:AB:9F:CC:15:90:C5:64:29:D6:FB:0C:E5:F8:20:A8:F3:75:A8:66:F9:CB:43:00:93:78:3B:FC:BB:39:6E:45:29:E6:EF:52:37:40:22:DD:86:BA:84:D9:EF:58:93:1B:EE:C5:D0:5F:A5:3F:CF:23:B6:33:F8:53:8A:9E:ED:51:E8:7B:09:78:30:A3:9F:5D:92:93:7B:E6:02:4B:55:DB:36:F7:E0:C0:9D:CB:B7:29:75:38:7F:61:5A:FB:B6:CB:36:BB:AB:E7:79:3C:2B:03:CE:AB:66:DB:B9:31:BA:F5:0B:55:EC:9A:F9:31:1D:00:1D:62:8D',
    'dq': '87:FF:7A:FA:62:B5:47:FE:E0:96:1B:2E:9B:CD:5D:67:18:D3:9D:8C:A7:3D:B6:69:1F:38:99:8D:E7:87:71:76:2C:5D:A6:8C:C2:43:A5:38:3B:16:6B:B2:3D:C5:70:E8:47:06:CA:80:1E:F5:F6:BA:E6:23:6A:0A:AF:A3:77:0E:8F:54:D1:A8:DA:1C:5F:8D:28:99:F0:82:33:1D:DB:0F:5C:8F:3D:FF:FA:4C:8D:97:10:2B:DA:FE:08:2A:11:8D:A6:63:39:88:88:0E:4B:55:59:9C:E6:7A:F2:6E:BF:A5:B2:C1:4A:9D:E7:B2:C4:DD:96:AB:DD:D2:D2:22:4C:75',
    'qi': '21:87:7B:0C:73:A1:AD:6B:F1:93:03:D0:B1:13:36:B4:E8:2B:8D:B7:2B:7E:FB:50:26:2A:5D:F8:39:5C:C7:25:6E:B8:CF:6C:40:B7:60:8D:59:36:A3:2D:BA:17:41:26:A5:27:06:2E:AD:8C:A3:05:FB:7E:17:7F:40:94:37:C9:DC:B9:71:8E:D8:20:18:BC:EF:0F:77:20:A2:C4:75:F9:DB:26:DA:0E:3C:B5:16:D0:84:EB:25:17:8E:82:8D:5C:AB:D4:9B:B3:16:1A:C0:18:1F:A7:F8:21:E8:0E:7A:D3:79:36:F9:94:30:54:AD:09:29:21:EE:2C:59:2E:43:75'
  };
  const cryptographer = new Jose.WebCryptographer();
  const signer = new Jose.JoseJWS.Signer(cryptographer);
  const plaintext = 'The true sign of intelligence is not knowledge but imagination.';
  cryptographer.setContentSignAlgorithm('RS256');
  const adsPromise = signer.addSigner(rsaKey, 'A.2.1');

  assert.willEqual(adsPromise.then(function () {
    return signer.sign(plaintext, null, {}).then(function (signature) {
      const b64uxp = /^[a-z0-9_-]+$/i;
      return b64uxp.test(signature.protected) &&
        b64uxp.test(signature.payload) &&
        b64uxp.test(signature.signature);
    });
  }), true, 'got right JSON serialization format');

  assert.willEqual(adsPromise.then(function () {
    return signer.sign(plaintext, null, {}).then(function (signature) {
      const xp = /([a-z0-9_-]+\.){2}[a-z0-9_-]+/i;
      return xp.test(signature.CompactSerialize());
    });
  }), true, 'got correct compact serialization format');

  assert.willEqual(adsPromise.then(function () {
    return signer.sign(plaintext, null, {}).then(function (signature) {
      const verifier = new Jose.JoseJWS.Verifier(cryptographer, signature);
      return verifier.addRecipient(rsaKey, 'A.2.1').then(function () {
        return verifier.verify().then(function (result) {
          return result.filter(function (value) {
            return !value.verified;
          }).length === 0;
        });
      });
    });
  }), true, 'JWS message has been correctly verified');

  assert.willEqual(adsPromise.then(function () {
    return signer.sign(plaintext, null, {}).then(function (signature) {
      const verifier = new Jose.JoseJWS.Verifier(cryptographer, signature);
      return verifier.addRecipient(rsaKey, 'A.2.1').then(function () {
        return verifier.verify().then(function (result) {
          return result[0].verified && result[0].payload === plaintext;
        });
      });
    });
  }), true, 'JWS message payload matched expected plaintext');
});

QUnit.test('keyfinder', function (assert) {
  const prvjwk = {
    'alg': 'RS256',
    'd': 'l0-Bq8hePldybBsBUon7eGgwD53XfzZNXKB9yq6V6DyOxpAP2KpASdCcTYlDWJb_tqdWSjqxDuWox0l6S3l-f6xjWu5Du1u0DATjzgtdGyrNw-yX0SZlVq_Nbotw0-0GT1VpyUmvNvCS_gy9tONDv4PIrfMe0fwaRoMFmVo40o18At6y4DMxWkH63wUTtXYFlGLH9dNd1yq4odIoqWYpA_aE0pxz1aGpqJzY0_-mXfB8oH-uAY6a474kAJV2PE25_mLxFRmT0qB-0qcpjoTn1SVQfMRaeWvh4YzU-o30mCKWmDgU5Obc0fK9buMoM3uQKFUkRNsCOg1o1_cjx6epsQ',
    'dp': 'R5dAKUQsBjKUCcoczkn5KOI3du5SU0F_p_2lpogHtR5vJcTZjluSm2lB7qgFheB80ZcVPtFiRN5h9A8qWmhHh5DIHibaQ0J_dVLH4CmmlKOBORzNJPicy54G99gsBzvTeqZ8_CYsrj1fRREMJxiHRk1uqe1VQ19nZQDZwrd8Q5E',
    'dq': 'pfXdH9NJdsMkKVUKruaw4K5jYONKVz499dbdTT8LgkkxoQy1Tvm_C1xJYO4KiK1qvjV9_jazqvGkvdxddPQOIc6bOmtm_UfSoMAdussi2spTK6eO5EAzDRcPfXqdgSc7ihjBdklma33q9iMhtIA2SE3IDG0QXswjKDfQ435n8Qk',
    'e': 'AQAB',
    'ext': true,
    'key_ops': ['sign'],
    'kid': '76d4d722-4398-4fc4-a47e-df3d15de7fab',
    'kty': 'RSA',
    'n': 'xw6vxkASH4Jz23XLQMAj3FB55Dq4xCBwaTtUZpKSddMx3hvVeZb_nWv2Ogu18vL-x8LaYGYYG_LSirVA_tJ3ArEw_rqQDJOvsHTAuGrSOJkusJeC46Z5ZP0TndpunV6-04rxltjUVriwO8XzZdH4RnX_kSUEz3qeUc5j-OhTj59sG1-Os51iYiUEwDa6z8fn20wHRtEvPzG0MNQBX58CPuIM9bS8eNOZKUG-oVWAoWcbMfqEE5D8YsW_cZUWY9OLRa5C6xNRMfwlxYeMedJgehXJmxqaxSn0fe6-VZk9qcJDLiWg6vy1NYOJ8UOgtKtSPr7uL4Kc8K8akYVq-qHXAQ',
    'p': '7ZYCLz4jFWW2ody4tPPOrDJn7dKXvkytUC6jL0_iGHNgjbcV3zEDkJC9eJWZaCXIwFKjnzlP4iQTHRqvE8pOFtHLaCj4MpEe9EIg6cZSoc866dVAD9aKS74TeCIQ5YBEvOAa_3h3Uecui0g_Xd0Hm3cr6VcNIMer2OffRmGTJcU',
    'q': '1nw5av78m5eTQv9IgOuxzvy9NQfm2hw8eq2eBduYalIvpa_3QTWXzvJ7_iOomNzZyEm6AjmKQu1Ualfgqq5YDU-jKBY4Pd27SQXHFwO75dsOZc7Xn2QQbHLNNOL8vNSy9ZeEkvDJtwX1lJ9x9XLXztRqJZr_UqS5680zCPO__A0',
    'qi': 'Zv9pwzMgWoAFu9hwp-foLoCYaFdVGj8vV-QovqW507TzhRiZuaP9SsYEF5ZizhEDLtjSxX2KycQUt-EEP9piUvgPiF_K7zXmQ-clvh_qzXrOE4UhfXbAjLFCUBf8YcgFsCYzvvqom3ktxOC0FPhfJr7s2EXQIQjzK5Drm-fZTZc'
  };
  const pubjwk = {
    'alg': 'RS256',
    'e': 'AQAB',
    'ext': true,
    'key_ops': ['verify'],
    'kid': '76d4d722-4398-4fc4-a47e-df3d15de7fab',
    'kty': 'RSA',
    'n': 'xw6vxkASH4Jz23XLQMAj3FB55Dq4xCBwaTtUZpKSddMx3hvVeZb_nWv2Ogu18vL-x8LaYGYYG_LSirVA_tJ3ArEw_rqQDJOvsHTAuGrSOJkusJeC46Z5ZP0TndpunV6-04rxltjUVriwO8XzZdH4RnX_kSUEz3qeUc5j-OhTj59sG1-Os51iYiUEwDa6z8fn20wHRtEvPzG0MNQBX58CPuIM9bS8eNOZKUG-oVWAoWcbMfqEE5D8YsW_cZUWY9OLRa5C6xNRMfwlxYeMedJgehXJmxqaxSn0fe6-VZk9qcJDLiWg6vy1NYOJ8UOgtKtSPr7uL4Kc8K8akYVq-qHXAQ'
  };
  const plaintext = "When you make the finding yourself - even if you're the last person on Earth to see the light - you'll never forget it. --Carl Sagan";

  const pubjwks = {};
  pubjwks[pubjwk.kid] = pubjwk;

  const keyfinder = function (kid) {
    const jwk = pubjwks[kid];
    if (jwk) {
      return window.crypto.subtle.importKey('jwk', jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
        true, ['verify']);
    } else {
      return Promise.reject(Error('unknown sender key id ' + kid));
    }
  };

  let cryptographer = new Jose.WebCryptographer();
  cryptographer.setContentSignAlgorithm('RS256');
  let signer = new Jose.JoseJWS.Signer(cryptographer);

  assert.willEqual(signer.addSigner(prvjwk, prvjwk.kid)
    .then(function () {
      return signer.sign(plaintext);
    })
    .then(function (signed) {
      const verifier = new Jose.JoseJWS.Verifier(cryptographer, signed, keyfinder);
      return verifier.verify().then(function (result) {
        return result.filter(function (value) {
          return !value.verified;
        }).length === 0;
      });
    }),
  true, 'keyfinder found key');

  cryptographer = new Jose.WebCryptographer();
  cryptographer.setContentSignAlgorithm('RS256');
  signer = new Jose.JoseJWS.Signer(cryptographer);

  assert.wont(signer.addSigner(prvjwk, prvjwk.kid)
    .then(function (prvkey) {
      cryptographer = new Jose.WebCryptographer();
      cryptographer.setContentSignAlgorithm('RS256');
      signer = new Jose.JoseJWS.Signer(cryptographer);
      return signer.addSigner(prvkey, 'unknown');
    })
    .then(function () {
      return signer.sign(plaintext);
    })
    .then(function (signed) {
      const verifier = new Jose.JoseJWS.Verifier(cryptographer, signed, keyfinder);
      return verifier.verify().then(function (result) {
        return result.filter(function (value) {
          return !value.verified;
        }).length === 0;
      });
    }), 'keyfinder rejected properly on unknown key');
});
