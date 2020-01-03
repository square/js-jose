QUnit.test('signature using ECDSA P-256 with SHA-256 (keys from appendix-A.3.1)', function (assert) {
  const ecKey = {
    'kty': 'EC',
    'crv': 'P-256',
    'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    'd': 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI'
  };
  const cryptographer = new Jose.WebCryptographer();
  cryptographer.setContentSignAlgorithm('ES256');
  const signer = new Jose.JoseJWS.Signer(cryptographer);
  const plaintext = 'The true sign of intelligence is not knowledge but imagination.';
  const verified = signer
    .addSigner(ecKey, 'A.3.1')
    .then(function () {
      return signer.sign(plaintext);
    })
    .then(function (signature) {
      const verifier = new Jose.JoseJWS.Verifier(cryptographer, signature);
      delete ecKey.d;
      return verifier.addRecipient(ecKey, 'A.3.1').then(function () { return verifier.verify(); });
    })
    .then(function (result) {
      return result[0].verified && result[0].payload === plaintext;
    });
  assert.willEqual(verified, true, 'JWS message has been correctly verified');
});
