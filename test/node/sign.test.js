const Jose = require('../..')

const WebCrypto = require("node-webcrypto-ossl")
const webcrypto = new WebCrypto()
Jose.setCrypto(webcrypto)

const base64UrlEncoder = new Jose.Utils.Base64Url();

const testRSAKey = {
  "kty": "RSA",
  "n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z"+
         "wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5Js"+
         "GY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic"+
         "AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-"+
         "bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF"+
         "Cur-kEgU8awapJzKnqDKgw",
  "e":   "AQAB",
  "d":   "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURk"+
         "nchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxW"+
         "p4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t"+
         "8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT"+
         "8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0"+
         "Y6mqnOYtqc0X4jfcKoAC8Q",
  "p":   "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60e"+
         "TDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36"+
         "GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
  "q":   "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIr"+
         "dwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezs"+
         "Z-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
  "dp":  "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue"+
         "0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2"+
         "GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
  "dq":  "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqe"+
         "W6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRs"+
         "obRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
  "qi":  "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwe"+
         "mRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SP"+
         "mRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
  "alg": "RS256",
  "kid": "2011-04-29",
};

test('creates a valid RSA JSON Web Signature', async () => {
  // initialise a WebCryptographer for RS256
  const cryptographer = new Jose.WebCryptographer()
  cryptographer.setContentSignAlgorithm("RS256")

  // initialise a Signer with testRSAKey added
  const signer = new Jose.JoseJWS.Signer(cryptographer)
  await signer.addSigner(testRSAKey, "A.2.1")

  // generate a JWS
  const payload = { msg: "The true sign of intelligence is not knowledge but imagination." }
  const unprotectedHeader = { foo: "bar" }
  const jws = await signer.sign(payload, null, unprotectedHeader)

  // verify the JWS
  expect(jws.protected).toBeDefined()
  expect(jws.payload).toBeDefined()
  expect(jws.signature).toBeDefined()
  const key = await Jose.Utils.importRsaPublicKey(testRSAKey, "RS256")
  const decodedSignature = Jose.Utils.arrayFromString(base64UrlEncoder.decode(jws.signature))
  const signedPayload = Jose.Utils.arrayFromString(jws.protected + "." + jws.payload)
  const verified = await webcrypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodedSignature, signedPayload)
  expect(verified).toBeTruthy()

  // check the JWS contains the correct values
  expect(jws.header).toEqual(unprotectedHeader)

  const decodedHeader = JSON.parse(base64UrlEncoder.decode(jws.protected))
  expect(decodedHeader.alg).toEqual("RS256")
  expect(decodedHeader.kid).toEqual("A.2.1")

  const decodedPayload = JSON.parse(base64UrlEncoder.decode(jws.payload))
  expect(decodedPayload).toEqual(payload)
})
