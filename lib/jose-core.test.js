// eslint-disable-next-line import/no-duplicates
import DefaultJose, { Jose } from './jose-core.js';
// eslint-disable-next-line import/no-duplicates
import * as AsJose from './jose-core.js';

it('ensure imports work', () => {
  expect(Jose).not.toBeUndefined();
  expect(Jose.JoseJWS).not.toBeUndefined();
  expect(Jose.JoseJWE).not.toBeUndefined();
  expect(Jose.WebCryptographer).not.toBeUndefined();

  console.log(Jose);
  expect(DefaultJose).not.toBeUndefined();
  expect(DefaultJose.WebCryptographer).not.toBeUndefined();
  expect(DefaultJose.Jose).not.toBeUndefined();
  expect(DefaultJose.Jose.JoseJWS).not.toBeUndefined();
  expect(DefaultJose.Jose.JoseJWE).not.toBeUndefined();
  expect(DefaultJose.Jose.WebCryptographer).not.toBeUndefined();

  expect(AsJose).not.toBeUndefined();
  expect(AsJose.WebCryptographer).not.toBeUndefined();
  expect(AsJose.Jose).not.toBeUndefined();
  expect(AsJose.Jose.JoseJWS).not.toBeUndefined();
  expect(AsJose.Jose.JoseJWE).not.toBeUndefined();
  expect(AsJose.Jose.WebCryptographer).not.toBeUndefined();
});
