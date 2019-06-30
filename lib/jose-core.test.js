import DefaultJose, { Jose } from './jose-core.js';

it('ensure imports work', () => {
  expect(Jose).not.toBeUndefined();
  expect(DefaultJose).not.toBeUndefined();
});
