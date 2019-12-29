(function (QUnit) {
  // jQuery promise objects have .then and .always methods
  // Q promise objects have .then and .finally methods
  function verifyPromise (promise) {
    if (!promise) {
      throw new Error('expected a promise object');
    }
    if (typeof promise.then !== 'function') {
      throw new Error('promise object does not have .then function');
    }
  }

  QUnit.extend(QUnit.assert, {
    // resolved promises
    will: function (promise, message) {
      verifyPromise(promise);

      const assert = this;
      const done = assert.async();
      promise.then(function () {
        assert.pushResult({
          result: true,
          actual: undefined,
          expected: undefined,
          message: message
        });
        done();
      }, function () {
        assert.pushResult({
          result: false,
          actual: undefined,
          expected: undefined,
          message: 'promise rejected (but should have been resolved)'
        });
        done();
      });
    },

    willEqual: function (promise, expected, message) {
      verifyPromise(promise);

      const assert = this;
      const done = assert.async();
      promise.then(function (actual) {
        assert.pushResult({
          result: actual == expected,
          actual: actual,
          expected: expected,
          message: message
        });
        done();
      }, function (actual) {
        assert.pushResult({
          result: false,
          actual: actual,
          expected: expected,
          message: 'promise rejected (but should have been resolved)'
        });
        done();
      });
    },

    willDeepEqual: function (promise, expected, message) {
      var always = verifyPromise(promise);

      const assert = this;
      const done = assert.async();
      promise.then(function (actual) {
        if (typeof QUnit.equiv !== 'function') {
          throw new Error('Missing QUnit.equiv function');
        }
        QUnit.push(QUnit.equiv(actual, expected), actual, expected, message);
        assert.pushResult({
          result: QUnit.equiv(actual, expected),
          actual: actual,
          expected: expected,
          message: message
        });
        done();
      }, function (actual) {
        assert.pushResult({
          result: false,
          actual: actual,
          expected: expected,
          message: 'promise rejected (but should have been resolved)'
        });
        done();
      });
    },

    // rejected promises
    wont: function (promise, message) {
      var always = verifyPromise(promise);

      const assert = this;
      const done = assert.async();
      promise.then(function () {
        assert.pushResult({
          result: false,
          actual: undefined,
          expected: undefined,
          message: 'promise resolved (but should have been rejected)'
        });
        done();
      }, function () {
        assert.pushResult({
          result: true,
          actual: undefined,
          expected: undefined,
          message: message
        });
        done();
      });
    },

    wontEqual: function (promise, expected, message) {
      var always = verifyPromise(promise);

      const assert = this;
      const done = assert.async();
      promise.then(function (actual) {
        assert.pushResult({
          result: false,
          actual: actual,
          expected: expected,
          message: 'promise resolved (but should have been rejected)'
        });
        done();
      }, function (actual) {
        assert.pushResult({
          result: actual == expected,
          actual: actual,
          expected: expected,
          message: message
        });
        done();
      });
    }
  });
}(QUnit));
