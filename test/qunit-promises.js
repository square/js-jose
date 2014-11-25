(function (QUnit) {
  // jQuery promise objects have .then and .always methods
  // Q promise objects have .then and .finally methods
  function verifyPromise(promise) {
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

      QUnit.stop();
      promise.then(function () {
        QUnit.push(true, undefined, undefined, message);
        QUnit.start();
      }, function () {
        QUnit.push(false, undefined, undefined, 'promise rejected (but should have been resolved)');
        QUnit.start();        
      });
    },

    willEqual: function (promise, expected, message) {
      verifyPromise(promise);

      QUnit.stop();
      promise.then(function (actual) {
        QUnit.push(actual == expected, actual, expected, message);
        QUnit.start();
      }, function (actual) {
        QUnit.push(false, actual, expected, 'promise rejected (but should have been resolved)');
        QUnit.start();
      });
    },

    willDeepEqual: function (promise, expected, message) {
      var always = verifyPromise(promise);

      QUnit.stop();
      promise.then(function (actual) {
        if (typeof QUnit.equiv !== 'function') {
          throw new Error('Missing QUnit.equiv function');
        }
        QUnit.push(QUnit.equiv(actual, expected), actual, expected, message);
        QUnit.start();
      }, function (actual) {
        QUnit.push(false, actual, expected, 'promise rejected (but should have been resolved)');
        QUnit.start();
      });
    },

    // rejected promises
    wont: function (promise, message) {
      var always = verifyPromise(promise);

      QUnit.stop();
      promise.then(function () {
        QUnit.push(false, undefined, undefined, 'promise resolved (but should have been rejected)');
        QUnit.start();
      }, function () {
        QUnit.push(true, undefined, undefined, message);
        QUnit.start();
      });
    },

    wontEqual: function (promise, expected, message) {
      var always = verifyPromise(promise);

      QUnit.stop();
      promise.then(function (actual) {
        QUnit.push(false, actual, expected, 'promise resolved (but should have been rejected)');
        QUnit.start();
      }, function (actual) {
        QUnit.push(actual == expected, actual, expected, message);
        QUnit.start();
      });
    }
  });
}(QUnit));
