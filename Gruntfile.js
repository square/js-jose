module.exports = function(grunt) {

  var config = {
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      all: ['Gruntfile.js', 'lib/*.js']
    },

    concat: {
      prod: {
        options: {
          banner: '(function(exports, crypto, Promise, Error, Uint8Array){\n"use strict";\n\n// supporting Safari and its vendor prefix\nif(!crypto.subtle) crypto.subtle = crypto.webkitSubtle;\n',
          footer: "}(window, window.crypto, window.Promise, window.Error, window.Uint8Array));\n"
        },
        src: [
          'lib/jose-core.js',
          'lib/jose-jwe-webcryptographer.js',
          'lib/jose-utils.js',
          'lib/jose-jwe-encrypt.js',
          'lib/jose-jwe-decrypt.js',
          'lib/jose-jws-sign.js',
          'lib/jose-jws-verify.js'
        ],
        dest: 'dist/jose.js'
      },
      testing: {
        options: {
          banner: '(function(exports, crypto, Promise, Error, Uint8Array){\n// supporting Safari and its vendor prefix\nif(!crypto.subtle) crypto.subtle = crypto.webkitSubtle;\n',
          footer: "}(window, window.crypto, window.Promise, window.Error, window.Uint8Array));\n"
        },
        src: [
          'lib/jose-core.js',
          'lib/jose-jwe-webcryptographer.js',
          'lib/jose-utils.js',
          'lib/jose-jwe-encrypt.js',
          'lib/jose-jwe-decrypt.js',
          'lib/jose-jws-sign.js',
          'lib/jose-jws-verify.js'
        ],
        dest: 'dist/jose-testing.js'
      },
      commonjs: {
        src: [
          'lib/jose-core.js',
          'lib/jose-jwe-webcryptographer.js',
          'lib/jose-utils.js',
          'lib/jose-jwe-encrypt.js',
          'lib/jose-jwe-decrypt.js',
          'lib/jose-jws-sign.js',
          'lib/jose-jws-verify.js'
        ],
        dest: 'dist/jose-commonjs.js'
      }
    },

    uglify: {
      dist: {
        src: 'dist/jose.js',
        dest: 'dist/jose.min.js'
      }
    },

    karma: {
      with_coverage: {
        options: {
          preprocessors: {
            'dist/jose-testing.js': ['coverage']
          },
          reporters: ['coverage', 'progress'],
          coverageReporter: {
            type : 'lcovonly',
            dir : 'coverage/'
          },
          frameworks: ['qunit'],
          files: [
            {pattern: 'dist/jose-testing.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
            'test/jose-jwe-test.html',
            'test/jose-jws-test.html'
          ],
          autoWatch: true,
          browsers: ['Chrome'],
          customLaunchers: {
            Chrome_travis_ci: {
              base: 'Chrome',
              flags: ['--no-sandbox']
            }
          },
          singleRun: true,
          plugins:['karma-coverage', 'karma-qunit', 'karma-chrome-launcher']
        }
      },
      without_coverage: {
        options: {
          frameworks: ['qunit'],
          files: [
            {pattern: 'dist/jose-testing.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
            'test/jose-jwe-test.html',
            'test/jose-jws-test.html'
          ],
          autoWatch: true,
          browsers: ['Chrome'],
          customLaunchers: {
            Chrome_travis_ci: {
              base: 'Chrome',
              flags: ['--no-sandbox']
            }
          },
          singleRun: true
        }
      }
    },

    coveralls: {
      options: {
        debug: true,
        coverageDir: 'coverage',
        force: true,
        recursive: true
      }
    }
  };

  if (process.env.TRAVIS) {
    config.karma.with_coverage.browsers = ['Chrome_travis_ci'];
    config.karma.without_coverage.browsers = ['Chrome_travis_ci'];
  }

  grunt.initConfig(config);

  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-karma');
  grunt.loadNpmTasks('grunt-karma-coveralls');

  grunt.registerTask('default', ['jshint', 'concat', 'uglify', 'karma:without_coverage']);
  grunt.registerTask('with_coverage', ['jshint', 'concat', 'uglify', 'karma:with_coverage']);
};
