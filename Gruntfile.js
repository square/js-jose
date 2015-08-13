module.exports = function(grunt) {

  var config = {
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      all: ['Gruntfile.js', 'lib/*.js']
    },

    concat: {
      dist: {
        options: {
          banner: '(function(exports, crypto, Promise, Error, Uint8Array, undefined){\n"use strict";\n',
          footer: "}(window, window.crypto, window.Promise, window.Error, window.Uint8Array));\n"
        },
        src: [
          'lib/jose-core.js',
          'lib/jose-jwe-webcryptographer.js',
          'lib/jose-jwe-utils.js',
          'lib/jose-jwe-encrypt.js',
          'lib/jose-jwe-decrypt.js',
          'lib/jose-jws-sign.js',
          'lib/jose-jws-verify.js',
          'lib/jose-backward-compatibility.js'
        ],
        dest: 'dist/jose-jwe.js'
      }
    },

    uglify: {
      dist: {
        src: 'dist/jose-jwe.js',
        dest: 'dist/jose-jwe.min.js'
      }
    },

    karma: {
      with_coverage: {
        options: {
          preprocessors: {
            'dist/jose-jwe.js': ['coverage']
          },
          reporters: ['coverage'],
          coverageReporter: {
            type : 'lcovonly',
            dir : 'coverage/'
          },
          frameworks: ['qunit'],
          files: [
            {pattern: 'dist/jose-jwe.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
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
            {pattern: 'dist/jose-jwe.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
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

  if(process.env.TRAVIS){
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
