const webpackDevConfig = require('./webpack.dev');
const webpackProdConfig = require('./webpack.prod');

module.exports = function(grunt) {

  var config = {
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      all: ['Gruntfile.js', 'lib/*.js'],
      options: {
        "esversion": 6
      }
    },

    webpack: {
      dev: webpackDevConfig,
      prod: webpackProdConfig
    },

    karma: {
      with_coverage: {
        options: {
          preprocessors: {
            'dist/jose.js': ['coverage']
          },
          reporters: ['coverage', 'progress'],
          coverageReporter: {
            type : 'lcovonly',
            dir : 'coverage/'
          },
          frameworks: ['qunit'],
          files: [
            {pattern: 'dist/jose.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
            'test/jose-jwe-test.html',
            'test/jose-jws-ecdsa-test.html',
            'test/jose-jws-rsa-test.html'
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
            {pattern: 'dist/jose.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
            'test/jose-jwe-test.html',
            'test/jose-jws-ecdsa-test.html',
            'test/jose-jws-rsa-test.html'
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
  grunt.loadNpmTasks('grunt-webpack');

  grunt.registerTask('default', ['jshint', 'webpack', 'karma:without_coverage']);
  grunt.registerTask('with_coverage', ['jshint', 'webpack', 'karma:with_coverage']);
};
