module.exports = function(grunt) {

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      all: ['Gruntfile.js', 'lib/*.js']
    },

    concat: {
      dist: {
        options: {
          banner: "(function(){\n",
          footer: "}());\n"
        },
        src: [
          'lib/jose-jwe-core.js',
          'lib/jose-jwe-utils.js',
          'lib/jose-jwe-encrypt.js',
          'lib/jose-jwe-decrypt.js',
          'lib/jose-jwe-mac-then-enc.js',
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
          frameworks: ['qunit'],
          files: [
            {pattern: 'dist/jose-jwe.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
            'test/jose-jwe-test.html'
          ],
          autoWatch: true,
          browsers: ['Chrome'],
          singleRun: true,
          plugins:[ 'karma-coverage', 'karma-qunit', 'karma-chrome-launcher']
        }
      },
      without_coverage: {
        options: {
          frameworks: ['qunit'],
          files: [
            {pattern: 'dist/jose-jwe.js', watching: false, included: false},
            {pattern: 'test/qunit-promises.js', watching: false, included: false},
            'test/jose-jwe-test.html'
          ],
          autoWatch: true,
          browsers: ['Chrome'],
          singleRun: true
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-karma');

  grunt.registerTask('default', ['jshint', 'concat', 'uglify', 'karma:without_coverage']);
  grunt.registerTask('with_coverage', ['jshint', 'concat', 'uglify', 'karma:with_coverage']);
};