module.exports = function(grunt) {

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      all: ['Gruntfile.js', 'lib/*.js']
    },

    concat: {
      dist: {
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
      continuous: {
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

  grunt.registerTask('default', ['jshint', 'concat', 'uglify', 'karma']);
};