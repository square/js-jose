const webpack = require('webpack')
const path = require('path')

module.exports = {
  module: {
    rules: [{
      use: {
        loader: 'babel-loader',
        options: {
          presets: ['@babel/preset-env']
        }
      },
      test: /\.js$/
    }]
  },

  entry: './lib/jose-core',

  output: {
    filename: 'jose.min.js',
    library: 'Jose',
    libraryTarget: 'umd',
    path: path.resolve(__dirname, 'dist')
  },

  mode: 'production',

  optimization: {
    splitChunks: {
      cacheGroups: {
        vendors: {
          priority: -10,
          test: /[\\/]node_modules[\\/]/
        }
      },

      chunks: 'async',
      minChunks: 1,
      minSize: 30000,
      name: true
    }
  }
}
