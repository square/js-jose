const webpack = require("webpack");
const path = require("path");

const web = {
  module : {
    rules: [
      {
        include: [path.resolve(__dirname, "src")],
        loader: "babel-loader",

        options: {
          presets: ["@babel/preset-env"]
        },

        test: /\.js$/
      }
    ]
  },

  entry: "./lib/jose-core",

  output: {
    filename: "jose.js",
    library: "Jose",
    libraryTarget: "commonjs",
    path: path.resolve(__dirname, "dist")
  },

  mode: "development",

  optimization: {
    splitChunks: {
      cacheGroups: {
        vendors: {
          priority: -10,
          test: /[\\/]node_modules[\\/]/
        }
      },

      chunks: "async",
      minChunks: 1,
      minSize: 30000,
      name: true
    }
  }
};

const node = {
  target: "node",
  module : {
    rules: [
      {
        include: [path.resolve(__dirname, "src")],
        loader: "babel-loader",

        options: {
          presets: ["@babel/preset-env"]
        },

        test: /\.js$/
      }
    ]
  },

  entry: "./lib/jose-core",

  output: {
    filename: "jose.node.js",
    library: "Jose",
    libraryTarget: "commonjs",
    path: path.resolve(__dirname, "dist")
  },

  mode: "development",

  optimization: {
    splitChunks: {
      cacheGroups: {
        vendors: {
          priority: -10,
          test: /[\\/]node_modules[\\/]/
        }
      },

      chunks: "async",
      minChunks: 1,
      minSize: 30000,
      name: true
    }
  }
};

module.exports = [web, node];
