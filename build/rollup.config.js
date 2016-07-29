import babel from 'rollup-plugin-babel';

export default {
  entry: 'src/strategy.js',
  format: 'cjs',
  plugins: [ babel() ],
  dest: 'index.js'
}