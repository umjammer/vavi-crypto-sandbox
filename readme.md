[![GitHub Packages](https://github.com/umjammer/vavi-crypto-sandbox/actions/workflows/maven-publish.yml/badge.svg)](https://github.com/umjammer/vavi-crypto-sandbox/actions/workflows/maven-publish.yml)
[![CodeQL](https://github.com/umjammer/vavi-crypto-sandbox/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/umjammer/vavi-crypto-sandbox/actions/workflows/codeql-analysis.yml)
![Java](https://img.shields.io/badge/Java-8-b07219)

# vavi-crypto-sandbox

 * windows certifications
 * Camellia
 * Eniguma (wip)

## references

 * [Java Security for the Enterprise (jstk)](http://www.j2ee-security.net/)
 * https://github.com/opengl-8080/enigma

## Tech-Know

### How to ignore JCA signed jar checker

 * use [instrumentation](src/test/java/instr/PropertiesClassFileTransformer.java)

## License

 * [Camellia](http://info.isl.ntt.co.jp/crypt/camellia/index.html)
```
This is a Crypto engine for Camellia(java implementation).

 License: BSD
 version: 1.0.1

For inquires regarding of Camellia, please access here.
  http://info.isl.ntt.co.jp/crypt/camellia/index.html
```

## TODO

 * rococoa
   * notification
   * keychain (cyberduck/core/dylib)
     * https://github.com/conormcd/osx-keychain-java
 * jna platform contains CFxxx