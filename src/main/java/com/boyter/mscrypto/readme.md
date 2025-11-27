# com.boyter.mscrypto

Provides classes for handling M$ certificates.

## Usage

### Tech-Know

* The keystore has an administrative password, the default password for `$JAVA_HOME/jre/lib/security/cacerts` is
  `changeit`
* If you do not specify a keystore file with the `-keystore` option, `keytools` will use the `$HOME/.keystore` file as the keystore file (it will create one if it does not exist).
* On the other hand, Java applications use `$JAVA_HOME/jre/lib/security/cacerts` as the keystore file by default (※)
* To specify an arbitrary keystore file for a Java application, use a system property
    * `javax.net.ssl.trustStore` ... Trust store file
    * `javax.net.ssl.trustStorePassword` ... Password for the trust store file
    * `javax.net.ssl.keyStore` ... keystore file
    * `javax.net.ssl.keyStorePassword` ... Password for the keystore file

A truststore is a keystore that contains trusted server certificates.
For SSL communication, specify `trustStore` and `trustStorePassword`.

Although it feels a bit strange, it can be run without specifying `trustStorePassword`.
If specified, it seems possible to verify the integrity of the truststore file.

* `.cer` files can be imported with `keytool`.
```
$ keytool -import -trustcacerts -file ca.cer -alias ca
```

## References

* src/test/java/t13.java - JSSE
* [Integrate Java Cryptography with Windows](http://www.ftponline.com/javapro/2002_07/magazine/features/bboyter/default_pf.aspx)

### Lisence

* [mscrypto](http://www.ftponline.com/javapro/2002_07/magazine/features/bboyter/default_pf.aspx)
```
/*
 * Copyright (c) 2001 Brian Boyter
 * All rights reserved
 *
 * This software is released subject to the GNU Public License.  See
 * the full license included with this distribution.
 */
```

## TODO

* Make it possible to export private keys or it will be useless.
    * ↑Is that really true? Let's do an experiment!
* When does `-Ddeployment.security.browser.keystore.use=true` work?
