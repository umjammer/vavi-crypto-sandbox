# com.boyter.mscrypto

M$ の証明書を扱うクラスを提供します．

## Tech-Know

  * キーストアには管理用パスワードがあり、`$JAVA_HOME/jre/lib/security/cacerts`のデフォルトパスワードは
`changeit` である
  * `keytools` は `-keystore` オプションでキーストアファイルを指定しない場合`$HOME/.keystore` ファイルをキーストアファイルとして使用する(なければ作成する)
  * 一方、Javaアプリケーションはデフォルトで `$JAVA_HOME/jre/lib/security/cacerts`  をキーストアファイルとして使用する(※)
  * Java アプリケーションに任意のキーストアファイルを指定するにはシステムプロパティを指定する
    * `javax.net.ssl.trustStore` ... トラストストアファイル
    * `javax.net.ssl.trustStorePassword` ... トラストストアファイルのパスワード
    * `javax.net.ssl.keyStore` ... キーストアファイル
    * `javax.net.ssl.keyStorePassword` ... キーストアファイルのパスワード

トラストストアは信頼できるサーバ証明書を格納したキーストアであり、
SSL通信のためには`trustStore`、`trustStorePassword`を指定する。

どうも気持が悪いが`trustStorePassword`は指定しなくても動作可能で、
指定した場合はトラストストアファイルの整合性を検証できるらしい。

  * `.cer` ファイルは `keytool` でインポートできる。
```
$ keytool -import -trustcacerts -file ca.cer -alias ca
```

## References

  * src/test/java/t13.java - JSSE
  * [Integrate Java Cryptography with Windows](http://www.ftponline.com/javapro/2002_07/magazine/features/bboyter/default_pf.aspx)

## TODO

  * プライベートキーエクスポートできるようにしとかな使われへんやん
    * ↑ホンマにそうか？実験しる！
  * `-Ddeployment.security.browser.keystore.use=true` はいつ効くねん

## Lisence

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