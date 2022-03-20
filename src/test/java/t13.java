/*
 * Copyright (c) 2003 by Naohide Sano, All rights rserved.
 *
 * Programmed by Naohide Sano
 */

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import vavi.util.Debug;
import vavi.util.StringUtil;


/**
 * SSL.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (vavi)
 * @version 0.00 031205 nsano initial version <br>
 */
public class t13 {

    /**
     * The program entry.
     * @param args 0:url, 1:jksFile, 2:password
     */
    public static void main(String[] args) throws Exception {

        URL url = new URL(args[0]);

        URLConnection connection = url.openConnection();

        // ******************************************************************
        String algorithm = "sunx509";
        String keyStore = System.getProperty("javax.net.ssl.keyStore");
        String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");
//        String trustStore = System.getProperty("javax.net.ssl.trustStore");
//        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStore), keyStorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, keyStorePassword.toCharArray());
        KeyManager[] km = kmf.getKeyManagers();

        // 証明書の信頼性を決定するためのインターフェース
        //
        TrustManager[] tm = { new RelaxedX509TrustManager() };
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
//        tmf.init(ks);
//        TrustManager[] tm = tmf.getTrustManagers();

        // ソケットプロトコルを実装するSSLContextを作成
        SSLContext sslContext = SSLContext.getInstance("SSL");
        // SSLContextを初期化
        sslContext.init(km, tm, new SecureRandom());
        // SSLContextのSocketFactoryを取得
        SSLSocketFactory sslsf = sslContext.getSocketFactory();
        // URLConnectionにSocketFactoryをセット
        ((HttpsURLConnection) connection).setSSLSocketFactory(sslsf);
        // ******************************************************************

        // ******************************************************************
        // ホスト名を無視させる
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
Debug.println(hostname + ", " + session);
                return true;
            }
        };
        ((HttpsURLConnection) connection).setHostnameVerifier(hv);

        // HTMLファイルをStreamで取得
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "JISAutoDetect"));
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }
        in.close();
    }

    /**
     * 証明書の信頼性をチェックするインターフェースを実装
     * (信頼されない証明書でも強制的に認証する)
     */
    static class RelaxedX509TrustManager implements X509TrustManager {

        /**
         * 信頼されない証明書でも強制的に認証する (クライアント認証)
         */
        public boolean isClientTrusted(X509Certificate[] chain) {
Debug.println(chain);
            return true;
        }

        /**
         * 信頼されない証明書でも強制的に認証する
         */
        public boolean isServerTrusted(X509Certificate[] chain) {
Debug.println(chain);
            return true;
        }

        /**
         * 証明書を返す
         */
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        /** */
        public void checkClientTrusted(X509Certificate[] chain,
                                       String authType) {
Debug.println(chain + ", " + authType);
        }

        /** */
        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType) {
Debug.println(authType);
            for (int i = 0; i < chain.length; i++) {
Debug.println(StringUtil.paramString(chain[i]));
            }
        }
    }
}

/* */
