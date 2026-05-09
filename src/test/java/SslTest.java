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
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
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
public class SslTest {

    /**
     * The program entry.
     * @param args 0:url, 1:jksFile, 2:password
     */
    public static void main(String[] args) throws Exception {

        URL url = new URL(args[0]);

        URLConnection connection = url.openConnection();

        // ----
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

        // Interface for determining the trustworthiness of a certificate
        //
        TrustManager[] tm = { new RelaxedX509TrustManager() };
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
//        tmf.init(ks);
//        TrustManager[] tm = tmf.getTrustManagers();

        // Create an SSLContext that implements the socket protocol.
        SSLContext sslContext = SSLContext.getInstance("SSL");
        // Initialize SSLContext
        sslContext.init(km, tm, new SecureRandom());
        // Get the SocketFactory of the SSLContext
        SSLSocketFactory sslsf = sslContext.getSocketFactory();
        // Set SocketFactory in URLConnection
        ((HttpsURLConnection) connection).setSSLSocketFactory(sslsf);
        // ----

        // ----
        // Ignore the hostname
        HostnameVerifier hv = (hostname, session) -> {
Debug.println(hostname + ", " + session);
            return true;
        };
        ((HttpsURLConnection) connection).setHostnameVerifier(hv);

        // Retrieve HTML files using Stream
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "JISAutoDetect"));
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }
        in.close();
    }

    /**
     * Implement an interface to check the trustworthiness of certificates.
     * (Enforce authentication even with untrusted certificates)
     */
    static class RelaxedX509TrustManager implements X509TrustManager {

        /**
         * Forcing authentication even with untrusted certificates (client authentication)
         */
        public boolean isClientTrusted(X509Certificate[] chain) {
Debug.println(chain);
            return true;
        }

        /**
         * Enforce authentication even with untrusted certificates.
         */
        public boolean isServerTrusted(X509Certificate[] chain) {
Debug.println(chain);
            return true;
        }

        /**
         * Return the certificate
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        /** */
        @Override
        public void checkClientTrusted(X509Certificate[] chain,
                                       String authType) {
Debug.println(Arrays.toString(chain) + ", " + authType);
        }

        /** */
        @Override
        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType) {
Debug.println(authType);
            for (X509Certificate x509Certificate : chain) {
                Debug.println(StringUtil.paramString(x509Certificate));
            }
        }
    }
}
