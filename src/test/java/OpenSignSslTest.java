/*
 * Copyright (c) 2003 by Naohide Sano, All rights rserved.
 *
 * Programmed by Naohide Sano
 */

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import vavi.util.Debug;


/**
 * opensign SSL.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (vavi)
 * @version 0.00 031217 nsano initial version <br>
 */
@EnabledOnOs(OS.WINDOWS)
public class OpenSignSslTest {

    /**
     * The program entry.
     */
    public static void main(String[] args) throws Exception {
        new OpenSignSslTest(args);
    }

    /** */
    public OpenSignSslTest(String[] args) throws Exception {
        URL url = new URL(args[0]);

        HttpURLConnection huc = (HttpURLConnection) url.openConnection();

        //----

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("MSKMF");
        kmf.init(null, null);
        KeyManager[] km = kmf.getKeyManagers();

        // Interface for determining the trustworthiness of a certificate
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("MSTMF");
        tmf.init((KeyStore) null);
        TrustManager[] tm = tmf.getTrustManagers();

        // Create an SSLContext that implements the socket protocol.
        SSLContext sslContext = SSLContext.getInstance("SSL");
        // Initialize SSLContext
        sslContext.init(km, tm, new SecureRandom());
        // Get the SocketFactory of the SSLContext
        SSLSocketFactory sslSF = sslContext.getSocketFactory();
        // Set SocketFactory in URLConnection
        ((HttpsURLConnection) huc).setSSLSocketFactory(sslSF);

        //----

        // Ignore the hostname
        HostnameVerifier hv = (hostname, session) -> {
Debug.println(hostname + ", "+ session);
            return true;
        };
        ((HttpsURLConnection) huc).setHostnameVerifier(hv);

        // Retrieve HTML files using Stream
        InputStream in = new BufferedInputStream(huc.getInputStream());
        OutputStream os = System.out;
        // Output to OutputStream
        byte[] bb = new byte[1024];
        int length = 0;
        while ((length = in.read(bb, 0, bb.length)) != -1) {
            os.write(bb, 0, length);
        }
        in.close();
    }
}
