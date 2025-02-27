/*
 * Copyright (c) 2001 Brian Boyter
 * All rights reserved
 *
 * This software is released subject to the GNU Public License.  See
 * the full license included with this distribution.
 */

package com.boyter.mscrypto;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.net.ssl.X509TrustManager;

import com.boyter.mscrypto.MSCryptoManager.Flag;

import static java.lang.System.getLogger;


/**
 * MSTrustManagerImpl.
 *
 * @author Brian Boyter
 * @version 0.00 050314 nsano modified <br>
 */
final class MSTrustManagerImpl implements X509TrustManager {

    private static final Logger logger = getLogger(MSTrustManagerImpl.class.getName());

    /** */
    private static final MSCryptoManager msCryptoManager = MSCryptoManager.getInstance();

    /**
     * @param ks this method use windows key store, this means nothing, so set null
     */
    MSTrustManagerImpl(KeyStore ks) throws KeyStoreException {
    }

    /**
     * Reads Microsoft certificate store
     * Returns array of trusted root CA certificates
     */
    public X509Certificate[] getAcceptedIssuers() {

        // Object[] objarray = null;
        X509Certificate[] caArray = null;

        try {
logger.log(Level.DEBUG, "getAcceptedIssuers: entered");

            CertStore caCerts = msCryptoManager.getCaCerts();

            X509CertSelector xcs = new X509CertSelector();
            xcs.setCertificateValid(new Date());

            Collection<? extends Certificate> certcollection = caCerts.getCertificates(xcs);
logger.log(Level.DEBUG, "getAcceptedIssuers: " + certcollection.size() + " certs found");

            caArray = new X509Certificate[certcollection.size()];
            caArray = certcollection.toArray(caArray);

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

//for (int i = 0; i < caArray.length; i++) {
//logger.log(Level.TRACE, "(" + i + ") " + caArray[i].getSubjectDN());
//}

        return caArray;
    }

    /**
     * Returns true if the client is authorized to access the server.
     * @throws CertificateException Client Certificate is not trusted
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        Flag dontKnowFlag = Flag.AskTheUser;

logger.log(Level.DEBUG, ">>>>>>>> checkClientTrusted: Entered: " + authType);

        try {
            msCryptoManager.isCertChainValid(chain, dontKnowFlag);
        } catch (CertificateException e) {
logger.log(Level.DEBUG, e);
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns true if the server is authorized to access the client.
     * @throws CertificateException Server Certificate is not trusted
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        Flag dontKnowFlag = Flag.AskTheUser;

logger.log(Level.DEBUG, ">>>>>>>> checkServerTrusted: Entered: " + authType);

        try {
            msCryptoManager.isCertChainValid(chain, dontKnowFlag);
        } catch (CertificateException e) {
logger.log(Level.DEBUG, e);
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
