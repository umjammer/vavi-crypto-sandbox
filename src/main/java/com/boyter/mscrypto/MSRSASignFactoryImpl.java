/*
 * Copyright (c) 2001 Brian Boyter
 * All rights reserved
 *
 * This software is released subject to the GNU Public License.  See
 * the full license included with this distribution.
 */

package com.boyter.mscrypto;

import java.lang.System.Logger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.getLogger;


/**
 * MSRSASignFactoryImpl.
 *
 * @author Brian Boyter
 * @version 0.00 050604 nsano modified <br>
 */
public class MSRSASignFactoryImpl extends SignatureSpi {

    private static final Logger logger = getLogger(MSRSASignFactoryImpl.class.getName());

    /** */
    private static final MSCryptoManager msCryptoManager = MSCryptoManager.getInstance();

    /** */
    private static boolean signOpInProgress = false;

    /** */
    private static boolean verifyOpInProgress = false;

    /** */
    private static Signature jsse;

    /** */
    private static MessageDigest md;

    /** */
    private static String messageDigestType;

    /**
     * @throws NoSuchAlgorithmException
     */
    protected static void setMessageDigestType(String mdType) throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance(mdType);
        messageDigestType = mdType;

logger.log(DEBUG, "MSRSASignFactoryImpl:setMessageDigestType " + mdType);
    }

    /** */
    protected Object engineGetParameter(String param) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineGetParameter: not implemented");
        return null;
    }

    /**
     * This method is overridden by providers to initialize this signature
     * engine with the specified parameter set.
     */
    protected void engineSetParameter(AlgorithmParameterSpec params) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineSetParameter: not implemented");
    }

    /**
     * Deprecated. Replaced by engineSetParameter(AlgorithmParameterSpec params)
     */
    protected void engineSetParameter(String param, Object value) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineSetParameter: not implemented");
    }

    /**
     * Initializes this signature object with the specified private key for
     * signing operations.
     */
    protected void engineInitSign(PrivateKey privateKey) {

logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineInitSign: entered");

        signOpInProgress = true;
        verifyOpInProgress = false;
    }

    /**
     * Returns the signature bytes of all the data updated so far.
     */
    protected byte[] engineSign() {

logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineSign: entered");

        if (!signOpInProgress) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: error - throw exception");
            return null;
        }

        byte[] hash = md.digest();
        byte[] mssig = msCryptoManager.getRSASignHash(hash, null, messageDigestType);
        signOpInProgress = false;
        return mssig;
    }

    /**
     * Finishes this signature operation and stores the resulting signature
     * bytes in the provided buffer outbuf, starting at offset.
     * returns the number of bytes placed into outbuf
     */
    protected int engineSign(byte[] outbuf, int offset, int len) {

logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineSign: entered");

        if (!signOpInProgress) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: error - throw exception");
            return 0;
        }

        byte[] hash = md.digest();
        byte[] mssig = msCryptoManager.getRSASignHash(hash, null, messageDigestType);
        System.arraycopy(mssig, 0, outbuf, offset, mssig.length);
        signOpInProgress = false;
        return mssig.length;
    }

    /**
     * Updates the data to be signed or verified using the specified byte.
     */
    protected void engineUpdate(byte b) {

logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineUpdate: entered");

        try {
            if (signOpInProgress) {
                md.update(b);
            } else if (verifyOpInProgress) {
                jsse.update(b);
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Updates the data to be signed or verified, using the specified array
     * of bytes, starting at the specified offset.
     */
    protected void engineUpdate(byte[] data, int off, int len) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineUpdate: entered");

        try {
            if (signOpInProgress) {
                md.update(data, off, len);
            } else if (verifyOpInProgress) {
                jsse.update(data, off, len);
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Initializes this signature object with the specified public key for
     * verification operations.
     */
    protected void engineInitVerify(PublicKey publicKey) {

logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineInitVerify: entered");

        try {
            String SignatureAlg = messageDigestType + "withRSA";
            jsse = Signature.getInstance(SignatureAlg, "SunJSSE");
            jsse.initVerify(publicKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        signOpInProgress = false;
        verifyOpInProgress = true;
    }

    /**
     * Verifies the passed-in signature.
     */
    protected boolean engineVerify(byte[] sigBytes) {
        boolean verifyresult = false;
logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineVerify: entered");

        if (!verifyOpInProgress) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: error - throw exception");
            return false;
        }

        try {
            verifyresult = jsse.verify(sigBytes);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return verifyresult;
    }

    /**
     * Verifies the passed-in signature in the specified array of bytes,
     * starting at the specified offset.
     */
    protected boolean engineVerify(byte[] sig, int off, int len) {
        boolean verifyresult = false;
logger.log(DEBUG, "MSSHARSASignFactoryImpl: engineVerify: entered");

        if (!verifyOpInProgress) {
logger.log(DEBUG, "MSSHARSASignFactoryImpl: error - throw exception");
            return false;
        }

        try {
            verifyresult = jsse.verify(sig, off, len);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return verifyresult;
    }
}
