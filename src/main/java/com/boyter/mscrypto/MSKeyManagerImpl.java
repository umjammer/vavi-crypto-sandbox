/*
 * Copyright (c) 2001 Brian Boyter
 * All rights reserved
 *
 * This software is released subject to the GNU Public License.  See
 * the full license included with this distribution.
 */

package com.boyter.mscrypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.X509KeyManager;

import com.boyter.mscrypto.MSCryptoManager.Flag;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.getLogger;


/**
 * MSKeyManagerImpl.
 *
 * @author Brian Boyter
 * @version 0.00 050314 nsano modified <br>
 */
final class MSKeyManagerImpl implements X509KeyManager {

    private static final Logger logger = getLogger(MSKeyManagerImpl.class.getName());

    /**
     * @param ks use windows key store, so this means nothing, set null
     * @param passphrase use windows key store, so this means nothing, set null
     */
    MSKeyManagerImpl(KeyStore ks, char[] passphrase) throws KeyStoreException {
    }

    /** native interface */
    private static final MSCryptoManager msCryptoManager = MSCryptoManager.getInstance();

    /**
     * Choose an alias to authenticate the client side of a secure socket given
     * the public key type and the list of certificate issuer authorities
     * recognized by the peer (if any).
     */
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        String alias = null;

logger.log(DEBUG, ">>>> chooseClientAlias: entered: issures: " + issuers.length + ", types: " + keyType.length);

        try {
            List<String> aliases = new ArrayList<>();
            for (int i = 0; i < keyType.length; i++) {
logger.log(DEBUG, i + ": " + keyType[i]);
                String[] tmp = getClientAliases(keyType[i], issuers);
                aliases.addAll(Arrays.asList(tmp));
            }
            if (aliases.isEmpty()) {
logger.log(DEBUG, "chooseClientAlias: something wrong - no aliases");
                return null;
            }
logger.log(DEBUG, "aliases: " + aliases.size());
            alias = aliases.get(0);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

logger.log(DEBUG, "<<<< chooseClientAlias: " + alias);
        return alias;
    }

    /**
     * Choose an alias to authenticate the server side of a secure socket given
     * the public key type and the list of certificate issuer authorities
     * recognized by the peer (if any).
     */
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String alias = null;

logger.log(DEBUG, ">>>> chooseServerAlias: return server alias");

        try {
            String[] aliases = getServerAliases(keyType, issuers);
            if (aliases == null) {
logger.log(DEBUG, "chooseServerAlias: something wrong - no aliases");
                return null;
            }
            alias = aliases[0];
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

logger.log(DEBUG, "<<<< chooseServerAlias: " + alias);

        return alias;
    }

    /**
     * Returns the certificate chain to validate the given alias.
     */
    public X509Certificate[] getCertificateChain(String alias) {

logger.log(DEBUG, ">>>> getCertificateChain: entered, alias:" + alias);

        X509Certificate[] certChain = null;
        X509Certificate cert = null;

        try {
            byte[] certBlob = msCryptoManager.getCert("My", alias);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(certBlob);
            cert = (X509Certificate) cf.generateCertificate(bais);
            bais.close();

            certChain = msCryptoManager.getCertChain(cert);

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

logger.log(DEBUG, "<<<< getCertificateChain: certChain:" + (certChain != null ? certChain.length : -1));
        return certChain;
    }

    /**
     * Get the matching aliases for authenticating the client side of a secure
     * socket given the public key type and the list of certificate issuer
     * authorities recognized by the peer (if any).
     */
    public String[] getClientAliases(String keyType, Principal[] issuers) {
logger.log(DEBUG, ">>>> getClientAliases: entered: " + keyType);
        String[] validAliases = null;

        try {
            String[] aliases = msCryptoManager.getAliases("My");
            if (aliases == null) {
                throw new IllegalStateException("No client aliases found");
            }

            // now throw out any aliases not signed by an approved issuer,
            // expired, or revoked
logger.log(DEBUG, "Number of accepted issuers: " + (issuers != null ? issuers.length : -1));
            validAliases = checkAlias(aliases, issuers);

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

logger.log(DEBUG, "<<<< aliases found: " + validAliases.length);
        for (String validAlias : validAliases) {
            logger.log(DEBUG, "getClientAliases: alias: " + validAlias);
        }

        return validAliases;
    }

    /**
     * Get the matching aliases for authenticating the server side of a secure
     * socket given the public key type and the list of certificate issuer
     * authorities recognized by the peer (if any).
     */
    public String[] getServerAliases(String keyType, Principal[] issuers) {
logger.log(DEBUG, "<<<< getServerAliases: return array of aliases ");
        String[] validAliases = null;

        try {
            String[] aliases = msCryptoManager.getAliases("My");
            if (aliases == null) {
logger.log(DEBUG, ">>>> No server aliases found");
                return null;
            }

            // now throw out any aliases not signed by an approved issuer,
            // expired, or revoked
            validAliases = checkAlias(aliases, issuers);

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

logger.log(DEBUG, ">>>> aliases found: " + validAliases.length);
        for (String validAlias : validAliases) {
            logger.log(DEBUG, "getServerAliases: alias: " + validAlias);
        }

        return validAliases;
    }

    /**
     * returns the RSA private key for the given alias
     */
    public PrivateKey getPrivateKey(String alias) {
        RSAPrivateKey rsaprivkey = null;
        RSAPrivateCrtKey rsaprivcrtkey = null;
        BigInteger mod = null;
        BigInteger exp = null;
        BigInteger coeff = null;
        BigInteger p = null;
        BigInteger q = null;
        BigInteger expp = null;
        BigInteger expq = null;
        BigInteger pubExp = null;
        byte[] pubExpBlob = new byte[4];
        byte[] keySizeBlob = new byte[4];
        int keySize;

logger.log(DEBUG, "<<<< getPrivateKey: entered, alias: " + alias);

        try {
            byte[] keyblob = msCryptoManager.getPrivateKey(alias);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            if (keyblob == null) { // generate a dummy key
                byte[] modblob = new byte[128];
                for (int i = 0; i < 128; i++) {
                    modblob[i] = 127;
                }
                mod = new BigInteger(modblob);
                exp = mod;

                RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(mod, exp);
                rsaprivkey = (RSAPrivateKey) kf.generatePrivate(privKeySpec);

logger.log(DEBUG, "getPrivateKey: normal exit");
                return rsaprivkey;

            } else { // use the key that got exported
                for (int i = 0; i < 4; i++) {
                    pubExpBlob[i] = keyblob[19 - i];
                    keySizeBlob[i] = keyblob[15 - i];
                }
                BigInteger bigKeySize = new BigInteger(keySizeBlob);
                keySize = bigKeySize.intValue();
logger.log(DEBUG, "keysize: " + keySize);

                byte[] modBlob = new byte[(keySize / 8)];
                byte[] expBlob = new byte[(keySize / 8)];
                byte[] pBlob = new byte[keySize / 16];
                byte[] qBlob = new byte[keySize / 16];
                byte[] exppBlob = new byte[keySize / 16];
                byte[] expqBlob = new byte[keySize / 16];
                byte[] coefBlob = new byte[keySize / 16];

                for (int i = 0; i < keySize / 8; i++) {
                    modBlob[i] = keyblob[19 - i + (keySize / 16) * 2];
                    expBlob[i] = keyblob[19 - i + (keySize / 16) * 9];
                }

                for (int i = 0; i < keySize / 16; i++) {
                    pBlob[i] = keyblob[19 - i + (keySize / 16) * 3];
                    qBlob[i] = keyblob[19 - i + (keySize / 16) * 4];
                    exppBlob[i] = keyblob[19 - i + (keySize / 16) * 5];
                    expqBlob[i] = keyblob[19 - i + (keySize / 16) * 6];
                    coefBlob[i] = keyblob[19 - i + (keySize / 16) * 7];
                }

                mod = new BigInteger(1, modBlob);
                exp = new BigInteger(1, expBlob);
                coeff = new BigInteger(1, coefBlob);
                p = new BigInteger(1, pBlob);
                q = new BigInteger(1, qBlob);
                expp = new BigInteger(1, exppBlob);
                expq = new BigInteger(1, expqBlob);
                pubExp = new BigInteger(1, pubExpBlob);

                RSAPrivateCrtKeySpec privCrtKeySpec = new RSAPrivateCrtKeySpec(mod, pubExp, exp, p, q, expp, expq, coeff);
                rsaprivcrtkey = (RSAPrivateCrtKey) kf.generatePrivate(privCrtKeySpec);
            }
        } catch (Exception e) {
            logger.log(Level.ERROR, ">>>> " + e);
//            throw new IllegalStateException(e);
        }

//logger.log(Level.TRACE, "mod: " + rsaprivcrtkey.getModulus());
//logger.log(Level.TRACE, "pubexp: " + rsaprivcrtkey.getPublicExponent());
//logger.log(Level.TRACE, "privexp: " + rsaprivcrtkey.getPrivateExponent());
//logger.log(Level.TRACE, "p: " + rsaprivcrtkey.getPrimeP());
//logger.log(Level.TRACE, "q: " + rsaprivcrtkey.getPrimeQ());
//logger.log(Level.TRACE, "expp: " + rsaprivcrtkey.getPrimeExponentP());
//logger.log(Level.TRACE, "expq: " + rsaprivcrtkey.getPrimeExponentQ());
//logger.log(Level.TRACE, "coeff: " + rsaprivcrtkey.getCrtCoefficient());

if (rsaprivcrtkey != null) {
logger.log(DEBUG, ">>>> getPrivateKey: normal exit");
}
        return rsaprivcrtkey;
    }

    /**
     * remove any aliases not signed by an approved issuer,
     * expired, or revoked
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private static String[] checkAlias(String[] aliases, Principal[] issuers) throws GeneralSecurityException, IOException {

logger.log(DEBUG, ">>>> CheckAlias: entered");
        X509Certificate cert = null;
        List<String> aliasList = new ArrayList<>();
        List<String> issuerList = new ArrayList<>();

logger.log(DEBUG, "aliases: " + aliases.length);
logger.log(DEBUG, "issuers: " + (issuers != null ? issuers.length : -1));
        Collections.addAll(aliasList, aliases);

        if (issuers != null) {
            for (Principal issuer : issuers) {
                issuerList.add(issuer.toString());
            }
        }

        // iterate thru the list of aliases
        Iterator<String> iter = aliasList.iterator();
        while (iter.hasNext()) {
            String alias = iter.next();

            // get the cert for this alias
            byte[] certBlob = msCryptoManager.getCert("My", alias);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream input = new ByteArrayInputStream(certBlob);
            cert = (X509Certificate) cf.generateCertificate(input);
            input.close();

            // is this alias's cert signed by an approved issuer?
            if (!issuerList.isEmpty()) {
                String certIssuer = cert.getIssuerDN().toString();
logger.log(DEBUG, "CheckAlias: certIssuer: " + certIssuer);
                if (!issuerList.contains(certIssuer)) {
                    iter.remove();
logger.log(DEBUG, "CheckAlias: no issuer found for alias " + alias);
                    continue;
                }
            }

            if (!msCryptoManager.isCertValid(cert, Flag.AcceptTheCertAnyway)) {
                iter.remove();
logger.log(DEBUG, "CheckAlias: cert is expired or revoked for alias " + alias);
                continue;
            }

logger.log(DEBUG, "CheckAlias: alias is valid " + alias);
        }

        aliases = new String[aliasList.size()];
        aliasList.toArray(aliases);

logger.log(DEBUG, "<<<< CheckAlias: valid aliases: " + aliases.length);
        return aliases;
    }
}
