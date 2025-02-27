/*
 * Copyright (c) 2022 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.security.keychain.spi;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import vavix.rococoa.keychain.KeychainPasswordStore;


/**
 * KeyChainKeyStore.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2022/02/25 umjammer initial version <br>
 */
public final class KeyChainKeyStore extends KeyStoreSpi {

    /** */
    private final KeychainPasswordStore keychain = new KeychainPasswordStore();

    // TODO how to set, property?
    private final String serviceName = "vavi.security.keychain.spi.KeyChainKeyStore";

    /** */
    public static class KeyChainKey implements Key {
        final String value;
        KeyChainKey(String value) {
            this.value = value;
        }
        @Override
        public String getAlgorithm() {
            return null;
        }
        @Override
        public String getFormat() {
            return "B]";
        }
        /** utf8 encoded byte array */
        @Override
        public byte[] getEncoded() {
            return value.getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return new KeyChainKey(keychain.getPassword(serviceName, alias));
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        keychain.addPassword(serviceName, alias, new String(key));
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        keychain.deletePassword(serviceName, alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        // TODO how to get?
        return null;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return keychain.getPassword(serviceName, alias) != null;
    }

    @Override
    public int engineSize() {
        // TODO how to know?
        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void engineStore(OutputStream stream,
                            char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    }

    @Override
    public void engineLoad(InputStream stream,
                           char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    }
}
