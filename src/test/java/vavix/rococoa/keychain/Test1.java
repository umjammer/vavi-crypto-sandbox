/*
 * Copyright (c) 2022 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavix.rococoa.keychain;


import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import vavi.security.keychain.spi.KeyChainKeyStore;
import vavi.security.keychain.spi.KeyChainKeyStoreProvider;
import vavi.util.Debug;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * Test1.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2022/02/24 umjammer initial version <br>
 */
@DisabledIfEnvironmentVariable(named = "GITHUB_WORKFLOW", matches = ".*")
class Test1 {

    static {
        int r = Security.addProvider(new KeyChainKeyStoreProvider());
Debug.println("provider pos: " + r);
Arrays.asList(Security.getProviders()).forEach(System.err::println);
    }

    @Test
    @DisplayName("by direct")
    void test() throws Exception {
        // why this works w/o password??? (from keychain app, we need password)
        KeyChainKeyStore keyStore = new KeyChainKeyStore();
        keyStore.engineSetKeyEntry("nsano", "testvalue".getBytes(), null);
        String gotten = new String(keyStore.engineGetKey("nsano", null).getEncoded(), StandardCharsets.UTF_8);
        assertEquals("testvalue", gotten);

        keyStore = new KeyChainKeyStore();
        gotten = new String(keyStore.engineGetKey("nsano", null).getEncoded(), StandardCharsets.UTF_8);
        assertEquals("testvalue", gotten);
    }

    @Test
    @DisplayName("by spi")
    void test2() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("KeyChain", "KeyChain");
Debug.println("type: " + keyStore.getType() + ", provider: " + keyStore.getProvider().getName());
        keyStore.load(null, null);

        assertEquals("KeyChain", keyStore.getType());
        assertEquals("KeyChain", keyStore.getProvider().getName());

        keyStore.setKeyEntry("nsano", "testvalue".getBytes(), null);
        String gotten = new String(keyStore.getKey("nsano", null).getEncoded(), StandardCharsets.UTF_8);
        assertEquals("testvalue", gotten);

        keyStore = KeyStore.getInstance("KeyChain", "KeyChain");
        keyStore.load(null, null);

        gotten = new String(keyStore.getKey("nsano", null).getEncoded(), StandardCharsets.UTF_8);
        assertEquals("testvalue", gotten);
    }

    @Test
    void test3() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("KeyChain", "KeyChain");
        keyStore.load(null, null);

        keyStore.setKeyEntry("vavi1", "vavi1".getBytes(), null);
        keyStore.setKeyEntry("vavi2", "vavi2".getBytes(), null);
        String gotten = new String(keyStore.getKey("vavi1", null).getEncoded(), StandardCharsets.UTF_8);
Debug.println("gotten: " + gotten);
        assertEquals("vavi1", gotten);
        gotten = new String(keyStore.getKey("vavi2", null).getEncoded(), StandardCharsets.UTF_8);
        assertEquals("vavi2", gotten);
    }
}
