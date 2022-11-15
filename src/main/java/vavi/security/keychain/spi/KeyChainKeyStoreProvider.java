/*
 * Copyright (c) 2006 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.security.keychain.spi;

import java.security.Provider;


/**
 * KeyChainKeyStoreProvider.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 06xxxx nsano initial version <br>
 */
public final class KeyChainKeyStoreProvider extends Provider {

    /** */
    public KeyChainKeyStoreProvider() {
        super("KeyChain", 1.02, "KeyChainKeyStoreProvider implements KeyStore for Mac KeyChain");
        put("KeyStore.KeyChain", "vavi.security.keychain.spi.KeyChainKeyStore");
        put("Key.KeyChain", "vavi.security.keychain.spi.KeyChainKeyStore.KeyChainKey");
    }
}

/* */
