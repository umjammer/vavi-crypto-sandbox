/*
 * Copyright (c) 2006 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.camellia;

import java.security.Provider;


/**
 * CamelliaCipherProvider.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 06xxxx nsano initial version <br>
 */
public final class CamelliaCipherProvider extends Provider {

    /** */
    public CamelliaCipherProvider() {
        super("Camellia", 1.03, "CamelliaCipherProvider implements NTT Camellia Decryption");
        put("Cipher.Camellia", "vavi.crypto.camellia.CamelliaCipher");
        put("SecretKeyFactory.Camellia", "vavi.crypto.camellia.CamelliaKeyFactory");
    }
}

/* */
