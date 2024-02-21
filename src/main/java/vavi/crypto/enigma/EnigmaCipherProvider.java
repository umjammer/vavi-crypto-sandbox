/*
 * Copyright (c) 2006 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.security.Provider;


/**
 * EnigmaCipherProvider.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 06xxxx nsano initial version <br>
 */
public final class EnigmaCipherProvider extends Provider {

    /** */
    public EnigmaCipherProvider() {
        super("EnigmaCipher", 1.03, "EnigmaCipherProvider implements Dr. Dobb's Enigma Cipher");
        put("Cipher.Enigma", "vavi.crypto.enigma.EnigmaCipher");
        put("SecretKeyFactory.Enigma", "vavi.crypto.enigma.EnigmaKeyFactory");
    }
}

/* */
