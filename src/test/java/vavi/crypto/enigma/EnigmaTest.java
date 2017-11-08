/*
 * Copyright (c) 2012 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.junit.Test;

import vavi.crypto.enigma.EnigmaCipher;
import vavi.crypto.enigma.EnigmaMachine;
import vavi.crypto.enigma.EnigmaReflector;
import vavi.crypto.enigma.EnigmaRotor;

import static org.junit.Assert.assertEquals;


/**
 * EnigmaTest.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2012/09/19 umjammer initial version <br>
 */
public class EnigmaTest {

    @Test
    public void test01() throws Exception {
        EnigmaMachine enigma = new EnigmaMachine(new EnigmaRotor[] { new EnigmaRotor(1, 1) }, new EnigmaReflector(1));
        byte[] in = "naohidesano1234".getBytes();
        byte[] out = new byte[in.length];
        enigma.processMessage(in, 0, out, 0, in.length);
        byte[] result = new byte[in.length];
        enigma.processMessage(out, 0, result, 0, in.length);
        assertEquals(in, result);
    }

    /** */
    @Test
    public void test02() throws Exception {
        EnigmaCipher cipher = new EnigmaCipher();
        SecureRandom random = new SecureRandom();
        Key key = new EnigmaCipher.CamelliaKey("sanonaohide01234");
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, random);
        String plain = "本日は晴天なり。";
        byte[] input = plain.getBytes("UTF-8");
        byte[] encrypted = cipher.engineDoFinal(input, 0, input.length);
//System.err.println("encrypted: " + encrypted.length);
        cipher.engineInit(Cipher.DECRYPT_MODE, key, random);
        byte[] decrypted = cipher.engineDoFinal(encrypted, 0, encrypted.length);
System.err.println(new String(decrypted, "UTF-8"));
        assertEquals(plain, new String(decrypted, "UTF-8"));
    }
}

/* */
