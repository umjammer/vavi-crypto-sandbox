/*
 * Copyright (c) 2012 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import vavi.util.Debug;
import vavi.util.StringUtil;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * EnigmaTest.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2012/09/19 umjammer initial version <br>
 */
public class EnigmaTest {

    @Test
    @Disabled("doen't work, how to use? lost source site")
    public void test01() throws Exception {
        SecureRandom random = new SecureRandom();
        EnigmaMachine enigma = new EnigmaMachine(new EnigmaRotor[] { new EnigmaRotor(random, 4), new EnigmaRotor(random, 11), new EnigmaRotor(random, 6) }, new EnigmaReflector(random));
        byte[] in = "naohidesano1234".getBytes();
        byte[] out = new byte[in.length];
        enigma.processMessage(in, 0, out, 0, in.length);
Debug.println("\n" + StringUtil.getDump(out));
        byte[] result = new byte[in.length];
        enigma.processMessage(out, 0, result, 0, in.length);
Debug.println("\n" + StringUtil.getDump(result));
        assertEquals(in, result);
    }

    @Test
    @Disabled("not completed yet")
    @DisplayName("jce raw")
    public void test02() throws Exception {
        EnigmaCipher cipher = new EnigmaCipher();
        Key key = new EnigmaCipher.EnigmaKey("sanonaohide01234");
        SecureRandom random = new SecureRandom();
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, random);
        String plain = "本日は晴天なり。";
        byte[] input = plain.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.engineDoFinal(input, 0, input.length);
//System.err.println("encrypted: " + encrypted.length);
        cipher.engineInit(Cipher.DECRYPT_MODE, key, random);
        byte[] decrypted = cipher.engineDoFinal(encrypted, 0, encrypted.length);
System.err.println(new String(decrypted, StandardCharsets.UTF_8));
        assertEquals(plain, new String(decrypted, StandardCharsets.UTF_8));
    }
}

/* */
