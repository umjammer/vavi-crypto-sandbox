/*
 * Copyright (c) 2012 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import com.beechwood.crypto.chipher.enigma.EnigmaMachine;
import com.beechwood.crypto.chipher.enigma.EnigmaReflector;
import com.beechwood.crypto.chipher.enigma.EnigmaRotor;
import vavi.crypto.enigma.EnigmaCipher.EnigmaKey;
import vavi.crypto.enigma.EnigmaCipher.EnigmaKeySpec;
import vavi.util.ByteUtil;
import vavi.util.Debug;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * EnigmaTest.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2012/09/19 umjammer initial version <br>
 */
public class EnigmaTest {

    static {
        // this needs to bypass security check using instrumentation
        int r = Security.addProvider(new EnigmaCipherProvider());
Debug.println("pos: " + r);
        Arrays.asList(Security.getProviders()).forEach(System.err::println);
    }

    /**
     * @see "https://gemini.google.com/app/7d8b01302d357aa8"
     */
    @Test
    @DisplayName("provided enigma components")
    void test01() throws Exception {
        // Configuration for the machines (Alice and Bob must share these)
        long sharedKeySeed = 123456789L; // Used to generate identical wiring
        int rotorCount = 3;
        int[] notchPositions = {50, 100, 150}; // Where the rotors trigger the next one
        int[] startPositions = {10, 20, 30};   // Initial rotor offsets

        // --- 1. Encryption (Alice) ---
        System.out.println("--- Encryption ---");
        EnigmaMachine aliceMachine = createMachine(sharedKeySeed, rotorCount, notchPositions, startPositions);

        String originalMessage = "Hello Enigma World";
        byte[] plainBytes = originalMessage.getBytes();
        byte[] encryptedBytes = new byte[plainBytes.length];

        // Process the message
        aliceMachine.processMessage(plainBytes, 0, encryptedBytes, 0, plainBytes.length);

        System.out.println("Original:  " + originalMessage);
        System.out.println("Encrypted: " + ByteUtil.toHexString(encryptedBytes));

        // --- 2. Decryption (Bob) ---
        System.out.println("\n--- Decryption ---");

        // Critical: We must create a FRESH machine with the SAME seed and parameters
        // to reproduce the exact state (wiring + initial positions).
        EnigmaMachine bobMachine = createMachine(sharedKeySeed, rotorCount, notchPositions, startPositions);

        byte[] decryptedBytes = new byte[encryptedBytes.length];

        // Process the ciphertext
        bobMachine.processMessage(encryptedBytes, 0, decryptedBytes, 0, encryptedBytes.length);

        String decryptedMessage = new String(decryptedBytes);
        System.out.println("Decrypted: " + decryptedMessage);

        assertEquals(originalMessage, decryptedMessage);
    }

    /**
     * Factory method to create an EnigmaMachine with deterministic wiring based on a seed.
     */
    private static EnigmaMachine createMachine(long seed, int count, int[] notches, int[] starts) throws Exception {
        // Use SHA1PRNG to ensure the random sequence is deterministic based on the seed
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(seed);

        // 1. Create the Reflector (Consumes random bytes for wiring)
        EnigmaReflector reflector = new EnigmaReflector(random);

        // 2. Create the Rotors (Consume random bytes for wiring)
        EnigmaRotor[] rotors = new EnigmaRotor[count];
        for (int i = 0; i < count; i++) {
            // Ensure we don't go out of bounds if params are shorter than count
            int notch = (i < notches.length) ? notches[i] : 0;
            int start = (i < starts.length) ? starts[i] : 0;

            rotors[i] = new EnigmaRotor(random, notch, start);
        }

        return new EnigmaMachine(rotors, reflector);
    }

    @Test
    @DisplayName("jce raw")
    public void test02() throws Exception {
        // shared secret key
        Key key = new EnigmaKey(new EnigmaKeySpec(123456789L, 3, new int[] {50, 100, 150}, new int[] {10, 20, 30}));
        String plain = "本日は晴天なり。";
        byte[] input = plain.getBytes(StandardCharsets.UTF_8);

        // alice side
        EnigmaCipher aliceCipher = new EnigmaCipher();
        SecureRandom aliceRandom = SecureRandom.getInstance("SHA1PRNG");
        aliceCipher.engineInit(Cipher.ENCRYPT_MODE, key, aliceRandom);
        byte[] encrypted = aliceCipher.engineDoFinal(input, 0, input.length);
Debug.println("encrypted: " + encrypted.length + ", " + ByteUtil.toHexString(encrypted));

        // bob side
        EnigmaCipher bobCipher = new EnigmaCipher();
        // the reason why new random is needed ... https://copilot.microsoft.com/chats/NNJGcjm7eJG7WmGRmgdtG
        SecureRandom bobRandom = SecureRandom.getInstance("SHA1PRNG");
        bobCipher.engineInit(Cipher.DECRYPT_MODE, key, bobRandom);
        byte[] decrypted = bobCipher.engineDoFinal(encrypted, 0, encrypted.length);
Debug.println(new String(decrypted, StandardCharsets.UTF_8));

        assertEquals(plain, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("jce")
    public void test03() throws Exception {
        // shared secret key
        KeySpec keySpec = new EnigmaKeySpec(123456789L, 3, new int[] {50, 100, 150}, new int[] {10, 20, 30});
        Key key = SecretKeyFactory.getInstance("Enigma").generateSecret(keySpec);
        String plain = "本日は晴天なり。";
        byte[] input = plain.getBytes(StandardCharsets.UTF_8);

        // alice side
        Cipher aliceCipher = Cipher.getInstance("Enigma", "Enigma");
        SecureRandom aliceRandom = SecureRandom.getInstance("SHA1PRNG");
        aliceCipher.init(Cipher.ENCRYPT_MODE, key, aliceRandom);
        byte[] encrypted = aliceCipher.doFinal(input, 0, input.length);
        Debug.println("encrypted: " + encrypted.length + ", " + ByteUtil.toHexString(encrypted));

        // bob side
        Cipher bobCipher = Cipher.getInstance("Enigma", "Enigma");
        SecureRandom bobRandom = SecureRandom.getInstance("SHA1PRNG");
        bobCipher.init(Cipher.DECRYPT_MODE, key, bobRandom);
        byte[] decrypted = bobCipher.doFinal(encrypted, 0, encrypted.length);
        Debug.println(new String(decrypted, StandardCharsets.UTF_8));

        assertEquals(plain, new String(decrypted, StandardCharsets.UTF_8));
    }
}
