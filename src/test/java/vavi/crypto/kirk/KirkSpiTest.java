/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import libkirk.KirkEngine;
import vavi.util.Debug;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static libkirk.Utilities.write32;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * KirkSpiTest.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public class KirkSpiTest {

    static {
        // the Cipher service needs to bypass the signed jar check using instrumentation
        int r = Security.addProvider(new KirkProvider());
Debug.println("pos: " + r);
    }

    private static final byte[] plain = "本日は晴天なり。KIRK is the PSP crypto engine.".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("sha1 (command 0xB), the same result as the raw engine")
    public void test00() throws Exception {
        MessageDigest md = MessageDigest.getInstance("KIRK-SHA1");
        assertEquals(20, md.getDigestLength());
        byte[] digest = md.digest(plain);

        // what jpcsp's KirkTest expects for 0x20 zero bytes
        byte[] zeros = new byte[0x20];
        assertArrayEquals(
                HexFormat.of().parseHex("DE8A847BFF8C343D69B853A215E6EE775EF2EF96"),
                MessageDigest.getInstance("KIRK-SHA1").digest(zeros));

        // the KIRK SHA-1 is a plain SHA-1
        assertArrayEquals(MessageDigest.getInstance("SHA-1").digest(plain), digest);

        // ... but the engine refuses empty data
        assertThrows(KirkException.class, () -> MessageDigest.getInstance("KIRK-SHA1").digest());
    }

    @Test
    @DisplayName("aes-128-cbc with a key table key (commands 0x4 and 0x7)")
    public void test01() throws Exception {
        SecretKey key = SecretKeyFactory.getInstance("KIRK").generateSecret(new KirkKeySpec(3));

        Cipher cipher = Cipher.getInstance("KIRK", "KIRK");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plain);
Debug.println("encrypted: " + encrypted.length + " bytes for " + plain.length);

        // the block keeps the header the engine needs to decrypt it back
        assertEquals(0x14 + (plain.length + 15 & ~15), encrypted.length);
        assertEquals(KirkEngine.KIRK_MODE_DECRYPT_CBC, encrypted[0]);
        assertFalse(Arrays.equals(plain, Arrays.copyOfRange(encrypted, 0x14, 0x14 + plain.length)));

        cipher.init(Cipher.DECRYPT_MODE, key);
        assertArrayEquals(plain, cipher.doFinal(encrypted));
    }

    @Test
    @DisplayName("aes-128-cbc with the fuse id key (commands 0x5 and 0x8)")
    public void test02() throws Exception {
        SecretKey key = new KirkKey(new KirkKeySpec(KirkKeySpec.FUSE));

        Cipher cipher = Cipher.getInstance("KIRK/CBC/NoPadding", "KIRK");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plain);

        cipher.init(Cipher.DECRYPT_MODE, key);
        assertArrayEquals(plain, cipher.doFinal(encrypted));

        // another key of the engine gives another block
        cipher.init(Cipher.ENCRYPT_MODE, new KirkKey(new KirkKeySpec(0)));
        assertFalse(Arrays.equals(encrypted, cipher.doFinal(plain)));
    }

    @Test
    @DisplayName("a CMD1 block, what the PSP executables are made of (commands 0x0 and 0x1)")
    public void test03() throws Exception {
        // the header of a CMD1 block carries the keys of the block itself
        byte[] block = new byte[0x90 + (plain.length + 15 & ~15)];
        byte[] keys = new byte[0x20]; // AES key and CMAC key
        SecureRandom.getInstance("KIRK-PRNG").nextBytes(keys);
        System.arraycopy(keys, 0, block, 0, keys.length);
        write32(block, 0x60, KirkEngine.KIRK_MODE_CMD1);
        write32(block, 0x70, plain.length); // data size
        write32(block, 0x74, 0); // data offset
        System.arraycopy(plain, 0, block, 0x90, plain.length);

        SecretKey key = new KirkKey(new KirkKeySpec(KirkKeySpec.KIRK1));

        Cipher cipher = Cipher.getInstance("KIRK", "KIRK");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(block);
Debug.println("CMD1 block: " + encrypted.length + " bytes");

        assertEquals(block.length, encrypted.length);

        cipher.init(Cipher.DECRYPT_MODE, key);
        assertArrayEquals(plain, cipher.doFinal(encrypted));
    }

    @Test
    @DisplayName("prng (command 0xE)")
    public void test04() throws Exception {
        SecureRandom random = SecureRandom.getInstance("KIRK-PRNG");
        byte[] bytes1 = new byte[100];
        byte[] bytes2 = new byte[100];
        random.nextBytes(bytes1);
        random.nextBytes(bytes2);
Debug.println("random: " + HexFormat.of().formatHex(bytes1));
        assertFalse(Arrays.equals(bytes1, bytes2));
        assertFalse(Arrays.equals(new byte[100], bytes1));
    }

    @Test
    @DisplayName("ecdsa (commands 0xC, 0x10 and 0x11)")
    public void test05() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("KIRK-ECDSA");
        generator.initialize(160);
        KeyPair keyPair = generator.generateKeyPair();
Debug.println("public key: " + ((KirkPublicKey) keyPair.getPublic()).getW());

        assertEquals(20, keyPair.getPrivate().getEncoded().length);
        assertEquals(40, keyPair.getPublic().getEncoded().length);
        assertNotNull(Kirk.CURVE.getGenerator());

        Signature signature = Signature.getInstance("SHA1withKIRKECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(plain);
        byte[] signed = signature.sign();
Debug.println("signature: " + HexFormat.of().formatHex(signed));
        assertEquals(40, signed.length);

        signature.initVerify(keyPair.getPublic());
        signature.update(plain);
        assertTrue(signature.verify(signed));

        // a modified message does not verify
        byte[] modified = plain.clone();
        modified[0] ^= 1;
        signature.initVerify(keyPair.getPublic());
        signature.update(modified);
        assertFalse(signature.verify(signed));
    }
}
