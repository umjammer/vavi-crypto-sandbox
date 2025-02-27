/*
 * Copyright (c) 2007 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;

import vavi.util.StringUtil;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;


/**
 * cipher test.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (vavi)
 * @version 0.00 070414 vavi initial version <br>
 */
public class Test22 {

    @Test
    void test() throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyPairGen.initialize(1024, random);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] data = "This ia an original message.".getBytes();
        byte[] encryptedData = cipher.doFinal(data);
System.err.println("encrypted\n" + StringUtil.getDump(encryptedData));

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
System.err.println("decrypted\n" + StringUtil.getDump(decryptedData));
        assertArrayEquals(data, decryptedData);
    }
}
