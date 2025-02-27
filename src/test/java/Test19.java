/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

import java.security.Provider;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * Crypt Example.
 *
 * @author <a href="mailto:hattori-f@klab.org">Fumitada Hattori</a>
 * @version 0.00 2005/02/07 hattori initial version <br>
 */
public class Test19 {

    /** */
    private static final byte[] key = "k3lmX0M9dmwAMvwOLm31NevEnreo7m32NeqiudR".getBytes();

    /** */
    DESKeySpec ks = null;

    /** */
    SecretKeyFactory kfact = null;

    /** */
    SecretKey sk = null;

    /** */
    public static String encode(String account, String password) throws Exception {

        int keyRange = key.length - 8;

        if (keyRange < 0) {
            throw new RuntimeException("The length of a key must be bigger than 8.");
        }

        Random random = new Random(System.currentTimeMillis());
        String offset = random.nextInt(keyRange) + "";

        if (offset.length() < 2) {
            offset = "0" + offset;
        }

        String accountLength = (account.length() < 10) ? ("0" + account.length()) : ("" + account.length());

        DESKeySpec ks = new DESKeySpec(key, Integer.parseInt(offset));
        SecretKeyFactory kfact = SecretKeyFactory.getInstance("DES");
        SecretKey sk = kfact.generateSecret(ks);
        Cipher ch = Cipher.getInstance("DES/ECB/PKCS5Padding");
        ch.init(Cipher.ENCRYPT_MODE, sk);

        return (offset + toHexString(ch.doFinal((accountLength + account + password).getBytes())));
    }

    /** */
    public static String[] decode(String encodedStr) throws Exception {
        int offset = Integer.parseInt(encodedStr.substring(0, 2));
        encodedStr = encodedStr.substring(2);

        DESKeySpec ks = new DESKeySpec(key, offset);
        SecretKeyFactory kfact = SecretKeyFactory.getInstance("DES");
        SecretKey sk = kfact.generateSecret(ks);
        Cipher ch = Cipher.getInstance("DES/ECB/PKCS5Padding");
        ch.init(Cipher.DECRYPT_MODE, sk);

        String accountPasswordPair = new String(ch.doFinal(toBytes(encodedStr)));
        int accountSize = Integer.parseInt(accountPasswordPair.substring(0, 2));
        accountPasswordPair = accountPasswordPair.substring(2);
        return new String[] {
            accountPasswordPair.substring(0, accountSize), accountPasswordPair.substring(accountSize)
        };
    }

    /** */
    public static String toHexString(byte[] bs) {

        StringBuilder buffer = new StringBuilder(bs.length * 2);
        for (byte b : bs) {
            if (b >= 0 && b < 0x10) {
                buffer.append('0');
            }
            buffer.append(Integer.toHexString(0xff & b));
        }
        return buffer.toString();
    }

    /** */
    public static byte[] toBytes(String hexString) throws NumberFormatException {

        if (hexString.length() % 2 == 1) {
            hexString = '0' + hexString;
        }
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = bytes.length - 1; i >= 0; i--) {
            String b = hexString.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) Integer.parseInt(b, 16);
        }
        return bytes;
    }

    @Test
    void test() throws Exception {

        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println(provider);
        }

//        Security.insertProviderAt(1, new com.sun.crypto.provider.SunJCE());

        String account = "hattori-f";
        String password = "hattori-f_pass";

System.out.println("account : " + account + ", password : " + password);

        String encodedStr = Test19.encode(account, password);

System.out.println("Encrypted String : " + encodedStr + "length : " + encodedStr.length());

        String[] decodedStrs = Test19.decode(encodedStr);

        System.out.println("account : " + decodedStrs[0] + ", password : " + decodedStrs[1]);

        assertEquals("hattori-f", decodedStrs[0]);
        assertEquals("hattori-f_pass", decodedStrs[1]);
    }
}
