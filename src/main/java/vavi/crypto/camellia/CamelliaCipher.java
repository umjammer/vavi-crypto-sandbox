/*
 * Copyright (c) 2009 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.camellia;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;


/**
 * CamelliaCipher.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 2009/02/22 nsano initial version <br>
 */
public final class CamelliaCipher extends CipherSpi {

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        byte[] output = engineUpdate(input, inputOffset, inputLen);
        finalized = true;
        return output;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outputLen = engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        finalized = true;
        return outputLen;
    }

    @Override
    protected int engineGetBlockSize() {
        return 4;
    }

    @Override
    protected byte[] engineGetIV() {
        throw new UnsupportedOperationException();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            int pad = inputLen % engineGetBlockSize();
            return (inputLen + (pad == 0 ? 0 : engineGetBlockSize() - pad)) * 4;
        } else {
            return inputLen / 4;
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException();
    }

    /** */
    private final Camellia camellia = new Camellia();

    /** */
    private boolean finalized = false;

    /** */
    private int opmode;

    /** */
    private final int[] keyTable = new int[52];

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;

        int[] keyInts = new int[16];
        byte[] keyBytes = key.getEncoded();
        for (int i = 0; i < keyBytes.length; i++) {
            keyInts[i] = keyBytes[i] & 0xff;
        }

        camellia.genEkey(keyInts, keyTable);

        finalized = false;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[engineGetOutputSize(input.length)];
        try {
            engineUpdate(input, inputOffset, inputLen, output, 0);
        } catch (ShortBufferException e) {
            assert false : e;
        }
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if (finalized) {
            throw new IllegalStateException("finalized"); // TODO check
        }

        int blockSize = engineGetBlockSize();

        int[] in = new int[4];
        int[] out = new int[4];

        if (opmode == Cipher.ENCRYPT_MODE) {
            byte[] dataBytes = new byte[engineGetOutputSize(inputLen) / 4];
//logger.log(Level.TRACE, "dataBytes: " + dataBytes.length);
            System.arraycopy(input, inputOffset, dataBytes, 0, inputLen);

            for (int i = 0; i < dataBytes.length; i += blockSize) {
                for (int j = 0; j < blockSize; j++) {
                    in[j] = dataBytes[i + j] & 0xff;
                }
                camellia.encryptBlock(in, keyTable, out);
                for (int j = 0; j < blockSize; j++) {
                    // TODO consider endian
                    for (int k = 0; k < 4; k++) {
                        output[outputOffset + i * 4 + j * 4 + k] = (byte) (out[j] >> ((3 - k) * 8));
//logger.log(Level.TRACE, "Y[%02d] %02x".formatted(outputOffset + i * 4 + j * 4 + k, output[outputOffset + i + j * 4 + k]));
                    }
//logger.log(Level.TRACE, "E: in[%02d]=%02x, out[%02d]=%08x".formatted(inputOffset + i + j, dataBytes[i + j], outputOffset + i + j, out[j]));
                }
            }
        } else if (opmode == Cipher.DECRYPT_MODE) {
//logger.log(Level.TRACE, "inputLen: " + inputLen / 4);
            for (int i = 0; i < inputLen / 4; i += blockSize) {
                for (int j = 0; j < blockSize; j++) {
                    // TODO consider endian
                    in[j] = 0;
                    for (int k = 0; k < 4; k++) {
//logger.log(Level.TRACE, "X[%02d] %02x".formatted(inputOffset + i * 4 + j * 4 + k, input[inputOffset + i * 4 + j * 4 + k] & 0xff));
                        in[j] |= (input[inputOffset + i * 4 + j * 4 + k] & 0xff) << ((3 - k) * 8);
                    }
                }
                camellia.decryptBlock(in, keyTable, out);
                for (int j = 0; j < blockSize; j++) {
                    output[outputOffset + i + j] = (byte) out[j];
//logger.log(Level.TRACE, "D: in[%02d]=%08x, out[%02d]=%02x".formatted(inputOffset + i + j, in[j], outputOffset + i + j, output[outputOffset + i + j]));
                }
            }
        } else {
            assert false : opmode;
        }

        return engineGetOutputSize(inputLen);
    }

    /** */
    public static class CamelliaKey implements SecretKey {
        /** 16 bytes (128 bit) key */
        final String key;
        /** @param key 16 bytes using UTF-8 encoding */
        public CamelliaKey(String key) {
            this.key = key;
        }
        public byte[] getEncoded() {
            return key.getBytes(StandardCharsets.UTF_8);
        }
        public String getAlgorithm() {
            return "Camellia";
        }
        public String getFormat() {
            return "B]";
        }
    }

    /** */
    public static class CamelliaKeySpec extends SecretKeySpec {
        /** 16 bytes (128 bit) key */
        final String key;
        /** @param key 16 bytes using UTF-8 encoding */
        public CamelliaKeySpec(String key) {
            super(key.getBytes(StandardCharsets.UTF_8), "Camellia");
            this.key = key;
        }
    }
}
