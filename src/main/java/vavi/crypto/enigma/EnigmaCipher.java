/*
 * Copyright (c) 2012 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import vavi.util.Debug;


/**
 * EnigmaCipher.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 2012/09/19 nsano initial version <br>
 */
public final class EnigmaCipher extends CipherSpi {

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
        // TODO Auto-generated method stub
        return null;
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
        // TODO Auto-generated method stub
        return null;
    }

    private EnigmaMachine enigma;

    private boolean finalized = false;

    private int opmode;

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;

        enigma = new EnigmaMachine(new EnigmaRotor[] { new EnigmaRotor(random, 1) }, new EnigmaReflector(random));

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
        // TODO Auto-generated method stub
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        // TODO Auto-generated method stub
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

        byte[] in = new byte[4];
        byte[] out = new byte[4];

        if (opmode == Cipher.ENCRYPT_MODE) {
            byte[] dataBytes = new byte[engineGetOutputSize(inputLen) / 4];
Debug.println(Level.FINE, "dataBytes: " + dataBytes.length);
            System.arraycopy(input, inputOffset, dataBytes, 0, inputLen);

            for (int i = 0; i < dataBytes.length; i += blockSize) {
                for (int j = 0; j < blockSize; j++) {
                    in[j] = dataBytes[i + j];
                }
                enigma.processMessage(in, 0, out, 0, blockSize);
                for (int j = 0; j < blockSize; j++) {
                    // TODO consider endian
                    for (int k = 0; k < 4; k++) {
                        output[outputOffset + i * 4 + j * 4 + k] = (byte) (out[j] >> ((3 - k) * 8));
Debug.printf(Level.FINE, "Y[%02d] %02x\n", outputOffset + i * 4 + j * 4 + k, output[outputOffset + i + j * 4 + k]);
                    }
Debug.printf(Level.FINE, "E: in[%02d]=%02x, out[%02d]=%08x\n", inputOffset + i + j, dataBytes[i + j], outputOffset + i + j, out[j]);
                }
            }
        } else if (opmode == Cipher.DECRYPT_MODE) {
Debug.println(Level.FINE, "inputLen: " + inputLen / 4);
            for (int i = 0; i < inputLen / 4; i += blockSize) {
                for (int j = 0; j < blockSize; j++) {
                    // TODO consider endian
                    in[j] = 0;
                    for (int k = 0; k < 4; k++) {
Debug.printf("X[%02d] %02x\n", inputOffset + i * 4 + j * 4 + k, input[inputOffset + i * 4 + j * 4 + k] & 0xff);
                        in[j] |= (input[inputOffset + i * 4 + j * 4 + k] & 0xff) << ((3 - k) * 8);
                    }
                }
                enigma.processMessage(in, 0, out, 0, blockSize);
                for (int j = 0; j < blockSize; j++) {
                    output[outputOffset + i + j] = out[j];
Debug.printf(Level.FINE, "D: in[%02d]=%08x, out[%02d]=%02x\n", inputOffset + i + j, in[j], outputOffset + i + j, output[outputOffset + i + j]);
                }
            }
        } else {
            assert false : opmode;
        }

        return engineGetOutputSize(inputLen);
    }

    /** */
    public static class EnigmaKey implements SecretKey {
        /** */
        String key;
        /** @param key 16 bytes using UTF-8 encoding */
        public EnigmaKey(String key) {
            this.key = key;
        }
        public byte[] getEncoded() {
            return key.getBytes(StandardCharsets.UTF_8);
        }
        public String getAlgorithm() {
            return "Enigma";
        }
        public String getFormat() {
            return "B]";
        }
    }

    /** */
    public static class EnigmaKeySpec extends SecretKeySpec {
        /** */
        String key;
        /** @param key 16 bytes using UTF-8 encoding */
        public EnigmaKeySpec(String key) {
            super(key.getBytes(StandardCharsets.UTF_8), "Enigma");
            this.key = key;
        }
    }
}

/* */

