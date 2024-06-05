/*
 * Copyright (c) 2001 Brian Boyter
 * All rights reserved
 *
 * This software is released subject to the GNU Public License.  See
 * the full license included with this distribution.
 */

package com.boyter.mscrypto;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
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
import javax.crypto.ShortBufferException;

import static java.lang.System.getLogger;


/**
 * MSRSACipherFactoryImpl.
 *
 * @author Brian Boyter
 * @version 0.00 050314 nsano modified <br>
 */
public final class MSRSACipherFactoryImpl extends CipherSpi {

    private static final Logger logger = getLogger(MSRSACipherFactoryImpl.class.getName());

    /** */
    private static final MSCryptoManager msCryptoManager = MSCryptoManager.getInstance();

    /** */
    private static String paddingAlgorithm = "PKCS1";

    /** */
    private static int ciphermode = 0;

    /** */
    private static final int keySize = msCryptoManager.getRSAKeysize() / 8;

    /** */
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /** */
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineDoFinal entered\n");

        byte[] outputData = null;
        buffer.write(input, inputOffset, inputLen);
        byte[] inputData = buffer.toByteArray();

        if (ciphermode == Cipher.DECRYPT_MODE) {
            if (keySize != inputData.length) {
                throw new IllegalBlockSizeException("MSRSA length of data to be decrypted must equal keysize " + keySize + "  " + inputData.length);
            }
            outputData = msCryptoManager.decryptRSA(paddingAlgorithm, inputData);
        }

        if (ciphermode == Cipher.ENCRYPT_MODE) {
            if (keySize < inputData.length) {
                throw new IllegalBlockSizeException("MSRSA length of data to be decrypted must be <= keysize " + keySize + "  " + inputData.length);
            }
            outputData = msCryptoManager.encryptRSA(paddingAlgorithm, inputData);
        }

        buffer.reset();
        return outputData;
    }

    /** */
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineDoFinal entered\n");

        byte[] outputData = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(outputData, 0, output, outputOffset, outputData.length);
        return outputData.length;
    }

    /** */
    protected int engineGetBlockSize() {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineGetBlockSize entered\n");
        return keySize;
    }

    /** */
    protected byte[] engineGetIV() {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineGetIV entered\n");
        return null;
    }

    /** */
    protected int engineGetKeySize(Key key) {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineGetKeySize entered\n");
        return keySize; // keysize is in bytes
    }

    /** */
    protected int engineGetOutputSize(int inputLen) {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineOutputSize entered\n");
        return keySize;
    }

    /** */
    protected AlgorithmParameters engineGetParameters() {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineGetParameters entered\n");
        return null;
    }

    /** */
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException, InvalidKeyException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineInit entered\n");
        engineInit(opmode, key, random);
    }

    /** */
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidAlgorithmParameterException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineInit entered\n");
        buffer.reset();
        throw new InvalidAlgorithmParameterException("MSRSA does not accept AlgorithmParameterSpec");
    }

    /** */
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineInit entered\n");

        buffer.reset();
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("MSRSA opmode must be either encrypt or decrypt");
        }
        ciphermode = opmode;
    }

    /** */
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineSetMode entered\n");
        if (!mode.equalsIgnoreCase("ECB")) {
            throw new NoSuchAlgorithmException("MSRSA supports only ECB mode");
        }
    }

    /** */
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineSetPadding entered\n");

        if (padding.substring(0, 5).equalsIgnoreCase("PKCS1")) {
            paddingAlgorithm = "PKCS1";
        } else {
            throw new NoSuchPaddingException("MSRSA only supports PKCS1 Padding (" + padding + ")");
        }
    }

    /** */
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineUpdate entered\n");

        buffer.write(input, inputOffset, inputLen);
        return null;
    }

    /** */
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
logger.log(Level.DEBUG, "\nMSRSACipherFactoryImpl: engineUpdate entered\n");
        return 0;
    }
}
