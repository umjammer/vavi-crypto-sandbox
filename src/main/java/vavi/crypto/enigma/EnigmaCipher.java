/*
 * Copyright (c) 2012 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.beechwood.crypto.chipher.enigma.EnigmaMachine;
import com.beechwood.crypto.chipher.enigma.EnigmaReflector;
import com.beechwood.crypto.chipher.enigma.EnigmaRotor;

import static java.lang.System.getLogger;


/**
 * EnigmaCipher.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 2012/09/19 nsano initial version <br>
 */
public final class EnigmaCipher extends CipherSpi {

    private static final Logger logger = getLogger(EnigmaCipher.class.getName());

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
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private EnigmaMachine enigma;

    private boolean finalized = false;

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (key instanceof EnigmaKey enigmaKey) {
            enigma = createMachine(random, enigmaKey.sharedKeySeed, enigmaKey.rotorCount, enigmaKey.notchPositions, enigmaKey.startPositions);
        } else {
            throw new IllegalArgumentException("key must be enigma key");
        }

        finalized = false;
    }

    /**
     * Factory method to create an EnigmaMachine with deterministic wiring based on a seed.
     */
    private static EnigmaMachine createMachine(SecureRandom random, long seed, int count, int[] notches, int[] starts) {
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
        throw new UnsupportedOperationException("enigma doesn't have mode");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new UnsupportedOperationException("enigma doesn't use padding");
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

        enigma.processMessage(input, inputOffset, output, outputOffset, inputLen);

        return engineGetOutputSize(inputLen);
    }

    /** */
    public static class EnigmaKey implements SecretKey {
        /** Used to generate identical wiring */
        long sharedKeySeed;
        int rotorCount;
        /** Where the rotors trigger the next one */
        int[] notchPositions = new int[3];
        /** Initial rotor offsets */
        int[] startPositions = new int[3];

        private final byte[] encoded;

        /** */
        public EnigmaKey(byte[] encoded) {
            this.encoded = encoded;

            // TODO use known encoding method
            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(encoded);
                DataInputStream dis = new DataInputStream(bais);

                this.sharedKeySeed = dis.readLong();
                this.rotorCount = dis.readInt();
                for (int i = 0; i < notchPositions.length; i++) {
                    notchPositions[i] = dis.readInt();
                }
                for (int i = 0; i < startPositions.length; i++) {
                    startPositions[i] = dis.readInt();
                }
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }

        @Override
        public String getAlgorithm() {
            return "Enigma";
        }

        @Override
        public String getFormat() {
            return "B]";
        }
    }

    /** */
    public static class EnigmaKeySpec extends SecretKeySpec {
        /** */
        final EnigmaKey key;
        /** */
        public EnigmaKeySpec(long sharedKeySeed, int rotorCount, int[] notchPositions, int[] startPositions) {
            super(encode(sharedKeySeed, rotorCount, notchPositions, startPositions), "Enigma");
            this.key = new EnigmaKey(getEncoded());
        }

        // TODO use known encoding method
        static byte[] encode(long sharedKeySeed, int rotorCount, int[] notchPositions, int[] startPositions) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.writeLong(sharedKeySeed);
                dos.writeInt(rotorCount);
                for (int notchPosition : notchPositions) {
                    dos.writeInt(notchPosition);
                }
                for (int startPosition : startPositions) {
                    dos.writeInt(startPosition);
                }
                return baos.toByteArray();
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }
    }
}
