/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import libkirk.KirkEngine;

import static vavi.crypto.kirk.Kirk.ELT_SIZE;


/**
 * The ECDSA key pair command (0xC) of the KIRK engine as a
 * {@link java.security.KeyPairGenerator}.
 * <p>
 * The curve is fixed, it is always {@link Kirk#CURVE}, and the private key comes from the
 * engine's own random number command.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public final class KirkKeyPairGenerator extends KeyPairGeneratorSpi {

    /** the only key size of the KIRK curve */
    private static final int KEY_SIZE = ELT_SIZE * 8;

    /** the name this generator answers to, the KIRK curve has no standard name */
    private static final String CURVE_NAME = "KIRK";

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != KEY_SIZE) {
            throw new InvalidParameterException("the KIRK curve is %d bits: %d".formatted(KEY_SIZE, keysize));
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof ECGenParameterSpec spec) || !CURVE_NAME.equalsIgnoreCase(spec.getName())) {
            throw new InvalidAlgorithmParameterException("the only curve of the KIRK engine is \"%s\": %s".formatted(CURVE_NAME, params));
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        Kirk.init();

        byte[] out = new byte[KirkEngine.KIRK_CMD12_BUFFER.SIZEOF];
        Kirk.check(KirkEngine.kirk_CMD12(out, out.length));

        return new KeyPair(
                new KirkPublicKey(Arrays.copyOfRange(out, ELT_SIZE, out.length)),
                new KirkPrivateKey(Arrays.copyOfRange(out, 0, ELT_SIZE)));
    }
}
