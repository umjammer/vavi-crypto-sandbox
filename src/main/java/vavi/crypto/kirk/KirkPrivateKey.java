/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import static vavi.crypto.kirk.Kirk.ELT_SIZE;


/**
 * An ECDSA private key of the KIRK engine, i.e. a scalar of {@link Kirk#CURVE}.
 * <p>
 * Its encoding is the raw 20 bytes big endian scalar the engine uses. The engine signs with
 * the key <em>encrypted</em> under the console unique fuse id key (that is what the command
 * 0x10 expects), the encryption is done by {@link KirkSignature}.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public class KirkPrivateKey implements ECPrivateKey {

    /** the scalar, big endian */
    private final byte[] scalar;

    /**
     * @param scalar the scalar, big endian
     * @throws IllegalArgumentException when the scalar is not 20 bytes
     */
    public KirkPrivateKey(byte[] scalar) {
        if (scalar.length != ELT_SIZE) {
            throw new IllegalArgumentException("a KIRK private key is %d bytes: %d".formatted(ELT_SIZE, scalar.length));
        }
        this.scalar = scalar.clone();
    }

    @Override
    public BigInteger getS() {
        return Kirk.toBigInteger(scalar);
    }

    @Override
    public ECParameterSpec getParams() {
        return Kirk.CURVE;
    }

    @Override
    public String getAlgorithm() {
        return "KIRK-ECDSA";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return scalar.clone();
    }
}
