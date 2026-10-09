/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import static vavi.crypto.kirk.Kirk.ELT_SIZE;


/**
 * An ECDSA public key of the KIRK engine, i.e. a point of {@link Kirk#CURVE}.
 * <p>
 * Its encoding is the raw {@code x || y} the engine uses, 20 bytes each.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public class KirkPublicKey implements ECPublicKey {

    /** x || y, big endian */
    private final byte[] point;

    /**
     * @param point x || y, big endian
     * @throws IllegalArgumentException when the point is not 2 x 20 bytes
     */
    public KirkPublicKey(byte[] point) {
        if (point.length != ELT_SIZE * 2) {
            throw new IllegalArgumentException("a KIRK public key is %d bytes: %d".formatted(ELT_SIZE * 2, point.length));
        }
        this.point = point.clone();
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(
                Kirk.toBigInteger(Arrays.copyOfRange(point, 0, ELT_SIZE)),
                Kirk.toBigInteger(Arrays.copyOfRange(point, ELT_SIZE, ELT_SIZE * 2)));
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
        return point.clone();
    }
}
