/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import javax.crypto.SecretKey;

import static libkirk.Utilities.write32;


/**
 * A key of the KIRK engine.
 * <p>
 * The key material itself is inside the engine and cannot be read, so what is encoded here
 * is only the key seed which names it, as the little endian word the engine's command
 * headers use.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 * @see KirkKeySpec
 */
public class KirkKey implements SecretKey {

    /** */
    final KirkKeySpec keySpec;

    /** */
    public KirkKey(KirkKeySpec keySpec) {
        this.keySpec = keySpec;
    }

    /** @return the key seed which names this key */
    public int getKeySeed() {
        return keySpec.keySeed;
    }

    @Override
    public String getAlgorithm() {
        return "KIRK";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    /** @return the key seed as a little endian word, <em>not</em> the key itself */
    @Override
    public byte[] getEncoded() {
        byte[] encoded = new byte[4];
        write32(encoded, 0, keySpec.keySeed);
        return encoded;
    }

    @Override
    public String toString() {
        return "KirkKey[keySeed=%d]".formatted(keySpec.keySeed);
    }
}
