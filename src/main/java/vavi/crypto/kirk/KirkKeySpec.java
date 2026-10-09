/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.spec.KeySpec;

import jpcsp.crypto.KeyVault;


/**
 * Selects one of the keys the KIRK engine keeps for itself.
 * <p>
 * A KIRK key is not key material, it is a <em>key seed</em>, i.e. the name of a key which
 * never leaves the engine:
 * <ul>
 * <li>{@code 0} ... {@code n} an index into the engine's key table, used by the commands 0x4 and 0x7,</li>
 * <li>{@link #FUSE} the console unique key derived from the fuse id, used by the commands 0x5 and 0x8,</li>
 * <li>{@link #KIRK1} the master key burnt into the engine, used by the commands 0x0 and 0x1.</li>
 * </ul>
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public class KirkKeySpec implements KeySpec {

    /** the KIRK1 master key, selects the commands 0x0 (encrypt) and 0x1 (decrypt) */
    public static final int KIRK1 = -1;

    /** the console unique fuse id key, selects the commands 0x5 (encrypt) and 0x8 (decrypt) */
    public static final int FUSE = 0x100;

    /** the number of keys in the engine's key table */
    public static final int KEY_SEEDS = KeyVault.keyvault.length;

    /** */
    final int keySeed;

    /**
     * @param keySeed {@link #KIRK1}, {@link #FUSE} or an index in [0, {@link #KEY_SEEDS})
     * @throws IllegalArgumentException when there is no such key
     */
    public KirkKeySpec(int keySeed) {
        if (keySeed != KIRK1 && keySeed != FUSE && (keySeed < 0 || keySeed >= KEY_SEEDS)) {
            throw new IllegalArgumentException("no such key seed: " + keySeed);
        }
        this.keySeed = keySeed;
    }

    /** @return the key seed this spec selects */
    public int getKeySeed() {
        return keySeed;
    }
}
