/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.SecureRandomSpi;

import libkirk.KirkEngine;


/**
 * The pseudo random number command (0xE) of the KIRK engine as a
 * {@link java.security.SecureRandom}.
 * <p>
 * The engine seeds itself (its internal state is stirred with the current time at every
 * command), it cannot be seeded from the outside, so {@link #engineSetSeed} does nothing.
 * <p>
 * <b>This is not a cryptographically strong generator by today's standards</b>, it is here
 * to reproduce what the PSP does, not to protect anything.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public final class KirkSecureRandom extends SecureRandomSpi {

    /**
     * The engine generates by chunks of a SHA-1 digest and recurses once per chunk,
     * so it is asked for one chunk at a time.
     */
    private static final int CHUNK_SIZE = Kirk.ELT_SIZE;

    /** does nothing, the KIRK engine seeds itself */
    @Override
    protected void engineSetSeed(byte[] seed) {
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        Kirk.init();
        for (int offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
            int length = Math.min(CHUNK_SIZE, bytes.length - offset);
            Kirk.check(KirkEngine.kirk_CMD14(bytes, offset, length));
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        byte[] seed = new byte[numBytes];
        engineNextBytes(seed);
        return seed;
    }
}
