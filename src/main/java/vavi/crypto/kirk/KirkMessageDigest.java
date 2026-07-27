/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigestSpi;


/**
 * The SHA-1 command (0xB) of the KIRK engine as a {@link java.security.MessageDigest}.
 * <p>
 * The engine hashes a whole buffer at once, so the data is kept until the digest is asked for.
 * Note that the engine refuses empty data ({@code KIRK_DATA_SIZE_ZERO}), unlike a plain SHA-1.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public final class KirkMessageDigest extends MessageDigestSpi {

    /** */
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    protected int engineGetDigestLength() {
        return Kirk.ELT_SIZE;
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] data = buffer.toByteArray();
        buffer.reset();
        return Kirk.sha1(data, 0, data.length);
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }
}
