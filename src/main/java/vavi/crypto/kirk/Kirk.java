/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.prefs.Preferences;

import jpcsp.crypto.KIRK;
import libkirk.KirkEngine;

import static java.lang.System.getLogger;
import static libkirk.Utilities.write32;


/**
 * The KIRK engine, as used by this package.
 * <p>
 * The engine is a static singleton (that's how the hardware is, there is only one),
 * so all it takes is to make sure it has been initialized once with the console
 * unique fuse id before a command is issued.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 * @see "https://github.com/ProximaV/kirk-engine-full"
 */
public final class Kirk {

    private static final Logger logger = getLogger(Kirk.class.getName());

    private Kirk() {
    }

    /** size of the SHA-1 command header, a little endian data size */
    static final int SHA1_HEADER_SIZE = 4;

    /** size of the AES-128-CBC command header (mode, unk, unk, key seed, data size) */
    static final int AES128CBC_HEADER_SIZE = 0x14;

    /** size of the CMD0/CMD1 block header */
    static final int CMD1_HEADER_SIZE = KirkEngine.KIRK_CMD1_HEADER.SIZEOF;

    /** offset of the data size in a CMD0/CMD1 block header */
    static final int CMD1_DATA_SIZE_OFFSET = 0x70;

    /** the size of a SHA-1 digest and of an element of the KIRK curve */
    static final int ELT_SIZE = 0x14;

    /**
     * The elliptic curve used by the KIRK ECDSA commands (0xC, 0xD, 0x10 and 0x11).
     * It is a 160 bit curve of Sony's own, {@code y² = x³ - 3x + b} over {@code GF(p)}.
     */
    public static final ECParameterSpec CURVE = new ECParameterSpec(
            new EllipticCurve(
                    new ECFieldFp(toBigInteger(KirkEngine.ec_p)),
                    toBigInteger(KirkEngine.ec_a),
                    toBigInteger(KirkEngine.ec_b2)),
            new ECPoint(toBigInteger(KirkEngine.Gx2), toBigInteger(KirkEngine.Gy2)),
            toBigInteger(KirkEngine.ec_N2),
            1);

    /** whether {@link KirkEngine#kirk_init(long)} has been called */
    private static boolean initialized;

    /**
     * Initializes the engine once, using the fuse id which is set for {@link KIRK},
     * i.e. the dummy one unless the user stored a real one in the preferences.
     */
    public static synchronized void init() {
        if (!initialized) {
            long fuseId;
            try {
                fuseId = Preferences.systemNodeForPackage(KIRK.class).getLong(KIRK.settingsFuseId, KIRK.dummyFuseId);
            } catch (SecurityException e) {
                logger.log(Level.DEBUG, e.toString());
                fuseId = KIRK.dummyFuseId;
            }
logger.log(Level.DEBUG, "kirk_init: fuseId: %#x".formatted(fuseId));
            check(KirkEngine.kirk_init(fuseId));
            initialized = true;
        }
    }

    /**
     * @param result a KIRK_xxx result code
     * @throws KirkException when the command did not succeed
     */
    static void check(int result) {
        if (result != KirkEngine.KIRK_OPERATION_SUCCESS) {
            throw new KirkException(result);
        }
    }

    /**
     * The SHA-1 of the KIRK command 0xB.
     *
     * @throws KirkException when {@code length} is zero, the engine refuses empty data
     */
    static byte[] sha1(byte[] data, int offset, int length) {
        init();
        byte[] in = new byte[SHA1_HEADER_SIZE + length];
        write32(in, 0, length);
        System.arraycopy(data, offset, in, SHA1_HEADER_SIZE, length);
        byte[] out = new byte[ELT_SIZE];
        check(KirkEngine.kirk_CMD11(out, in, in.length));
        return out;
    }

    /** a big endian byte array as a positive {@link BigInteger} */
    static BigInteger toBigInteger(byte[] value) {
        return new BigInteger(1, value);
    }

    /** a positive {@link BigInteger} as a big endian byte array of exactly {@code length} bytes */
    static byte[] toByteArray(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[length];
        if (bytes.length > length) {
            // drop the sign byte
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        } else {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        }
        return result;
    }

    /** rounds up to the next multiple of 16, the AES block size */
    static int align16(int size) {
        return size + 15 & ~15;
    }
}
