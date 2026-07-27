/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.ProviderException;

import libkirk.KirkEngine;


/**
 * An error returned by the KIRK engine.
 * <p>
 * This is a {@link ProviderException} because the KIRK commands are able to fail
 * everywhere in the SPI, even where the JCA doesn't allow a checked exception.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public class KirkException extends ProviderException {

    /** the KIRK_xxx result code */
    private final int result;

    /** @param result a KIRK_xxx result code */
    public KirkException(int result) {
        super("%s (%d)".formatted(toString(result), result));
        this.result = result;
    }

    /** @return the KIRK_xxx result code which caused this exception */
    public int getResult() {
        return result;
    }

    /** @return the name of a KIRK_xxx result code */
    public static String toString(int result) {
        return switch (result) {
            case KirkEngine.KIRK_OPERATION_SUCCESS -> "KIRK_OPERATION_SUCCESS";
            case KirkEngine.KIRK_NOT_ENABLED -> "KIRK_NOT_ENABLED";
            case KirkEngine.KIRK_INVALID_MODE -> "KIRK_INVALID_MODE";
            case KirkEngine.KIRK_HEADER_HASH_INVALID -> "KIRK_HEADER_HASH_INVALID";
            case KirkEngine.KIRK_DATA_HASH_INVALID -> "KIRK_DATA_HASH_INVALID";
            case KirkEngine.KIRK_SIG_CHECK_INVALID -> "KIRK_SIG_CHECK_INVALID";
            case KirkEngine.KIRK_NOT_INITIALIZED -> "KIRK_NOT_INITIALIZED";
            case KirkEngine.KIRK_INVALID_OPERATION -> "KIRK_INVALID_OPERATION";
            case KirkEngine.KIRK_INVALID_SEED_CODE -> "KIRK_INVALID_SEED_CODE";
            case KirkEngine.KIRK_INVALID_SIZE -> "KIRK_INVALID_SIZE";
            case KirkEngine.KIRK_DATA_SIZE_ZERO -> "KIRK_DATA_SIZE_ZERO";
            default -> "KIRK_UNKNOWN";
        };
    }
}
