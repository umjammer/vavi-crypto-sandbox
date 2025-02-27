/*
 * Copyright (c) 2001 Brian Boyter
 * All rights reserved
 *
 * This software is released subject to the GNU Public License.  See
 * the full license included with this distribution.
 */

package com.boyter.mscrypto;

import java.security.NoSuchAlgorithmException;


/**
 * MSSHARSASignature.
 *
 * @author Brian Boyter
 * @version 0.00 050314 nsano modified <br>
 */
public final class MSSHARSASignature extends MSRSASignFactoryImpl {

    /**
     * @throws NoSuchAlgorithmException
     */
    public MSSHARSASignature() throws NoSuchAlgorithmException {
        super.setMessageDigestType("SHA1");
    }
}
