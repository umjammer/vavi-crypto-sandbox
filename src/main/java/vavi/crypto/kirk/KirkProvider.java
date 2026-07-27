/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.Provider;


/**
 * The KIRK engine of the PSP as a security provider.
 * <p>
 * Note that the {@code Cipher} service, like any third party JCE service, is only usable
 * from a signed jar.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 * @see vavi.crypto.kirk
 */
public final class KirkProvider extends Provider {

    /** */
    public KirkProvider() {
        super("KIRK", "1.0.9", "KirkProvider implemented the PSP KIRK crypto engine");
        put("Cipher.KIRK", "vavi.crypto.kirk.KirkCipher");
        put("SecretKeyFactory.KIRK", "vavi.crypto.kirk.KirkKeyFactory");
        put("MessageDigest.KIRK-SHA1", "vavi.crypto.kirk.KirkMessageDigest");
        put("SecureRandom.KIRK-PRNG", "vavi.crypto.kirk.KirkSecureRandom");
        put("KeyPairGenerator.KIRK-ECDSA", "vavi.crypto.kirk.KirkKeyPairGenerator");
        put("Signature.SHA1withKIRKECDSA", "vavi.crypto.kirk.KirkSignature");
        put("Alg.Alias.Signature.KIRK-ECDSA", "SHA1withKIRKECDSA");
    }
}
