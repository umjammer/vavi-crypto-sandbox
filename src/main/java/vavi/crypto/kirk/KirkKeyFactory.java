/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;


/**
 * KirkKeyFactory.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public class KirkKeyFactory extends SecretKeyFactorySpi {

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof KirkKeySpec kirkKeySpec) {
            return new KirkKey(kirkKeySpec);
        }
        throw new InvalidKeySpecException("unable to process key spec: " + keySpec);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        if (key instanceof KirkKey kirkKey) {
            return new KirkKeySpec(kirkKey.keySpec.keySeed);
        }
        throw new InvalidKeySpecException("key is unsupported: " + key);
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof KirkKey) {
            return key;
        }
        throw new InvalidKeyException("to translate key is unsupported: " + key);
    }
}
