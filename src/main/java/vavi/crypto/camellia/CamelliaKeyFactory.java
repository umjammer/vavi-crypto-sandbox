/*
 * Copyright (c) 2022 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.camellia;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

import vavi.crypto.camellia.CamelliaCipher.CamelliaKey;
import vavi.crypto.camellia.CamelliaCipher.CamelliaKeySpec;


/**
 * CamelliaKeyFactory.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2022/02/25 umjammer initial version <br>
 */
public class CamelliaKeyFactory extends SecretKeyFactorySpi {

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof CamelliaKeySpec) {
            return new CamelliaKey(CamelliaKeySpec.class.cast(keySpec).key);
        }
        throw new InvalidKeySpecException("unable to process key spec: " + keySpec);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        if (key instanceof CamelliaKey) {
            return new CamelliaKeySpec(CamelliaKey.class.cast(key).key);
        }
        throw new InvalidKeySpecException("key is unsupported: " + key);
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof CamelliaKey) {
            return key;
        }
        throw new InvalidKeyException("to translate key is unsupported: " + key);
    }
}

/* */
