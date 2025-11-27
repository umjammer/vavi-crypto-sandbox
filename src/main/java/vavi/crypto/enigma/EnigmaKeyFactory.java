/*
 * Copyright (c) 2022 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

import vavi.crypto.enigma.EnigmaCipher.EnigmaKey;
import vavi.crypto.enigma.EnigmaCipher.EnigmaKeySpec;


/**
 * EnigmaKeyFactory.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2022/02/25 umjammer initial version <br>
 */
public class EnigmaKeyFactory extends SecretKeyFactorySpi {

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof EnigmaKeySpec enigmaKeySpec) {
            return enigmaKeySpec.key;
        }
        throw new InvalidKeySpecException("unable to process key spec: " + keySpec);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        if (key instanceof EnigmaKey enigmaKey) {
            return new EnigmaKeySpec(enigmaKey.sharedKeySeed, enigmaKey.rotorCount, enigmaKey.notchPositions, enigmaKey.startPositions);
        }
        throw new InvalidKeySpecException("key is unsupported: " + key);
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof EnigmaKey) {
            return key;
        }
        throw new InvalidKeyException("to translate key is unsupported: " + key);
    }
}
