/*
 * Copyright (c) 2024 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.enigma;

import java.security.spec.AlgorithmParameterSpec;

import com.beechwood.crypto.chipher.enigma.EnigmaParams;


/**
 * EnigmaParameterSpec.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (nsano)
 * @version 0.00 2024-02-21 nsano initial version <br>
 */
public class EnigmaParameterSpec implements EnigmaParams, AlgorithmParameterSpec {

    @Override
    public int[] getNotchPositions() {
        return new int[0];
    }

    @Override
    public int[] getStartPositions() {
        return new int[0];
    }

    @Override
    public int getRotorCount() {
        return 0;
    }
}
