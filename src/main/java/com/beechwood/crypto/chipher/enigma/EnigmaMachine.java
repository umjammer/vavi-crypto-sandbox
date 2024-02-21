/*
 * https://archive.org/details/dr_dobbs_journal-1999_03/page/46/mode/2up
 */

package com.beechwood.crypto.chipher.enigma;

import vavi.util.Debug;

public class EnigmaMachine {

    private final EnigmaRotor[] rotors;

    private final int rotorCount;

    private final EnigmaReflector reflector;

    public EnigmaMachine(EnigmaRotor[] rotors, EnigmaReflector ref) {
        this.rotors = rotors;
        rotorCount = rotors.length;
        reflector = ref;
    }

    public void processMessage(byte[] in, int inOffset, byte[] out, int outOffset, int len) {
        int ox = outOffset;
        for (int i = inOffset; i < len; i++) {
            for (int rotorIndex = 0; rotorIndex < rotorCount; rotorIndex++) {
                try {
                    rotors[rotorIndex].advance();
                    break;
                } catch (EnigmaRotorTrippedException erte) {
Debug.println(erte.getMessage());
                }
            }
            int ic = in[i] & 0xff;
            for (int k = 0; k < rotorCount; k++) {
                ic = rotors[k].processByte(ic, true);
            }
            ic = reflector.reflect(ic);
            for (int k = rotorCount - 1; k >= 0; k--) {
                ic = rotors[k].processByte(ic, false);
            }
            out[ox++] = (byte) (ic & 0xff);
        }
    }
}
