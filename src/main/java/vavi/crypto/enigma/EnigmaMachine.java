/*
 * http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/DDJ/1999/9903/9903c/9903c.htm
 */

package vavi.crypto.enigma;

import vavi.util.Debug;

public class EnigmaMachine {

    private EnigmaRotor[] rotors;

    private int rotorCount;

    private EnigmaReflector reflector;

    protected EnigmaMachine(EnigmaRotor[] rotors, EnigmaReflector ref) {
        this.rotors = rotors;
        rotorCount = rotors.length;
        reflector = ref;
    }

    protected void processMessage(byte[] in, int inOffset, byte[] out, int outOffset, int len) {
        int ox = 0;
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
            out[ox++] = (byte) ic;
        }
    }
}
