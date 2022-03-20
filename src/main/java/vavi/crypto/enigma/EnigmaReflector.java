/*
 * http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/DDJ/1999/9903/9903c/9903c.htm
 */

package vavi.crypto.enigma;

import java.security.SecureRandom;


public class EnigmaReflector {

    private int[] contacts = new int[256];

    protected EnigmaReflector(SecureRandom r) {
        byte[] rb = new byte[1];
        int[] mi = new int[256];
        for (int i = 0; i < 256; ++i)
            mi[i] = -1;
        int[] f = new int[2];
        for (int i = 0; i < 128; ++i) {
            for (int j = 0; j < 2; ++j) {
                r.nextBytes(rb);
                int ix = rb[0] & 0x3f;
                while (true) {
                    if (mi[ix] < 0) {
                        mi[ix] = 1;
                        f[j] = ix;
                        break;
                    }
                    ++ix;
                    if (ix > 255) {
                        ix = 0;
                    }
                }
            }
            contacts[f[0]] = f[1];
            contacts[f[1]] = f[0];
        }
    }

    protected int reflect(int i) {
        return contacts[i];
    }
}
