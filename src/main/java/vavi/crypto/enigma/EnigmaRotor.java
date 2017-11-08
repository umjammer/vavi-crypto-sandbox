/*
 * http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/DDJ/1999/9903/9903c/9903c.htm
 */

package vavi.crypto.enigma;

import java.security.SecureRandom;


public class EnigmaRotor {

    private int notchIndex;

    @SuppressWarnings("unused")
    private int startPosition = 0;

    private int currentIndex = 0;

    private int[] b = new int[256];

    private int[] f = new int[256];

    protected EnigmaRotor(long seed, int notchIndex) {
        this.notchIndex = notchIndex;
        int fx = 0;
        int bx;
        for (int i = 0; i < 256; ++i)
            f[i] = b[i] = -1;
        SecureRandom r = new SecureRandom();
        r.setSeed(seed);
        byte[] rb = new byte[1];
        for (int i = 0; i < 256; ++i) {
            r.nextBytes(rb);
            bx = rb[0] & 0xff;
            if (b[bx] < 0) {
                b[bx] = fx;
            } else {
                bx = (bx + 128) % 256;
                while (true) {
                    if (bx > 255)
                        bx = 0;
                    if (b[bx] < 0)
                        break;
                    bx++;
                }
                b[bx] = fx;
            }
            f[fx] = bx;
            fx++;
        }
    }

    protected void setStartingPosition(int startPosition) {
        this.startPosition = currentIndex = startPosition;
    }

    protected void advance() throws EnigmaRotorTrippedException {
        currentIndex++;
        if (currentIndex > 255) {
            currentIndex = 0;
        }
        if (currentIndex == notchIndex) {
            throw new EnigmaRotorTrippedException("notch at " + notchIndex + " tripped");
        }
    }

    protected int processByte(int i, boolean forward) {
        int ri;
        int ix;
        if (forward) {
            ix = (i + currentIndex) % 256;
            ri = b[ix];
        } else {
            ix = i;
            ri = (f[ix] - currentIndex + 256) % 256;
        }
        return ri;
    }
}
