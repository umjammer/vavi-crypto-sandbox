/*
 * https://archive.org/details/dr_dobbs_journal-1999_03/page/46/mode/2up
 */

package com.beechwood.crypto.chipher.enigma;

import java.security.SecureRandom;


/**
 */
public class EnigmaRotor {

    private final int notchIndex;

    private int currentIndex = 0;

    private final int[] b = new int[256];

    private final int[] f = new int[256];

    public EnigmaRotor(SecureRandom r, int notchIndex, int startPosition) {
        this.notchIndex = notchIndex;
        this.currentIndex = startPosition;
        int fx = 0;
        int bx;
        for (int i = 0; i < 256; ++i)
            f[i] = b[i] = -1;
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
